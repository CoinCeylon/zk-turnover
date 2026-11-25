import type { MidnightAdapter } from "../adapters.js";
import { JURISDICTION_FLAGS, LICENSE_TIERS } from "../constants.js";
import { getCurrentEpochDay } from "../env.js";
import { hexToUtf8, sha256Hex, utf8ToHex } from "../hash.js";
import type {
  ComplianceCredential,
  IssueCredentialInput,
  IssuedCredentialReceipt,
  ZkAccessProofPayload,
  ZkAccessProofRequest,
  ZkProofVerificationResult,
} from "../types.js";

interface MockProofEnvelope {
  commitment: string;
  policyId: string;
  endpointId: string;
  epoch: number;
  nullifierHash: string;
  minTier: number;
  allowedJurisdictionMask: number;
  callIndex: number;
  maxCallsPerEpoch: number;
  issuerMerkleRoot: string;
}

/**
 * Stateful in-memory Midnight mock enforcing the exact same business constraints as
 * `access_gate.compact`: Merkle inclusion, non-revocation, license tier, jurisdiction
 * bitmask, expiry epoch, rate-limit ceiling, and nullifier replay rejection.
 */
export class MockMidnightAdapter implements MidnightAdapter {
  readonly mode = "mock" as const;

  private readonly credentials = new Map<string, ComplianceCredential>();
  private readonly commitmentIndex = new Map<string, string>();
  private readonly spentNullifiers = new Set<string>();
  private issuerMerkleRoot: string;
  private seededDemoCredential: ComplianceCredential;

  constructor() {
    this.issuerMerkleRoot = sha256Hex("veil402-empty-merkle-root");
    const defaultExpiry = getCurrentEpochDay() + 365;
    const demoSecret = sha256Hex("demo-ceylon-trade-analytics-secret-v1");
    const commitment = this.computeCommitment(
      demoSecret,
      LICENSE_TIERS.LICENSED_SME,
      JURISDICTION_FLAGS.LK | JURISDICTION_FLAGS.EU,
      defaultExpiry,
    );
    this.seededDemoCredential = {
      credentialId: "cred-demo-lk-sme-001",
      orgSecret: demoSecret,
      orgDisplayName: "Ceylon Trade Analytics (Pvt) Ltd",
      licenseTier: LICENSE_TIERS.LICENSED_SME,
      jurisdictionMask: JURISDICTION_FLAGS.LK | JURISDICTION_FLAGS.EU,
      expiryEpoch: defaultExpiry,
      commitment,
      issuedAt: new Date().toISOString(),
      revoked: false,
    };
    this.credentials.set(this.seededDemoCredential.credentialId, this.seededDemoCredential);
    this.commitmentIndex.set(commitment, this.seededDemoCredential.credentialId);
    this.recomputeMerkleRoot();
  }

  getDemoCredential(): ComplianceCredential {
    return { ...this.seededDemoCredential };
  }

  async getIssuerMerkleRoot(): Promise<string> {
    return this.issuerMerkleRoot;
  }

  async issueDemoCredential(input: IssueCredentialInput): Promise<IssuedCredentialReceipt> {
    const orgSecret =
      input.orgSecret ??
      sha256Hex(`${input.orgDisplayName}:${Date.now()}:${this.credentials.size}`);
    const commitment = this.computeCommitment(
      orgSecret,
      input.licenseTier,
      input.jurisdictionMask,
      input.expiryEpoch,
    );
    const credentialId = `cred-${commitment.slice(0, 12)}`;
    const credential: ComplianceCredential = {
      credentialId,
      orgSecret,
      orgDisplayName: input.orgDisplayName,
      licenseTier: input.licenseTier,
      jurisdictionMask: input.jurisdictionMask,
      expiryEpoch: input.expiryEpoch,
      commitment,
      issuedAt: new Date().toISOString(),
      revoked: false,
    };
    this.credentials.set(credentialId, credential);
    this.commitmentIndex.set(commitment, credentialId);
    this.recomputeMerkleRoot();
    return {
      credential,
      issuerMerkleRoot: this.issuerMerkleRoot,
    };
  }

  async revokeCredential(
    credentialId: string,
  ): Promise<{ revoked: boolean; issuerMerkleRoot: string }> {
    const existing = this.credentials.get(credentialId);
    if (!existing) {
      return { revoked: false, issuerMerkleRoot: this.issuerMerkleRoot };
    }
    existing.revoked = true;
    this.recomputeMerkleRoot();
    return { revoked: true, issuerMerkleRoot: this.issuerMerkleRoot };
  }

  async generateAccessProof(request: ZkAccessProofRequest): Promise<ZkAccessProofPayload> {
    const { credential, endpointId, policy, currentEpoch, callIndex } = request;

    const storedId = this.commitmentIndex.get(credential.commitment);
    const stored = storedId ? this.credentials.get(storedId) : undefined;
    if (!stored || stored.revoked) {
      throw new Error("ZK circuit assertion failed: credential not in active Issuer Merkle root");
    }
    const recomputedCommitment = this.computeCommitment(
      credential.orgSecret,
      credential.licenseTier,
      credential.jurisdictionMask,
      credential.expiryEpoch,
    );
    if (recomputedCommitment !== credential.commitment) {
      throw new Error("ZK circuit assertion failed: credential witness does not match commitment");
    }
    if (credential.licenseTier < policy.minTier) {
      throw new Error(
        `ZK circuit assertion failed: licenseTier ${credential.licenseTier} < required ${policy.minTier}`,
      );
    }
    if ((credential.jurisdictionMask & policy.allowedJurisdictionMask) === 0) {
      throw new Error("ZK circuit assertion failed: jurisdiction not permitted by endpoint policy");
    }
    if (currentEpoch > credential.expiryEpoch) {
      throw new Error("ZK circuit assertion failed: compliance credential has expired");
    }
    if (!Number.isInteger(callIndex) || callIndex < 0 || callIndex >= policy.maxCallsPerEpoch) {
      throw new Error(
        `ZK circuit assertion failed: callIndex ${callIndex} exceeds maxCallsPerEpoch ${policy.maxCallsPerEpoch}`,
      );
    }

    const nullifierHash = sha256Hex(
      `nullifier:${credential.orgSecret}:${endpointId}:${currentEpoch}:${callIndex}`,
    );

    const envelope: MockProofEnvelope = {
      commitment: credential.commitment,
      policyId: policy.policyId,
      endpointId,
      epoch: currentEpoch,
      nullifierHash,
      minTier: policy.minTier,
      allowedJurisdictionMask: policy.allowedJurisdictionMask,
      callIndex,
      maxCallsPerEpoch: policy.maxCallsPerEpoch,
      issuerMerkleRoot: this.issuerMerkleRoot,
    };

    return {
      proofHex: utf8ToHex(JSON.stringify(envelope)),
      nullifierHash,
      policyId: policy.policyId,
      endpointId,
      epoch: currentEpoch,
      issuerMerkleRoot: this.issuerMerkleRoot,
      mode: "mock",
      generatedAt: new Date().toISOString(),
    };
  }

  async verifyAccessProof(
    proof: ZkAccessProofPayload,
    expectedPolicyId: string,
    expectedEpoch: number,
  ): Promise<ZkProofVerificationResult> {
    const now = new Date().toISOString();
    const fail = (reason: string): ZkProofVerificationResult => ({
      valid: false,
      reason,
      nullifierHash: proof.nullifierHash,
      policyId: proof.policyId,
      verifiedAt: now,
      mode: "mock",
    });

    if (proof.policyId !== expectedPolicyId) {
      return fail(`Policy mismatch: expected ${expectedPolicyId}, received ${proof.policyId}`);
    }
    if (proof.epoch !== expectedEpoch) {
      return fail(`Epoch mismatch: expected ${expectedEpoch}, received ${proof.epoch}`);
    }
    if (proof.issuerMerkleRoot !== this.issuerMerkleRoot) {
      return fail("Stale or unrecognized Issuer Merkle root");
    }
    if (this.spentNullifiers.has(proof.nullifierHash)) {
      return fail("Nullifier already spent (replay or duplicate rate-limit slot)");
    }

    let envelope: MockProofEnvelope;
    try {
      envelope = JSON.parse(hexToUtf8(proof.proofHex)) as MockProofEnvelope;
    } catch {
      return fail("Malformed proof payload");
    }

    if (
      envelope.nullifierHash !== proof.nullifierHash ||
      envelope.policyId !== expectedPolicyId ||
      envelope.epoch !== expectedEpoch ||
      envelope.issuerMerkleRoot !== this.issuerMerkleRoot
    ) {
      return fail("Proof envelope bindings do not match public inputs");
    }

    const storedId = this.commitmentIndex.get(envelope.commitment);
    const stored = storedId ? this.credentials.get(storedId) : undefined;
    if (!stored || stored.revoked) {
      return fail("Credential commitment is no longer active");
    }

    this.spentNullifiers.add(proof.nullifierHash);
    return {
      valid: true,
      nullifierHash: proof.nullifierHash,
      policyId: proof.policyId,
      verifiedAt: now,
      mode: "mock",
    };
  }

  private computeCommitment(
    orgSecret: string,
    licenseTier: number,
    jurisdictionMask: number,
    expiryEpoch: number,
  ): string {
    return sha256Hex(`cred:${orgSecret}:${licenseTier}:${jurisdictionMask}:${expiryEpoch}`);
  }

  private recomputeMerkleRoot(): void {
    const activeCommitments = Array.from(this.credentials.values())
      .filter((c) => !c.revoked)
      .map((c) => c.commitment)
      .sort();
    this.issuerMerkleRoot =
      activeCommitments.length === 0
        ? sha256Hex("veil402-empty-merkle-root")
        : sha256Hex(`merkle-root:${activeCommitments.join("|")}`);
  }
}
