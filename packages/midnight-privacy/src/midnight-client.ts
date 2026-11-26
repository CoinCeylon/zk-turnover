import {
  JURISDICTION_FLAGS,
  LICENSE_TIERS,
  NETWORK_CONFIG,
  getCurrentEpochDay,
  hexToUtf8,
  sha256Hex,
  utf8ToHex,
  type ComplianceCredential,
  type IssueCredentialInput,
  type IssuedCredentialReceipt,
  type MidnightAdapter,
  type ZkAccessProofPayload,
  type ZkAccessProofRequest,
  type ZkProofVerificationResult,
} from "@zk-turnover/contracts-spec";
import {
  buildSanitizedWitnessInputs,
  bytesToHex,
  computeCredentialCommitment,
  computeDeterministicNullifier,
  createPrivacyAppWitnessProviders,
  sanitizeOrgSecret,
  type PrivacyAppWitnessProviders,
  type SanitizedWitnessInputs,
} from "./witness.js";

export interface MidnightClientConfig {
  proofServerUrl?: string;
  contractAddress: string;
  indexerUrl?: string;
  nodeUrl?: string;
  requestTimeoutMs?: number;
  /**
   * When true, falls back to local deterministic proof envelope generation if the
   * Docker Proof Server is unreachable. Defaults to `false` so live mode fails
   * loudly unless fallback is explicitly enabled.
   */
  allowLocalFallback?: boolean;
}

export interface ProofServerHealth {
  healthy: boolean;
  url: string;
  latencyMs: number;
  error?: string;
}

export interface ProofServerProveRequest {
  circuit: "verify_access";
  contractAddress: string;
  publicInputs: {
    policyId: string;
    endpointId: string;
    currentEpoch: number;
    issuerMerkleRoot: string;
    nullifierHash: string;
    minTier: number;
    allowedJurisdictionMask: number;
    maxCallsPerEpoch: number;
  };
  privateWitness: {
    orgSecretHex: string;
    licenseTier: number;
    jurisdictionCode: number;
    expiryEpoch: string;
    callIndex: number;
    merkleLeafHex: string;
  };
}

export interface ProofServerProveResponse {
  proofHex: string;
  proverVersion?: string;
  provingTimeMs?: number;
}

interface SerializedProofEnvelope {
  version: "midnight-compact-0.36.0";
  contractAddress: string;
  circuit: "verify_access";
  policyId: string;
  endpointId: string;
  epoch: number;
  nullifierHash: string;
  issuerMerkleRoot: string;
  proofBytesHex: string;
}

export type ProofServerErrorCode = "TIMEOUT" | "UNREACHABLE" | "HTTP_ERROR" | "INVALID_RESPONSE";

export class MidnightProofServerError extends Error {
  readonly code: ProofServerErrorCode;
  readonly statusCode?: number;

  constructor(message: string, code: ProofServerErrorCode, statusCode?: number) {
    super(message);
    this.name = "MidnightProofServerError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * HTTP client for the local Midnight Proof Server Docker container (default port 6300).
 * Keeps private witnesses (`org_secret`, `license_tier`, etc.) on the local machine.
 */
export class MidnightProofServerClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(
    baseUrl: string = NETWORK_CONFIG.MIDNIGHT_DEFAULT_PROOF_SERVER_URL,
    timeoutMs = 15_000,
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
  }

  get url(): string {
    return this.baseUrl;
  }

  async healthCheck(): Promise<ProofServerHealth> {
    const started = Date.now();
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: "GET",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      return {
        healthy: response.ok,
        url: this.baseUrl,
        latencyMs: Date.now() - started,
        ...(response.ok ? {} : { error: `HTTP ${response.status} ${response.statusText}` }),
      };
    } catch (error) {
      return {
        healthy: false,
        url: this.baseUrl,
        latencyMs: Date.now() - started,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async proveCircuit(request: ProofServerProveRequest): Promise<ProofServerProveResponse> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/prove`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
        throw new MidnightProofServerError(
          `Midnight Proof Server timed out after ${this.timeoutMs}ms at ${this.baseUrl}`,
          "TIMEOUT",
        );
      }
      throw new MidnightProofServerError(
        `Midnight Proof Server unreachable at ${this.baseUrl}: ${error instanceof Error ? error.message : String(error)}`,
        "UNREACHABLE",
      );
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new MidnightProofServerError(
        `Midnight Proof Server error (${response.status} ${response.statusText}): ${detail || "prove failed"}`,
        "HTTP_ERROR",
        response.status,
      );
    }

    const body = (await response.json()) as Partial<ProofServerProveResponse>;
    if (typeof body.proofHex !== "string" || body.proofHex.length === 0) {
      throw new MidnightProofServerError(
        "Midnight Proof Server returned an invalid response without proofHex",
        "INVALID_RESPONSE",
      );
    }

    return {
      proofHex: body.proofHex,
      proverVersion: body.proverVersion,
      provingTimeMs: body.provingTimeMs,
    };
  }

  async verifyProof(params: {
    contractAddress: string;
    proofHex: string;
    policyId: string;
    endpointId: string;
    epoch: number;
    nullifierHash: string;
    issuerMerkleRoot: string;
  }): Promise<{ valid: boolean; reason?: string }> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(params),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
        return {
          valid: false,
          reason: `Midnight Proof Server verification timed out after ${this.timeoutMs}ms`,
        };
      }
      return {
        valid: false,
        reason: `Midnight Proof Server unreachable: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      return {
        valid: false,
        reason: `Proof Server verification HTTP ${response.status}: ${detail || response.statusText}`,
      };
    }

    const body = (await response.json()) as { valid?: boolean; reason?: string };
    return {
      valid: Boolean(body.valid),
      reason: body.reason,
    };
  }
}

/**
 * Midnight privacy client integrating `witness.ts`, `privacy_app.compact` ledger state,
 * and the local Midnight Proof Server Docker container.
 */
export class MidnightPrivacyClient implements MidnightAdapter {
  readonly mode = "live" as const;
  readonly proofServer: MidnightProofServerClient;
  readonly witnessProviders: PrivacyAppWitnessProviders;

  private readonly contractAddress: string;
  private readonly allowLocalFallback: boolean;
  private readonly credentials = new Map<string, ComplianceCredential>();
  private readonly commitmentIndex = new Map<string, string>();
  private readonly spentNullifiers = new Set<string>();
  private issuerMerkleRoot: string;

  constructor(config: MidnightClientConfig) {
    this.contractAddress = config.contractAddress;
    this.allowLocalFallback = config.allowLocalFallback ?? false;
    this.proofServer = new MidnightProofServerClient(
      config.proofServerUrl ?? NETWORK_CONFIG.MIDNIGHT_DEFAULT_PROOF_SERVER_URL,
      config.requestTimeoutMs,
    );
    this.witnessProviders = createPrivacyAppWitnessProviders();
    this.issuerMerkleRoot = sha256Hex(`veil402-empty-merkle-root:${this.contractAddress}`);

    // Seed deterministic demo credential so live adapter tests can run immediately.
    const defaultExpiry = getCurrentEpochDay() + 365;
    const demoSecret = sha256Hex("demo-ceylon-trade-analytics-secret-v1");
    const commitment = computeCredentialCommitment(
      demoSecret,
      LICENSE_TIERS.LICENSED_SME,
      JURISDICTION_FLAGS.LK | JURISDICTION_FLAGS.EU,
      defaultExpiry,
    );
    const demoCredential: ComplianceCredential = {
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
    this.credentials.set(demoCredential.credentialId, demoCredential);
    this.commitmentIndex.set(commitment, demoCredential.credentialId);
    this.recomputeMerkleRoot();
  }

  getDemoCredential(): ComplianceCredential {
    const demo = this.credentials.get("cred-demo-lk-sme-001");
    if (!demo) {
      throw new Error("Demo credential missing");
    }
    return { ...demo };
  }

  async getIssuerMerkleRoot(): Promise<string> {
    return this.issuerMerkleRoot;
  }

  async issueDemoCredential(input: IssueCredentialInput): Promise<IssuedCredentialReceipt> {
    const orgSecret =
      input.orgSecret ??
      sha256Hex(`${input.orgDisplayName}:${Date.now()}:${this.credentials.size}`);
    const secretHex = bytesToHex(sanitizeOrgSecret(orgSecret));
    const commitment = computeCredentialCommitment(
      secretHex,
      input.licenseTier,
      input.jurisdictionMask,
      input.expiryEpoch,
    );
    const credentialId = `cred-${commitment.slice(0, 12)}`;
    const credential: ComplianceCredential = {
      credentialId,
      orgSecret: secretHex,
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
      throw new Error("ZK circuit assertion failed: credential not in active issuer_merkle_root");
    }

    const sanitized: SanitizedWitnessInputs = buildSanitizedWitnessInputs(request);
    const recomputedCommitment = computeCredentialCommitment(
      credential.orgSecret,
      sanitized.license_tier,
      sanitized.jurisdiction_code,
      Number(sanitized.expiry_epoch),
    );
    if (recomputedCommitment !== credential.commitment) {
      throw new Error("ZK circuit assertion failed: credential witness does not match commitment");
    }

    const nullifierHash = computeDeterministicNullifier({
      orgSecret: credential.orgSecret,
      endpointId,
      epoch: currentEpoch,
      callIndex: sanitized.call_index,
    });

    const ctx = { privateState: { witness: sanitized } };
    const [, orgSecretBytes] = this.witnessProviders.org_secret(ctx);

    let proofBytesHex: string;
    try {
      const proved = await this.proofServer.proveCircuit({
        circuit: "verify_access",
        contractAddress: this.contractAddress,
        publicInputs: {
          policyId: policy.policyId,
          endpointId,
          currentEpoch,
          issuerMerkleRoot: this.issuerMerkleRoot,
          nullifierHash,
          minTier: policy.minTier,
          allowedJurisdictionMask: policy.allowedJurisdictionMask,
          maxCallsPerEpoch: policy.maxCallsPerEpoch,
        },
        privateWitness: {
          orgSecretHex: bytesToHex(orgSecretBytes),
          licenseTier: sanitized.license_tier,
          jurisdictionCode: sanitized.jurisdiction_code,
          expiryEpoch: sanitized.expiry_epoch.toString(),
          callIndex: sanitized.call_index,
          merkleLeafHex: bytesToHex(sanitized.merkle_path.leaf),
        },
      });
      proofBytesHex = proved.proofHex;
    } catch (error) {
      if (!this.allowLocalFallback) {
        throw error;
      }
      proofBytesHex = sha256Hex(
        `fallback-zk:${this.contractAddress}:${credential.commitment}:${nullifierHash}:${this.issuerMerkleRoot}`,
      );
    }

    const envelope: SerializedProofEnvelope = {
      version: "midnight-compact-0.36.0",
      contractAddress: this.contractAddress,
      circuit: "verify_access",
      policyId: policy.policyId,
      endpointId,
      epoch: currentEpoch,
      nullifierHash,
      issuerMerkleRoot: this.issuerMerkleRoot,
      proofBytesHex,
    };

    return {
      proofHex: utf8ToHex(JSON.stringify(envelope)),
      nullifierHash,
      policyId: policy.policyId,
      endpointId,
      epoch: currentEpoch,
      issuerMerkleRoot: this.issuerMerkleRoot,
      mode: "live",
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
      mode: "live",
    });

    if (proof.policyId !== expectedPolicyId) {
      return fail(`Policy mismatch: expected ${expectedPolicyId}, received ${proof.policyId}`);
    }
    if (proof.epoch !== expectedEpoch) {
      return fail(`Epoch mismatch: expected ${expectedEpoch}, received ${proof.epoch}`);
    }
    if (proof.issuerMerkleRoot !== this.issuerMerkleRoot) {
      return fail("Stale or unrecognized issuer_merkle_root");
    }
    if (this.spentNullifiers.has(proof.nullifierHash)) {
      return fail("Nullifier already spent (replay or duplicate rate-limit slot)");
    }

    let envelope: SerializedProofEnvelope;
    try {
      envelope = JSON.parse(hexToUtf8(proof.proofHex)) as SerializedProofEnvelope;
    } catch {
      return fail("Malformed Midnight ZK proof envelope");
    }

    if (
      envelope.version !== "midnight-compact-0.36.0" ||
      envelope.circuit !== "verify_access" ||
      envelope.contractAddress !== this.contractAddress ||
      envelope.nullifierHash !== proof.nullifierHash ||
      envelope.policyId !== expectedPolicyId ||
      envelope.epoch !== expectedEpoch ||
      envelope.issuerMerkleRoot !== this.issuerMerkleRoot ||
      typeof envelope.proofBytesHex !== "string" ||
      !/^[0-9a-fA-F]+$/.test(envelope.proofBytesHex)
    ) {
      return fail("Proof envelope bindings do not match public circuit inputs");
    }

    if (!this.allowLocalFallback) {
      try {
        const remote = await this.proofServer.verifyProof({
          contractAddress: this.contractAddress,
          proofHex: envelope.proofBytesHex,
          policyId: expectedPolicyId,
          endpointId: proof.endpointId,
          epoch: expectedEpoch,
          nullifierHash: proof.nullifierHash,
          issuerMerkleRoot: this.issuerMerkleRoot,
        });
        if (!remote.valid) {
          return fail(remote.reason ?? "Midnight Proof Server rejected ZK proof");
        }
      } catch (error) {
        return fail(
          `Midnight Proof Server verification failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    this.spentNullifiers.add(proof.nullifierHash);
    return {
      valid: true,
      nullifierHash: proof.nullifierHash,
      policyId: proof.policyId,
      verifiedAt: now,
      mode: "live",
    };
  }

  private recomputeMerkleRoot(): void {
    const activeCommitments = Array.from(this.credentials.values())
      .filter((cred) => !cred.revoked)
      .map((cred) => cred.commitment)
      .sort();
    this.issuerMerkleRoot =
      activeCommitments.length === 0
        ? sha256Hex(`veil402-empty-merkle-root:${this.contractAddress}`)
        : sha256Hex(`merkle:${activeCommitments.join("|")}`);
  }
}
