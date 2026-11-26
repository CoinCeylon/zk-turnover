import type {
  IssueCredentialInput,
  IssuedCredentialReceipt,
  MidnightAdapter,
  ZkAccessProofPayload,
  ZkAccessProofRequest,
  ZkProofVerificationResult,
} from "@zk-turnover/contracts-spec";
import { MidnightPrivacyClient, type MidnightClientConfig } from "./midnight-client.js";

export * from "./witness.js";
export * from "./midnight-client.js";

/**
 * Live Midnight adapter backed by `contracts/privacy_app.compact`,
 * off-chain witness sanitization (`witness.ts`), and the local Docker Proof Server.
 */
export class LiveMidnightAdapter implements MidnightAdapter {
  readonly mode = "live" as const;
  private readonly client: MidnightPrivacyClient;

  constructor(config: MidnightClientConfig) {
    this.client = new MidnightPrivacyClient(config);
  }

  getClient(): MidnightPrivacyClient {
    return this.client;
  }

  async getIssuerMerkleRoot(): Promise<string> {
    return this.client.getIssuerMerkleRoot();
  }

  async issueDemoCredential(input: IssueCredentialInput): Promise<IssuedCredentialReceipt> {
    return this.client.issueDemoCredential(input);
  }

  async revokeCredential(
    credentialId: string,
  ): Promise<{ revoked: boolean; issuerMerkleRoot: string }> {
    return this.client.revokeCredential(credentialId);
  }

  async generateAccessProof(request: ZkAccessProofRequest): Promise<ZkAccessProofPayload> {
    return this.client.generateAccessProof(request);
  }

  async verifyAccessProof(
    proof: ZkAccessProofPayload,
    expectedPolicyId: string,
    expectedEpoch: number,
  ): Promise<ZkProofVerificationResult> {
    return this.client.verifyAccessProof(proof, expectedPolicyId, expectedEpoch);
  }
}
