import type {
  IssueCredentialInput,
  IssuedCredentialReceipt,
  MidnightAdapter,
  ZkAccessProofPayload,
  ZkAccessProofRequest,
  ZkProofVerificationResult,
} from "@zk-turnover/contracts-spec";

/**
 * Member 2 implements this live adapter backed by `contracts/access_gate.compact`,
 * Midnight.js 5.0.0, and the local Docker Proof Server (port 6300).
 */
export class LiveMidnightAdapter implements MidnightAdapter {
  readonly mode = "live" as const;

  constructor(
    private readonly config: {
      proofServerUrl: string;
      contractAddress: string;
      indexerUrl?: string;
      nodeUrl?: string;
    },
  ) {}

  async getIssuerMerkleRoot(): Promise<string> {
    throw new Error(
      `LiveMidnightAdapter.getIssuerMerkleRoot not yet wired (contract: ${this.config.contractAddress})`,
    );
  }

  async issueDemoCredential(_input: IssueCredentialInput): Promise<IssuedCredentialReceipt> {
    throw new Error("LiveMidnightAdapter.issueDemoCredential not yet wired");
  }

  async revokeCredential(
    _credentialId: string,
  ): Promise<{ revoked: boolean; issuerMerkleRoot: string }> {
    throw new Error("LiveMidnightAdapter.revokeCredential not yet wired");
  }

  async generateAccessProof(_request: ZkAccessProofRequest): Promise<ZkAccessProofPayload> {
    throw new Error(
      `LiveMidnightAdapter.generateAccessProof not yet wired (proofServer: ${this.config.proofServerUrl})`,
    );
  }

  async verifyAccessProof(
    _proof: ZkAccessProofPayload,
    _expectedPolicyId: string,
    _expectedEpoch: number,
  ): Promise<ZkProofVerificationResult> {
    throw new Error("LiveMidnightAdapter.verifyAccessProof not yet wired");
  }
}
