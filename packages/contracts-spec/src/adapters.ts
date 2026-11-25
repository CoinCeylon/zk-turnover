import type {
  AgentResearchRequest,
  AgentResearchResponse,
  DatasetEndpoint,
  Http402ChallengePayload,
  IssueCredentialInput,
  IssuedCredentialReceipt,
  ProviderRegistrationInput,
  QueryRequestPayload,
  QuerySuccessResponse,
  SlaBondInput,
  SlaBondStatus,
  SlaRefundInput,
  UnsignedCardanoTx,
  X402BuildPaymentInput,
  X402SettlementResult,
  ZkAccessProofPayload,
  ZkAccessProofRequest,
  ZkProofVerificationResult,
} from "./types.js";

/**
 * Implemented by Member 2 (`@zk-turnover/midnight-privacy`) for `MIDNIGHT_MODE=live`.
 * Mocked by `MockMidnightAdapter` for `MIDNIGHT_MODE=mock`.
 */
export interface MidnightAdapter {
  readonly mode: "mock" | "live";

  /** Returns the current public Issuer Merkle root committed on Midnight. */
  getIssuerMerkleRoot(): Promise<string>;

  /** Demo issuer helper: commits a new compliance credential into the Merkle tree. */
  issueDemoCredential(input: IssueCredentialInput): Promise<IssuedCredentialReceipt>;

  /** Revokes an existing credential commitment so future ZK proofs fail. */
  revokeCredential(credentialId: string): Promise<{ revoked: boolean; issuerMerkleRoot: string }>;

  /** Runs locally (Docker Proof Server in live mode) to prove eligibility without revealing identity. */
  generateAccessProof(request: ZkAccessProofRequest): Promise<ZkAccessProofPayload>;

  /** Called by the API Gateway to verify the ZK proof & enforce nullifier uniqueness. */
  verifyAccessProof(
    proof: ZkAccessProofPayload,
    expectedPolicyId: string,
    expectedEpoch: number,
  ): Promise<ZkProofVerificationResult>;
}

/**
 * Implemented by Member 3 (`@zk-turnover/cardano-settlement`) for `CARDANO_MODE=live`.
 * Mocked by `MockCardanoAdapter` for `CARDANO_MODE=mock`.
 */
export interface CardanoAdapter {
  readonly mode: "mock" | "live";

  /** Builds a deterministic unsigned Cardano eUTxO x402 payment tx targeting the Aiken vault. */
  buildX402PaymentTx(input: X402BuildPaymentInput): Promise<UnsignedCardanoTx>;

  /**
   * Trust-minimized x402 Facilitator check: validates signed CBOR, confirms expected lovelace
   * and script target, broadcasts to Cardano Preprod, and returns settlement + split breakdown.
   */
  verifyAndSubmitX402Tx(params: {
    signedTxCbor: string;
    expectedLovelace: string;
    expectedScriptAddress: string;
    endpointId: string;
    splitBps: readonly [number, number, number];
  }): Promise<X402SettlementResult>;

  /** Locks provider SLA collateral inside `sla_revenue_vault.ak`. */
  buildPostSlaBondTx(input: SlaBondInput): Promise<UnsignedCardanoTx>;

  /** Triggers on-chain 75% / 20% / 5% revenue distribution via Aiken `SettleRevenue`. */
  buildSettleSplitTx(endpointId: string): Promise<UnsignedCardanoTx>;

  /** Processes an SLA breach refund from the provider's bond via `ClaimSlaRefund`. */
  buildSlaRefundTx(input: SlaRefundInput): Promise<UnsignedCardanoTx>;

  /** Reads current SLA bond & accrued revenue state for an endpoint. */
  getSlaBondStatus(endpointId: string): Promise<SlaBondStatus | null>;
}

/**
 * Consumed by Member 4 (`@zk-turnover/web`) and backed by Member 1 (`@zk-turnover/api-gateway`).
 */
export interface GatewayClient {
  readonly mode: "mock" | "live";

  listCatalog(): Promise<readonly DatasetEndpoint[]>;

  requestChallenge(endpointId: string): Promise<Http402ChallengePayload>;

  executeVerifiedQuery<TData = Record<string, unknown>>(
    request: QueryRequestPayload,
    options?: {
      payerAddress?: string;
      signTx?: (unsignedTxCbor: string) => Promise<string>;
    },
  ): Promise<QuerySuccessResponse<TData>>;

  runAgentResearch(request: AgentResearchRequest): Promise<AgentResearchResponse>;

  registerEndpoint(input: ProviderRegistrationInput): Promise<DatasetEndpoint>;
}
