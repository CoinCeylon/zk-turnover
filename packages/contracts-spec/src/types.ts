export type RuntimeMode = "mock" | "live";

export interface SwitchboardConfig {
  gatewayMode: RuntimeMode;
  midnightMode: RuntimeMode;
  cardanoMode: RuntimeMode;
  gatewayUrl: string;
}

/**
 * Basis points (sum MUST equal 10000): [datasetOwnerBps, apiOperatorBps, protocolTreasuryBps].
 * Default: [7500, 2000, 500] (75% / 20% / 5%).
 */
export type RevenueSplitBps = readonly [number, number, number];

export interface EndpointPolicy {
  policyId: string;
  /** Minimum compliance tier required (0=Public, 1=Academic, 2=Licensed SME, 3=Enterprise). */
  minTier: number;
  /** Bitmask of permitted jurisdictions (see JURISDICTION_FLAGS). */
  allowedJurisdictionMask: number;
  /** Maximum unlinkable calls allowed per organization per epoch day. */
  maxCallsPerEpoch: number;
}

export interface DatasetEndpoint {
  endpointId: string;
  name: string;
  category: string;
  description: string;
  providerName: string;
  /** Price per API call in lovelace (1 ADA = 1,000,000 lovelace). */
  priceLovelace: string;
  assetUnit: "lovelace" | string;
  policy: EndpointPolicy;
  cardanoVaultScriptAddress: string;
  ownerAddress: string;
  operatorAddress: string;
  protocolAddress: string;
  splitBps: RevenueSplitBps;
  slaBondLovelace: string;
  slaBacked: boolean;
  sampleParams: Record<string, string>;
}

export interface ProviderRegistrationInput {
  endpointId: string;
  name: string;
  category: string;
  description: string;
  providerName: string;
  priceLovelace: string;
  policy: Omit<EndpointPolicy, "policyId">;
  ownerAddress: string;
  operatorAddress: string;
  splitBps?: RevenueSplitBps;
  slaBondLovelace: string;
}

// -----------------------------------------------------------------------------
// Midnight Privacy & ZK Types (Member 2 owns live implementation)
// -----------------------------------------------------------------------------

export interface ComplianceCredential {
  credentialId: string;
  /** Never revealed publicly or sent to API providers. */
  orgSecret: string;
  orgDisplayName: string;
  licenseTier: number;
  jurisdictionMask: number;
  expiryEpoch: number;
  commitment: string;
  issuedAt: string;
  revoked: boolean;
}

export interface IssueCredentialInput {
  orgDisplayName: string;
  licenseTier: number;
  jurisdictionMask: number;
  expiryEpoch: number;
  /** Optional deterministic secret for repeatable tests; generated automatically if omitted. */
  orgSecret?: string;
}

export interface IssuedCredentialReceipt {
  credential: ComplianceCredential;
  issuerMerkleRoot: string;
}

export interface ZkAccessProofRequest {
  credential: ComplianceCredential;
  endpointId: string;
  policy: EndpointPolicy;
  currentEpoch: number;
  callIndex: number;
}

export interface ZkAccessProofPayload {
  proofHex: string;
  nullifierHash: string;
  policyId: string;
  endpointId: string;
  epoch: number;
  issuerMerkleRoot: string;
  mode: RuntimeMode;
  generatedAt: string;
}

export interface ZkProofVerificationResult {
  valid: boolean;
  reason?: string;
  nullifierHash: string;
  policyId: string;
  verifiedAt: string;
  mode: RuntimeMode;
}

// -----------------------------------------------------------------------------
// Cardano x402 & Aiken Settlement Types (Member 3 owns live implementation)
// -----------------------------------------------------------------------------

export interface X402PaymentRequirements {
  scheme: "cardano-eutxo-x402";
  network: "cardano-preprod" | "cardano-preview";
  asset: "lovelace" | string;
  amountLovelace: string;
  payToAddress: string;
  endpointId: string;
  splitBps: RevenueSplitBps;
  expiresAt: string;
}

/** Returned by API Gateway with HTTP 402 Payment Required */
export interface Http402ChallengePayload {
  status: 402;
  error: "PAYMENT_AND_ZK_PROOF_REQUIRED";
  message: string;
  payment: X402PaymentRequirements;
  privacy: {
    network: "midnight-testnet";
    policy: EndpointPolicy;
    currentEpoch: number;
    issuerMerkleRoot: string;
  };
}

export interface X402BuildPaymentInput {
  endpointId: string;
  toScriptAddress: string;
  amountLovelace: string;
  payerAddress: string;
  nullifierHash: string;
  policyId: string;
  splitBps: RevenueSplitBps;
}

export interface UnsignedCardanoTx {
  unsignedTxCbor: string;
  estimatedFeeLovelace: string;
  metadataAttached: {
    endpointId: string;
    nullifierHash: string;
    policyId: string;
  };
  mode: RuntimeMode;
}

export interface RevenueSplitBreakdown {
  totalLovelace: string;
  datasetOwnerLovelace: string;
  apiOperatorLovelace: string;
  protocolTreasuryLovelace: string;
  splitBps: RevenueSplitBps;
}

export interface X402SettlementResult {
  valid: boolean;
  reason?: string;
  txHash: string;
  explorerUrl: string;
  settledLovelace: string;
  split: RevenueSplitBreakdown;
  confirmationStatus: "submitted-mempool" | "confirmed-onchain";
  settledAt: string;
  mode: RuntimeMode;
}

export interface SlaBondInput {
  endpointId: string;
  providerAddress: string;
  bondLovelace: string;
  splitBps: RevenueSplitBps;
}

export interface SlaBondStatus {
  endpointId: string;
  scriptAddress: string;
  bondedLovelace: string;
  accruedRevenueLovelace: string;
  active: boolean;
  lastTxHash: string;
  explorerUrl: string;
}

export interface SlaRefundInput {
  endpointId: string;
  callerAddress: string;
  refundLovelace: string;
  breachReason: string;
  originalTxHash: string;
}

// -----------------------------------------------------------------------------
// API Gateway & Frontend Portal Types (Member 1 & Member 4)
// -----------------------------------------------------------------------------

export interface QueryRequestPayload {
  endpointId: string;
  params: Record<string, string>;
}

/** Displayed inside the UI's "Advanced / Verify On-Chain" toggle drawer */
export interface AdvancedVerificationTrace {
  http402Challenge: Http402ChallengePayload;
  midnightProof: {
    policyId: string;
    nullifierHash: string;
    issuerMerkleRoot: string;
    proofPreview: string;
    identityExposed: false;
    mode: RuntimeMode;
  };
  cardanoSettlement: {
    txHash: string;
    explorerUrl: string;
    confirmationStatus: "submitted-mempool" | "confirmed-onchain";
    split: RevenueSplitBreakdown;
    vaultScriptAddress: string;
    mode: RuntimeMode;
  };
}

export interface QuerySuccessResponse<TData = Record<string, unknown>> {
  status: 200;
  endpointId: string;
  summaryBadge: string;
  data: TData;
  advancedTrace: AdvancedVerificationTrace;
}

export interface AgentResearchRequest {
  question: string;
  maxBudgetLovelace?: string;
}

export interface AgentStepTrace {
  step: number;
  title: string;
  detail: string;
  status: "done" | "error";
  endpointId?: string;
  txHash?: string;
  explorerUrl?: string;
  nullifierHash?: string;
}

export interface AgentResearchResponse {
  question: string;
  answerMarkdown: string;
  totalSpentLovelace: string;
  queriesExecuted: number;
  steps: AgentStepTrace[];
  traces: AdvancedVerificationTrace[];
}
