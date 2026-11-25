import type { DatasetEndpoint, RevenueSplitBps } from "./types.js";

/**
 * Standard HTTP headers shared between apps/web (Member 4), api-gateway (Member 1),
 * midnight-privacy (Member 2), and cardano-settlement (Member 3).
 */
export const HTTP_HEADERS = {
  PAYMENT_SIGNATURE: "payment-signature",
  PAYMENT_REQUIRED: "payment-required",
  MIDNIGHT_ZK_PROOF: "x-midnight-zk-proof",
  MIDNIGHT_NULLIFIER: "x-midnight-nullifier",
  MIDNIGHT_POLICY_ID: "x-midnight-policy-id",
  RECEIPT_TX_HASH: "x-cardano-tx-hash",
} as const;

export const NETWORK_CONFIG = {
  CARDANO_PREPROD_EXPLORER_BASE: "https://preprod.cexplorer.io",
  CARDANO_KOIOS_PREPROD_URL: "https://preprod.koios.rest/api/v1",
  MIDNIGHT_DEFAULT_PROOF_SERVER_URL: "http://localhost:6300",
} as const;

export function getPreprodExplorerTxUrl(txHash: string): string {
  return `${NETWORK_CONFIG.CARDANO_PREPROD_EXPLORER_BASE}/tx/${txHash}`;
}

/**
 * Bitmask flags matching Compact ZK circuit jurisdiction checks:
 * `(credential.jurisdictionMask & policy.allowedJurisdictionMask) != 0`.
 */
export const JURISDICTION_FLAGS = {
  LK: 1 << 0, // 1  - Sri Lanka
  EU: 1 << 1, // 2  - European Union
  UK: 1 << 2, // 4  - United Kingdom
  US: 1 << 3, // 8  - United States
  SG: 1 << 4, // 16 - Singapore
  GLOBAL: (1 << 5) - 1, // 31 - Any supported jurisdiction
} as const;

export const LICENSE_TIERS = {
  PUBLIC: 0,
  ACADEMIC_RESEARCHER: 1,
  LICENSED_SME: 2,
  ENTERPRISE_REGULATED: 3,
} as const;

export const DEFAULT_REVENUE_SPLIT_BPS: RevenueSplitBps = [7500, 2000, 500];

export const DEMO_ADDRESSES = {
  VAULT_SCRIPT_PREPROD: "addr_test1wqveil402slavaultdemopreprod0000000000000000000000001",
  DATASET_OWNER_PREPROD: "addr_test1qzveil402owner000000000000000000000000000000000000001",
  API_OPERATOR_PREPROD: "addr_test1qzveil402operator000000000000000000000000000000000001",
  PROTOCOL_TREASURY_PREPROD: "addr_test1qzveil402treasury0000000000000000000000000000000001",
  DEMO_BUYER_PREPROD: "addr_test1qzveil402buyer000000000000000000000000000000000000001",
} as const;

/**
 * Three flagship commercial endpoints shared across Gateway & Frontend mocks.
 * Prices are denominated in Preprod lovelace (1 tADA = 1,000,000 lovelace).
 */
export const DEMO_CATALOG: readonly DatasetEndpoint[] = [
  {
    endpointId: "lk-export-tariff-intel",
    name: "Sri Lanka Export & Customs Tariff Intelligence",
    category: "Trade & Supply Chain",
    description:
      "Real-time EU/UK HS-code tariff schedules, EUDR deforestation risk scores, and port clearance benchmarks for Ceylon tea, cinnamon, spices, and apparel.",
    providerName: "LankaTrade Data Consortium",
    priceLovelace: "2000000", // 2 tADA
    assetUnit: "lovelace",
    policy: {
      policyId: "pol-export-tier2-lk-eu-uk",
      minTier: LICENSE_TIERS.LICENSED_SME,
      allowedJurisdictionMask:
        JURISDICTION_FLAGS.LK | JURISDICTION_FLAGS.EU | JURISDICTION_FLAGS.UK,
      maxCallsPerEpoch: 25,
    },
    cardanoVaultScriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
    ownerAddress: DEMO_ADDRESSES.DATASET_OWNER_PREPROD,
    operatorAddress: DEMO_ADDRESSES.API_OPERATOR_PREPROD,
    protocolAddress: DEMO_ADDRESSES.PROTOCOL_TREASURY_PREPROD,
    splitBps: DEFAULT_REVENUE_SPLIT_BPS,
    slaBondLovelace: "50000000", // 50 tADA
    slaBacked: true,
    sampleParams: {
      commodity: "Ceylon Cinnamon (HS 0906.11)",
      destination: "EU",
    },
  },
  {
    endpointId: "sme-credit-risk-snapshot",
    name: "Verified SME Corporate Risk & Sanctions Snapshot",
    category: "Commercial Risk & Compliance",
    description:
      "Confidential B2B counterparty risk score, beneficial-ownership watchflags, and invoice payment-velocity index without exposing which company you are researching.",
    providerName: "Colombo Commercial Bureau",
    priceLovelace: "3000000", // 3 tADA
    assetUnit: "lovelace",
    policy: {
      policyId: "pol-risk-tier2-global",
      minTier: LICENSE_TIERS.LICENSED_SME,
      allowedJurisdictionMask: JURISDICTION_FLAGS.GLOBAL,
      maxCallsPerEpoch: 15,
    },
    cardanoVaultScriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
    ownerAddress: DEMO_ADDRESSES.DATASET_OWNER_PREPROD,
    operatorAddress: DEMO_ADDRESSES.API_OPERATOR_PREPROD,
    protocolAddress: DEMO_ADDRESSES.PROTOCOL_TREASURY_PREPROD,
    splitBps: DEFAULT_REVENUE_SPLIT_BPS,
    slaBondLovelace: "75000000", // 75 tADA
    slaBacked: true,
    sampleParams: {
      entityCode: "PV-88421-LK",
      jurisdiction: "LK",
    },
  },
  {
    endpointId: "licensed-legal-ai-brief",
    name: "Licensed Regulatory & PDPA AI Legal Brief",
    category: "AI & Legal Intelligence",
    description:
      "Pay-per-query specialized AI summarizer over Sri Lanka Personal Data Protection Act (PDPA), Central Bank circulars, and cross-border compliance clauses.",
    providerName: "LexCeylon AI Partners",
    priceLovelace: "1500000", // 1.5 tADA
    assetUnit: "lovelace",
    policy: {
      policyId: "pol-legal-tier1-global",
      minTier: LICENSE_TIERS.ACADEMIC_RESEARCHER,
      allowedJurisdictionMask: JURISDICTION_FLAGS.GLOBAL,
      maxCallsPerEpoch: 50,
    },
    cardanoVaultScriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
    ownerAddress: DEMO_ADDRESSES.DATASET_OWNER_PREPROD,
    operatorAddress: DEMO_ADDRESSES.API_OPERATOR_PREPROD,
    protocolAddress: DEMO_ADDRESSES.PROTOCOL_TREASURY_PREPROD,
    splitBps: DEFAULT_REVENUE_SPLIT_BPS,
    slaBondLovelace: "40000000", // 40 tADA
    slaBacked: true,
    sampleParams: {
      topic: "PDPA cross-border B2B data transfer requirements",
    },
  },
];

export function buildDemoEndpointPayload(
  endpointId: string,
  params: Record<string, string>,
): Record<string, unknown> {
  switch (endpointId) {
    case "lk-export-tariff-intel":
      return {
        commodity: params["commodity"] ?? "Ceylon Cinnamon (HS 0906.11)",
        destination: params["destination"] ?? "EU",
        preferentialTariffRate: "0.0% (GSP+ Eligible)",
        eudrComplianceRisk: "Low-Medium (Plot Geolocation Required)",
        avgColomboPortClearanceHours: 18.4,
        priceIndexUsdPerKg: 14.85,
        recommendedAction:
          "Attach plot-level geolocation attestation and phytosanitary certificate prior to vessel cut-off.",
        updatedAt: new Date().toISOString(),
      };
    case "sme-credit-risk-snapshot":
      return {
        entityCode: params["entityCode"] ?? "PV-88421-LK",
        riskTier: "A- (Low Counterparty Risk)",
        sanctionsAndPepMatch: false,
        medianInvoiceSettlementDays: 29,
        activeCourtDisputes: 0,
        recommendedCreditLimitLkr: "12,500,000",
        updatedAt: new Date().toISOString(),
      };
    case "licensed-legal-ai-brief":
      return {
        topic: params["topic"] ?? "PDPA cross-border B2B data transfer requirements",
        applicableStatute: "Sri Lanka Personal Data Protection Act No. 9 of 2022 (Part III)",
        executiveSummary:
          "Controllers transferring personal data outside Sri Lanka must verify adequacy decisions or binding safeguards. Replacing raw identity API keys with zero-knowledge eligibility proofs minimizes personal-data processing exposure.",
        complianceChecklist: [
          "Avoid collecting raw NIC or personal emails where eligibility proofs suffice",
          "Maintain audit-ready selective-disclosure logs for Data Protection Authority review",
          "Verify processor SLA and breach notification timelines",
        ],
        updatedAt: new Date().toISOString(),
      };
    default:
      return {
        endpointId,
        params,
        result: "Verified gated payload delivered successfully.",
        updatedAt: new Date().toISOString(),
      };
  }
}
