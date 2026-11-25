import type { CardanoAdapter } from "../adapters.js";
import { DEMO_ADDRESSES, DEMO_CATALOG, getPreprodExplorerTxUrl } from "../constants.js";
import { assertValidSplitBps, calculateRevenueSplit } from "../env.js";
import { hexToUtf8, sha256Hex, utf8ToHex } from "../hash.js";
import type {
  RevenueSplitBps,
  SlaBondInput,
  SlaBondStatus,
  SlaRefundInput,
  UnsignedCardanoTx,
  X402BuildPaymentInput,
  X402SettlementResult,
} from "../types.js";

interface MockCborEnvelope {
  kind: "x402-payment" | "sla-bond" | "settle-split" | "sla-refund";
  endpointId: string;
  toScriptAddress: string;
  amountLovelace: string;
  payerAddress?: string;
  nullifierHash?: string;
  policyId?: string;
  splitBps?: RevenueSplitBps;
  signedBy?: string;
  nonce: string;
}

/**
 * Stateful in-memory Cardano Preprod + Aiken mock supporting deterministic x402 payment
 * verification, exact 75%/20%/5% BigInt revenue splits, SLA bonds, and SLA refunds.
 */
export class MockCardanoAdapter implements CardanoAdapter {
  readonly mode = "mock" as const;

  private readonly bonds = new Map<string, SlaBondStatus>();
  private txCounter = 0;

  constructor() {
    for (const ep of DEMO_CATALOG) {
      const seedTx = sha256Hex(`genesis-bond:${ep.endpointId}`);
      this.bonds.set(ep.endpointId, {
        endpointId: ep.endpointId,
        scriptAddress: ep.cardanoVaultScriptAddress,
        bondedLovelace: ep.slaBondLovelace,
        accruedRevenueLovelace: "0",
        active: ep.slaBacked,
        lastTxHash: seedTx,
        explorerUrl: getPreprodExplorerTxUrl(seedTx),
      });
    }
  }

  /** Helper for tests and mock wallet signing flows. */
  static mockSignTx(
    unsignedTxCbor: string,
    signerAddress: string = DEMO_ADDRESSES.DEMO_BUYER_PREPROD,
  ): string {
    const parsed = JSON.parse(hexToUtf8(unsignedTxCbor)) as MockCborEnvelope;
    const signed: MockCborEnvelope = { ...parsed, signedBy: signerAddress };
    return utf8ToHex(JSON.stringify(signed));
  }

  async buildX402PaymentTx(input: X402BuildPaymentInput): Promise<UnsignedCardanoTx> {
    assertValidSplitBps(input.splitBps);
    if (BigInt(input.amountLovelace) <= 0n) {
      throw new Error("x402 payment amountLovelace must be positive");
    }

    const envelope: MockCborEnvelope = {
      kind: "x402-payment",
      endpointId: input.endpointId,
      toScriptAddress: input.toScriptAddress,
      amountLovelace: input.amountLovelace,
      payerAddress: input.payerAddress,
      nullifierHash: input.nullifierHash,
      policyId: input.policyId,
      splitBps: input.splitBps,
      nonce: `${Date.now()}-${++this.txCounter}`,
    };

    return {
      unsignedTxCbor: utf8ToHex(JSON.stringify(envelope)),
      estimatedFeeLovelace: "178450", // ~0.178 tADA typical Cardano eUTxO fee
      metadataAttached: {
        endpointId: input.endpointId,
        nullifierHash: input.nullifierHash,
        policyId: input.policyId,
      },
      mode: "mock",
    };
  }

  async verifyAndSubmitX402Tx(params: {
    signedTxCbor: string;
    expectedLovelace: string;
    expectedScriptAddress: string;
    endpointId: string;
    splitBps: RevenueSplitBps;
  }): Promise<X402SettlementResult> {
    const now = new Date().toISOString();
    const zeroSplit = calculateRevenueSplit("0", params.splitBps);
    const fail = (reason: string): X402SettlementResult => ({
      valid: false,
      reason,
      txHash: "",
      explorerUrl: "",
      settledLovelace: "0",
      split: zeroSplit,
      confirmationStatus: "submitted-mempool",
      settledAt: now,
      mode: "mock",
    });

    let envelope: MockCborEnvelope;
    try {
      envelope = JSON.parse(hexToUtf8(params.signedTxCbor)) as MockCborEnvelope;
    } catch {
      return fail("Invalid signed Cardano CBOR payload");
    }

    if (envelope.kind !== "x402-payment") {
      return fail(`Unexpected transaction kind: ${envelope.kind}`);
    }
    if (!envelope.signedBy) {
      return fail("Transaction is unsigned");
    }
    if (envelope.endpointId !== params.endpointId) {
      return fail(`Endpoint mismatch: expected ${params.endpointId}, got ${envelope.endpointId}`);
    }
    if (envelope.toScriptAddress !== params.expectedScriptAddress) {
      return fail("Output script address does not match Aiken SLA revenue vault");
    }
    if (BigInt(envelope.amountLovelace) < BigInt(params.expectedLovelace)) {
      return fail(
        `Insufficient x402 payment: received ${envelope.amountLovelace} lovelace, expected at least ${params.expectedLovelace}`,
      );
    }

    const txHash = sha256Hex(`cardano-preprod-mock:${params.signedTxCbor}`);
    const split = calculateRevenueSplit(envelope.amountLovelace, params.splitBps);

    const existingBond = this.bonds.get(params.endpointId);
    if (existingBond) {
      existingBond.accruedRevenueLovelace = (
        BigInt(existingBond.accruedRevenueLovelace) + BigInt(envelope.amountLovelace)
      ).toString();
      existingBond.lastTxHash = txHash;
      existingBond.explorerUrl = getPreprodExplorerTxUrl(txHash);
    }

    return {
      valid: true,
      txHash,
      explorerUrl: getPreprodExplorerTxUrl(txHash),
      settledLovelace: envelope.amountLovelace,
      split,
      confirmationStatus: "submitted-mempool",
      settledAt: now,
      mode: "mock",
    };
  }

  async buildPostSlaBondTx(input: SlaBondInput): Promise<UnsignedCardanoTx> {
    assertValidSplitBps(input.splitBps);
    const bondAmount = BigInt(input.bondLovelace);
    if (bondAmount <= 0n) {
      throw new Error("SLA bond amount must be positive");
    }

    const envelope: MockCborEnvelope = {
      kind: "sla-bond",
      endpointId: input.endpointId,
      toScriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
      amountLovelace: input.bondLovelace,
      payerAddress: input.providerAddress,
      splitBps: input.splitBps,
      nonce: `${Date.now()}-${++this.txCounter}`,
    };
    const unsignedTxCbor = utf8ToHex(JSON.stringify(envelope));
    const txHash = sha256Hex(`sla-bond:${unsignedTxCbor}`);

    const current = this.bonds.get(input.endpointId);
    const nextTotal = current ? BigInt(current.bondedLovelace) + bondAmount : bondAmount;
    this.bonds.set(input.endpointId, {
      endpointId: input.endpointId,
      scriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
      bondedLovelace: nextTotal.toString(),
      accruedRevenueLovelace: current?.accruedRevenueLovelace ?? "0",
      active: true,
      lastTxHash: txHash,
      explorerUrl: getPreprodExplorerTxUrl(txHash),
    });

    return {
      unsignedTxCbor,
      estimatedFeeLovelace: "195000",
      metadataAttached: {
        endpointId: input.endpointId,
        nullifierHash: "sla-bond-collateral",
        policyId: "aiken-sla-vault",
      },
      mode: "mock",
    };
  }

  async buildSettleSplitTx(endpointId: string): Promise<UnsignedCardanoTx> {
    const status = this.bonds.get(endpointId);
    if (!status) {
      throw new Error(`No Aiken SLA vault found for endpoint ${endpointId}`);
    }
    const accrued = status.accruedRevenueLovelace;
    const envelope: MockCborEnvelope = {
      kind: "settle-split",
      endpointId,
      toScriptAddress: status.scriptAddress,
      amountLovelace: accrued,
      nonce: `${Date.now()}-${++this.txCounter}`,
    };
    status.accruedRevenueLovelace = "0";
    const unsignedTxCbor = utf8ToHex(JSON.stringify(envelope));
    const txHash = sha256Hex(`settle-split:${unsignedTxCbor}`);
    status.lastTxHash = txHash;
    status.explorerUrl = getPreprodExplorerTxUrl(txHash);

    return {
      unsignedTxCbor,
      estimatedFeeLovelace: "220000",
      metadataAttached: {
        endpointId,
        nullifierHash: "aiken-revenue-split",
        policyId: "aiken-sla-vault",
      },
      mode: "mock",
    };
  }

  async buildSlaRefundTx(input: SlaRefundInput): Promise<UnsignedCardanoTx> {
    const status = this.bonds.get(input.endpointId);
    if (!status) {
      throw new Error(`No SLA bond registered for endpoint ${input.endpointId}`);
    }
    const refund = BigInt(input.refundLovelace);
    const bonded = BigInt(status.bondedLovelace);
    if (refund <= 0n || refund > bonded) {
      throw new Error("Refund exceeds available SLA bond collateral");
    }

    status.bondedLovelace = (bonded - refund).toString();
    const envelope: MockCborEnvelope = {
      kind: "sla-refund",
      endpointId: input.endpointId,
      toScriptAddress: status.scriptAddress,
      amountLovelace: input.refundLovelace,
      payerAddress: input.callerAddress,
      nonce: `${Date.now()}-${++this.txCounter}`,
    };
    const unsignedTxCbor = utf8ToHex(JSON.stringify(envelope));
    const txHash = sha256Hex(`sla-refund:${unsignedTxCbor}`);
    status.lastTxHash = txHash;
    status.explorerUrl = getPreprodExplorerTxUrl(txHash);

    return {
      unsignedTxCbor,
      estimatedFeeLovelace: "210000",
      metadataAttached: {
        endpointId: input.endpointId,
        nullifierHash: input.originalTxHash,
        policyId: "aiken-sla-refund",
      },
      mode: "mock",
    };
  }

  async getSlaBondStatus(endpointId: string): Promise<SlaBondStatus | null> {
    const status = this.bonds.get(endpointId);
    return status ? { ...status } : null;
  }
}
