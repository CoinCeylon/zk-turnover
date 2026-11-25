import type {
  CardanoAdapter,
  RevenueSplitBps,
  SlaBondInput,
  SlaBondStatus,
  SlaRefundInput,
  UnsignedCardanoTx,
  X402BuildPaymentInput,
  X402SettlementResult,
} from "@zk-turnover/contracts-spec";

/**
 * Member 3 implements this live adapter backed by `aiken/validators/sla_revenue_vault.ak`,
 * Mesh SDK (`@meshsdk/core`, `@meshsdk/x402`), and Blockfrost/Koios on Cardano Preprod.
 */
export class LiveCardanoAdapter implements CardanoAdapter {
  readonly mode = "live" as const;

  constructor(
    private readonly config: {
      network: "preprod" | "preview";
      scriptAddress: string;
      protocolTreasuryAddress: string;
      blockfrostApiKey?: string;
      koiosUrl?: string;
    },
  ) {}

  async buildX402PaymentTx(_input: X402BuildPaymentInput): Promise<UnsignedCardanoTx> {
    throw new Error(
      `LiveCardanoAdapter.buildX402PaymentTx not yet wired (script: ${this.config.scriptAddress})`,
    );
  }

  async verifyAndSubmitX402Tx(_params: {
    signedTxCbor: string;
    expectedLovelace: string;
    expectedScriptAddress: string;
    endpointId: string;
    splitBps: RevenueSplitBps;
  }): Promise<X402SettlementResult> {
    throw new Error("LiveCardanoAdapter.verifyAndSubmitX402Tx not yet wired");
  }

  async buildPostSlaBondTx(_input: SlaBondInput): Promise<UnsignedCardanoTx> {
    throw new Error("LiveCardanoAdapter.buildPostSlaBondTx not yet wired");
  }

  async buildSettleSplitTx(_endpointId: string): Promise<UnsignedCardanoTx> {
    throw new Error("LiveCardanoAdapter.buildSettleSplitTx not yet wired");
  }

  async buildSlaRefundTx(_input: SlaRefundInput): Promise<UnsignedCardanoTx> {
    throw new Error("LiveCardanoAdapter.buildSlaRefundTx not yet wired");
  }

  async getSlaBondStatus(_endpointId: string): Promise<SlaBondStatus | null> {
    throw new Error("LiveCardanoAdapter.getSlaBondStatus not yet wired");
  }
}
