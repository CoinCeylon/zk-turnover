import type { GatewayClient } from "../adapters.js";
import {
  buildDemoEndpointPayload,
  DEFAULT_REVENUE_SPLIT_BPS,
  DEMO_ADDRESSES,
  DEMO_CATALOG,
} from "../constants.js";
import { assertValidSplitBps, getCurrentEpochDay, lovelaceToAdaString } from "../env.js";
import type {
  AgentResearchRequest,
  AgentResearchResponse,
  AgentStepTrace,
  AdvancedVerificationTrace,
  DatasetEndpoint,
  Http402ChallengePayload,
  ProviderRegistrationInput,
  QueryRequestPayload,
  QuerySuccessResponse,
} from "../types.js";
import { MockCardanoAdapter } from "./mockCardanoAdapter.js";
import { MockMidnightAdapter } from "./mockMidnightAdapter.js";

/**
 * Drop-in mock Gateway client for Member 4 (`apps/web`) when `GATEWAY_MODE=mock`.
 * Executes the real HTTP 402 -> Midnight ZK -> Cardano x402 contract lifecycle in memory.
 */
export class MockGatewayClient implements GatewayClient {
  readonly mode = "mock" as const;

  private readonly endpoints: DatasetEndpoint[];
  private readonly midnight: MockMidnightAdapter;
  private readonly cardano: MockCardanoAdapter;
  private readonly callCounters = new Map<string, number>();

  constructor(
    midnight: MockMidnightAdapter = new MockMidnightAdapter(),
    cardano: MockCardanoAdapter = new MockCardanoAdapter(),
  ) {
    this.endpoints = DEMO_CATALOG.map((ep) => ({ ...ep, policy: { ...ep.policy } }));
    this.midnight = midnight;
    this.cardano = cardano;
  }

  async listCatalog(): Promise<readonly DatasetEndpoint[]> {
    return this.endpoints.map((ep) => ({ ...ep }));
  }

  async requestChallenge(endpointId: string): Promise<Http402ChallengePayload> {
    const endpoint = this.findEndpoint(endpointId);
    const currentEpoch = getCurrentEpochDay();
    const issuerMerkleRoot = await this.midnight.getIssuerMerkleRoot();

    return {
      status: 402,
      error: "PAYMENT_AND_ZK_PROOF_REQUIRED",
      message: `Provide a Midnight ZK proof for policy ${endpoint.policy.policyId} and Cardano x402 payment of ${lovelaceToAdaString(endpoint.priceLovelace)}.`,
      payment: {
        scheme: "cardano-eutxo-x402",
        network: "cardano-preprod",
        asset: endpoint.assetUnit,
        amountLovelace: endpoint.priceLovelace,
        payToAddress: endpoint.cardanoVaultScriptAddress,
        endpointId: endpoint.endpointId,
        splitBps: endpoint.splitBps,
        expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      },
      privacy: {
        network: "midnight-testnet",
        policy: endpoint.policy,
        currentEpoch,
        issuerMerkleRoot,
      },
    };
  }

  async executeVerifiedQuery<TData = Record<string, unknown>>(
    request: QueryRequestPayload,
    options?: {
      payerAddress?: string;
      signTx?: (unsignedTxCbor: string) => Promise<string>;
    },
  ): Promise<QuerySuccessResponse<TData>> {
    const endpoint = this.findEndpoint(request.endpointId);
    const challenge = await this.requestChallenge(endpoint.endpointId);
    const credential = this.midnight.getDemoCredential();

    const counterKey = `${endpoint.endpointId}:${challenge.privacy.currentEpoch}`;
    const callIndex = this.callCounters.get(counterKey) ?? 0;

    const zkProof = await this.midnight.generateAccessProof({
      credential,
      endpointId: endpoint.endpointId,
      policy: endpoint.policy,
      currentEpoch: challenge.privacy.currentEpoch,
      callIndex,
    });

    const verification = await this.midnight.verifyAccessProof(
      zkProof,
      endpoint.policy.policyId,
      challenge.privacy.currentEpoch,
    );
    if (!verification.valid) {
      throw new Error(`Midnight ZK proof rejected: ${verification.reason}`);
    }
    this.callCounters.set(counterKey, callIndex + 1);

    const payerAddress = options?.payerAddress ?? DEMO_ADDRESSES.DEMO_BUYER_PREPROD;
    const unsigned = await this.cardano.buildX402PaymentTx({
      endpointId: endpoint.endpointId,
      toScriptAddress: challenge.payment.payToAddress,
      amountLovelace: challenge.payment.amountLovelace,
      payerAddress,
      nullifierHash: zkProof.nullifierHash,
      policyId: endpoint.policy.policyId,
      splitBps: endpoint.splitBps,
    });

    const signedTxCbor = options?.signTx
      ? await options.signTx(unsigned.unsignedTxCbor)
      : MockCardanoAdapter.mockSignTx(unsigned.unsignedTxCbor, payerAddress);

    const settlement = await this.cardano.verifyAndSubmitX402Tx({
      signedTxCbor,
      expectedLovelace: challenge.payment.amountLovelace,
      expectedScriptAddress: challenge.payment.payToAddress,
      endpointId: endpoint.endpointId,
      splitBps: endpoint.splitBps,
    });
    if (!settlement.valid) {
      throw new Error(`Cardano x402 payment rejected: ${settlement.reason}`);
    }

    const data = buildDemoEndpointPayload(endpoint.endpointId, request.params) as TData;
    const advancedTrace: AdvancedVerificationTrace = {
      http402Challenge: challenge,
      midnightProof: {
        policyId: zkProof.policyId,
        nullifierHash: zkProof.nullifierHash,
        issuerMerkleRoot: zkProof.issuerMerkleRoot,
        proofPreview: `${zkProof.proofHex.slice(0, 32)}...`,
        identityExposed: false,
        mode: "mock",
      },
      cardanoSettlement: {
        txHash: settlement.txHash,
        explorerUrl: settlement.explorerUrl,
        confirmationStatus: settlement.confirmationStatus,
        split: settlement.split,
        vaultScriptAddress: endpoint.cardanoVaultScriptAddress,
        mode: "mock",
      },
    };

    return {
      status: 200,
      endpointId: endpoint.endpointId,
      summaryBadge: `Eligibility Verified · Identity Hidden · Paid ${lovelaceToAdaString(endpoint.priceLovelace)}`,
      data,
      advancedTrace,
    };
  }

  async runAgentResearch(request: AgentResearchRequest): Promise<AgentResearchResponse> {
    const targetIds = ["lk-export-tariff-intel", "licensed-legal-ai-brief"];
    const steps: AgentStepTrace[] = [];
    const traces: AdvancedVerificationTrace[] = [];
    let totalSpent = 0n;
    let stepNum = 1;

    for (const endpointId of targetIds) {
      const result = await this.executeVerifiedQuery({
        endpointId,
        params: { topic: request.question, destination: "EU" },
      });
      totalSpent += BigInt(result.advancedTrace.cardanoSettlement.split.totalLovelace);
      traces.push(result.advancedTrace);
      steps.push({
        step: stepNum++,
        title: `HTTP 402 -> ZK Proof + Cardano Settlement (${endpointId})`,
        detail: result.summaryBadge,
        status: "done",
        endpointId,
        txHash: result.advancedTrace.cardanoSettlement.txHash,
        explorerUrl: result.advancedTrace.cardanoSettlement.explorerUrl,
        nullifierHash: result.advancedTrace.midnightProof.nullifierHash,
      });
    }

    return {
      question: request.question,
      answerMarkdown: [
        `### Autonomous Research Summary`,
        `Query: **${request.question}**`,
        ``,
        `- **Trade & Tariff Feed:** Ceylon Cinnamon & Tea exports to the EU qualify for 0.0% GSP+ tariff rates when accompanied by EUDR plot geolocation attestations (avg Colombo port clearance: 18.4 hrs).`,
        `- **Regulatory Brief (Sri Lanka PDPA):** Using zero-knowledge eligibility proofs avoids sharing corporate identity or raw personal records with external data brokers.`,
        `- **Settlement Proof:** Executed ${traces.length} verified pay-per-call queries totaling **${lovelaceToAdaString(totalSpent)}** with zero monthly subscriptions and zero identity leakage.`,
      ].join("\n"),
      totalSpentLovelace: totalSpent.toString(),
      queriesExecuted: traces.length,
      steps,
      traces,
    };
  }

  async registerEndpoint(input: ProviderRegistrationInput): Promise<DatasetEndpoint> {
    const splitBps = input.splitBps ?? DEFAULT_REVENUE_SPLIT_BPS;
    assertValidSplitBps(splitBps);

    await this.cardano.buildPostSlaBondTx({
      endpointId: input.endpointId,
      providerAddress: input.ownerAddress,
      bondLovelace: input.slaBondLovelace,
      splitBps,
    });

    const created: DatasetEndpoint = {
      endpointId: input.endpointId,
      name: input.name,
      category: input.category,
      description: input.description,
      providerName: input.providerName,
      priceLovelace: input.priceLovelace,
      assetUnit: "lovelace",
      policy: {
        ...input.policy,
        policyId: `pol-${input.endpointId}`,
      },
      cardanoVaultScriptAddress: DEMO_ADDRESSES.VAULT_SCRIPT_PREPROD,
      ownerAddress: input.ownerAddress,
      operatorAddress: input.operatorAddress,
      protocolAddress: DEMO_ADDRESSES.PROTOCOL_TREASURY_PREPROD,
      splitBps,
      slaBondLovelace: input.slaBondLovelace,
      slaBacked: true,
      sampleParams: {},
    };
    this.endpoints.push(created);
    return created;
  }

  private findEndpoint(endpointId: string): DatasetEndpoint {
    const found = this.endpoints.find((ep) => ep.endpointId === endpointId);
    if (!found) {
      throw new Error(`Unknown endpointId: ${endpointId}`);
    }
    return found;
  }
}
