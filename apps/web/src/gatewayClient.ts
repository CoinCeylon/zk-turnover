import {
  MockGatewayClient,
  readSwitchboardConfig,
  type AgentResearchRequest,
  type AgentResearchResponse,
  type DatasetEndpoint,
  type GatewayClient,
  type Http402ChallengePayload,
  type ProviderRegistrationInput,
  type QueryRequestPayload,
  type QuerySuccessResponse,
} from "@zk-turnover/contracts-spec";

/**
 * Live HTTP client wired once `NEXT_PUBLIC_GATEWAY_MODE=live`.
 * Member 4 builds the entire UI against `MockGatewayClient` first with zero waiting.
 */
class HttpGatewayClient implements GatewayClient {
  readonly mode = "live" as const;

  constructor(private readonly baseUrl: string) {}

  async listCatalog(): Promise<readonly DatasetEndpoint[]> {
    const res = await fetch(`${this.baseUrl}/api/catalog`);
    if (!res.ok) throw new Error(`Catalog fetch failed (${res.status})`);
    return (await res.json()) as DatasetEndpoint[];
  }

  async requestChallenge(endpointId: string): Promise<Http402ChallengePayload> {
    const res = await fetch(`${this.baseUrl}/api/query/${encodeURIComponent(endpointId)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ params: {} }),
    });
    if (res.status !== 402) {
      throw new Error(`Expected HTTP 402 challenge, received ${res.status}`);
    }
    return (await res.json()) as Http402ChallengePayload;
  }

  async executeVerifiedQuery<TData = Record<string, unknown>>(
    _request: QueryRequestPayload,
    _options?: {
      payerAddress?: string;
      signTx?: (unsignedTxCbor: string) => Promise<string>;
    },
  ): Promise<QuerySuccessResponse<TData>> {
    throw new Error("Wire wallet-signed PAYMENT-SIGNATURE + X-MIDNIGHT-ZK-PROOF retry here in live mode");
  }

  async runAgentResearch(request: AgentResearchRequest): Promise<AgentResearchResponse> {
    const res = await fetch(`${this.baseUrl}/api/agent/research`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!res.ok) throw new Error(`Agent research failed (${res.status})`);
    return (await res.json()) as AgentResearchResponse;
  }

  async registerEndpoint(input: ProviderRegistrationInput): Promise<DatasetEndpoint> {
    const res = await fetch(`${this.baseUrl}/api/provider/endpoints`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    if (!res.ok) throw new Error(`Provider registration failed (${res.status})`);
    return (await res.json()) as DatasetEndpoint;
  }
}

export function createGatewayClient(
  env: Record<string, string | undefined> = {},
): GatewayClient {
  const config = readSwitchboardConfig(env);
  if (config.gatewayMode === "live") {
    return new HttpGatewayClient(config.gatewayUrl);
  }
  return new MockGatewayClient();
}
