import {
  MockCardanoAdapter,
  MockMidnightAdapter,
  readSwitchboardConfig,
  type CardanoAdapter,
  type MidnightAdapter,
} from "@zk-turnover/contracts-spec";

export interface GatewayRuntimeAdapters {
  midnight: MidnightAdapter;
  cardano: CardanoAdapter;
}

/**
 * Resolves Midnight and Cardano adapters based on `.env` switchboard flags.
 * Member 1 develops entirely against `mock` adapters until Member 2 & Member 3
 * pass their solo tests and flip `MIDNIGHT_MODE=live` / `CARDANO_MODE=live`.
 */
export function resolveGatewayAdapters(
  env: Record<string, string | undefined> = process.env,
  liveOverrides?: Partial<GatewayRuntimeAdapters>,
): GatewayRuntimeAdapters {
  const config = readSwitchboardConfig(env);

  const midnight: MidnightAdapter =
    config.midnightMode === "live" && liveOverrides?.midnight
      ? liveOverrides.midnight
      : new MockMidnightAdapter();

  const cardano: CardanoAdapter =
    config.cardanoMode === "live" && liveOverrides?.cardano
      ? liveOverrides.cardano
      : new MockCardanoAdapter();

  return { midnight, cardano };
}

// Entrypoint smoke log when running `npm run dev:gateway`
if (process.argv[1]?.endsWith("index.js")) {
  const config = readSwitchboardConfig(process.env);
  const adapters = resolveGatewayAdapters(process.env);
  console.log("[api-gateway] Switchboard:", config);
  console.log("[api-gateway] Active adapters:", {
    midnight: adapters.midnight.mode,
    cardano: adapters.cardano.mode,
  });
}
