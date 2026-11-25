import type { RevenueSplitBps, RevenueSplitBreakdown, RuntimeMode, SwitchboardConfig } from "./types.js";

function parseMode(raw: string | undefined, fallback: RuntimeMode = "mock"): RuntimeMode {
  return raw?.trim().toLowerCase() === "live" ? "live" : fallback;
}

/**
 * Safely reads the zero-wait feature flags from Node's `process.env` or any record.
 * Defaults to `"mock"` so every track boots standalone without external credentials.
 */
export function readSwitchboardConfig(
  env: Record<string, string | undefined> = {},
): SwitchboardConfig {
  return {
    gatewayMode: parseMode(env["GATEWAY_MODE"] ?? env["NEXT_PUBLIC_GATEWAY_MODE"], "mock"),
    midnightMode: parseMode(env["MIDNIGHT_MODE"], "mock"),
    cardanoMode: parseMode(env["CARDANO_MODE"], "mock"),
    gatewayUrl: env["NEXT_PUBLIC_GATEWAY_URL"]?.trim() || "http://localhost:4000",
  };
}

export function assertValidSplitBps(splitBps: RevenueSplitBps): void {
  const [owner, operator, protocol] = splitBps;
  if (
    !Number.isInteger(owner) ||
    !Number.isInteger(operator) ||
    !Number.isInteger(protocol) ||
    owner < 0 ||
    operator < 0 ||
    protocol < 0 ||
    owner + operator + protocol !== 10_000
  ) {
    throw new Error(
      `Invalid revenue split basis points [${splitBps.join(", ")}]: must be non-negative integers summing to 10000`,
    );
  }
}

/**
 * Exact BigInt lovelace revenue split matching Aiken on-chain integer arithmetic.
 * Any 1-2 lovelace remainder goes to the dataset owner so `owner + operator + protocol === total`.
 */
export function calculateRevenueSplit(
  totalLovelaceInput: string | bigint,
  splitBps: RevenueSplitBps,
): RevenueSplitBreakdown {
  assertValidSplitBps(splitBps);
  const total = typeof totalLovelaceInput === "bigint" ? totalLovelaceInput : BigInt(totalLovelaceInput);
  if (total < 0n) {
    throw new Error("totalLovelace must be non-negative");
  }

  const [, operatorBps, protocolBps] = splitBps;
  const operator = (total * BigInt(operatorBps)) / 10_000n;
  const protocol = (total * BigInt(protocolBps)) / 10_000n;
  const owner = total - operator - protocol;

  return {
    totalLovelace: total.toString(),
    datasetOwnerLovelace: owner.toString(),
    apiOperatorLovelace: operator.toString(),
    protocolTreasuryLovelace: protocol.toString(),
    splitBps,
  };
}

/** Deterministic UTC day epoch integer (e.g., 20261124 -> integer days since Unix epoch). */
export function getCurrentEpochDay(now: Date = new Date()): number {
  return Math.floor(now.getTime() / 86_400_000);
}

export function lovelaceToAdaString(lovelace: string | bigint): string {
  const value = typeof lovelace === "bigint" ? lovelace : BigInt(lovelace);
  const whole = value / 1_000_000n;
  const frac = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return frac.length > 0 ? `${whole}.${frac} tADA` : `${whole} tADA`;
}
