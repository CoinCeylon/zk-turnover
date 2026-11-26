import { sha256Hex, type ZkAccessProofRequest } from "@zk-turnover/contracts-spec";

/**
 * Merkle tree depth matching `MerkleTreePath<16, Bytes<32>>` in `contracts/privacy_app.compact`.
 */
export const ISSUER_MERKLE_TREE_DEPTH = 16;

export interface MerklePathStep {
  sibling: Uint8Array;
  goes_left: boolean;
}

export interface CompactMerkleTreePath {
  leaf: Uint8Array;
  path: readonly MerklePathStep[];
}

/**
 * Sanitized off-chain witness inputs matching `privacy_app.compact` witness declarations:
 * - `org_secret`: 32-byte organization secret (never disclosed)
 * - `license_tier`: uint8 (0..255)
 * - `jurisdiction_code`: uint32 bitmask (1=LK, 2=EU, 4=UK, 8=US, 16=SG, 31=GLOBAL)
 * - `expiry_epoch`: uint64 UTC day epoch
 * - `call_index`: uint32 per-epoch rate-limit slot
 * - `merkle_path`: depth-16 Merkle inclusion path against `issuer_merkle_root`
 */
export interface SanitizedWitnessInputs {
  org_secret: Uint8Array;
  license_tier: number;
  jurisdiction_code: number;
  expiry_epoch: bigint;
  call_index: number;
  merkle_path: CompactMerkleTreePath;
}

export interface PrivacyAppPrivateState {
  readonly witness: SanitizedWitnessInputs;
}

export interface WitnessExecutionContext<TPrivateState = PrivacyAppPrivateState> {
  readonly privateState: TPrivateState;
}

/**
 * Midnight.js-compatible witness provider map for `contracts/privacy_app.compact`.
 * Each function returns `[nextPrivateState, witnessValue]` without mutating or leaking secrets.
 */
export interface PrivacyAppWitnessProviders {
  org_secret(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, Uint8Array];
  license_tier(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, bigint];
  jurisdiction_code(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, bigint];
  expiry_epoch(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, bigint];
  call_index(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, bigint];
  merkle_path(ctx: WitnessExecutionContext): [PrivacyAppPrivateState, CompactMerkleTreePath];
}

export class WitnessValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WitnessValidationError";
  }
}

export function hexToBytes32(hex: string, label = "value"): Uint8Array {
  const normalized = hex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new WitnessValidationError(`${label} must be a 32-byte (64-char) hex string`);
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Sanitizes `orgSecret` into a 32-byte `Uint8Array`.
 * Accepts either a 64-char hex secret or an arbitrary non-empty string (hashed via SHA-256).
 */
export function sanitizeOrgSecret(orgSecret: string): Uint8Array {
  if (typeof orgSecret !== "string" || orgSecret.trim().length === 0) {
    throw new WitnessValidationError("org_secret must be a non-empty string");
  }
  const trimmed = orgSecret.trim();
  const stripped = trimmed.replace(/^0x/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(stripped)) {
    return hexToBytes32(stripped, "org_secret");
  }
  return hexToBytes32(sha256Hex(trimmed), "org_secret");
}

/**
 * Sanitizes `license_tier` into Compact `Uint<8>` range [0, 255].
 */
export function sanitizeLicenseTier(licenseTier: number): number {
  if (!Number.isInteger(licenseTier) || licenseTier < 0 || licenseTier > 255) {
    throw new WitnessValidationError(
      `license_tier must be an integer between 0 and 255 (received: ${licenseTier})`,
    );
  }
  return licenseTier;
}

/**
 * Sanitizes `jurisdiction_code` into Compact `Uint<32>` non-zero bitmask.
 */
export function sanitizeJurisdictionCode(jurisdictionMask: number): number {
  if (
    !Number.isInteger(jurisdictionMask) ||
    jurisdictionMask <= 0 ||
    jurisdictionMask > 0xffff_ffff
  ) {
    throw new WitnessValidationError(
      `jurisdiction_code must be a positive 32-bit integer bitmask (received: ${jurisdictionMask})`,
    );
  }
  return jurisdictionMask;
}

/**
 * Sanitizes `expiry_epoch` into Compact `Uint<64>` (`bigint`).
 */
export function sanitizeExpiryEpoch(expiryEpoch: number): bigint {
  if (!Number.isInteger(expiryEpoch) || expiryEpoch < 0) {
    throw new WitnessValidationError(
      `expiry_epoch must be a non-negative integer epoch day (received: ${expiryEpoch})`,
    );
  }
  return BigInt(expiryEpoch);
}

/**
 * Sanitizes `call_index` into Compact `Uint<32>` and optionally enforces `maxCallsPerEpoch`.
 */
export function sanitizeCallIndex(callIndex: number, maxCallsPerEpoch?: number): number {
  if (!Number.isInteger(callIndex) || callIndex < 0 || callIndex > 0xffff_ffff) {
    throw new WitnessValidationError(
      `call_index must be a non-negative 32-bit integer (received: ${callIndex})`,
    );
  }
  if (maxCallsPerEpoch !== undefined && callIndex >= maxCallsPerEpoch) {
    throw new WitnessValidationError(
      `call_index ${callIndex} exceeds policy maxCallsPerEpoch (${maxCallsPerEpoch})`,
    );
  }
  return callIndex;
}

/**
 * Computes the deterministic credential commitment matching `@zk-turnover/contracts-spec`.
 */
export function computeCredentialCommitment(
  orgSecret: string,
  licenseTier: number,
  jurisdictionMask: number,
  expiryEpoch: number,
): string {
  const secretHex = bytesToHex(sanitizeOrgSecret(orgSecret));
  const tier = sanitizeLicenseTier(licenseTier);
  const jurisdiction = sanitizeJurisdictionCode(jurisdictionMask);
  const expiry = sanitizeExpiryEpoch(expiryEpoch);
  return sha256Hex(`cred:${secretHex}:${tier}:${jurisdiction}:${expiry.toString()}`);
}

/**
 * Computes the deterministic, unlinkable per-epoch nullifier hash for double-spend
 * and proof-replay protection.
 */
export function computeDeterministicNullifier(params: {
  orgSecret: string;
  endpointId: string;
  epoch: number;
  callIndex: number;
}): string {
  const secretHex = bytesToHex(sanitizeOrgSecret(params.orgSecret));
  const callIdx = sanitizeCallIndex(params.callIndex);
  if (!params.endpointId.trim()) {
    throw new WitnessValidationError("endpointId must be non-empty");
  }
  if (!Number.isInteger(params.epoch) || params.epoch < 0) {
    throw new WitnessValidationError("epoch must be a non-negative integer");
  }
  return sha256Hex(
    `nullifier:${secretHex}:${params.endpointId.trim()}:${params.epoch}:${callIdx}`,
  );
}

/**
 * Builds a padded depth-16 Merkle path for a credential leaf commitment.
 */
export function buildMerklePath(
  leafHex: string,
  steps: readonly { siblingHex: string; goesLeft: boolean }[] = [],
): CompactMerkleTreePath {
  const leaf = hexToBytes32(leafHex, "merkle_leaf");
  const path: MerklePathStep[] = [];
  for (let i = 0; i < ISSUER_MERKLE_TREE_DEPTH; i++) {
    const step = steps[i];
    if (step) {
      path.push({
        sibling: hexToBytes32(step.siblingHex, `merkle_path[${i}]`),
        goes_left: Boolean(step.goesLeft),
      });
    } else {
      path.push({
        sibling: new Uint8Array(32),
        goes_left: false,
      });
    }
  }
  return { leaf, path };
}

/**
 * Validates and sanitizes all private witness inputs from a `ZkAccessProofRequest`
 * before passing them to the local Midnight Proof Server.
 */
export function buildSanitizedWitnessInputs(
  request: ZkAccessProofRequest,
  merkleSteps: readonly { siblingHex: string; goesLeft: boolean }[] = [],
): SanitizedWitnessInputs {
  const { credential, policy, currentEpoch, callIndex } = request;

  if (credential.revoked) {
    throw new WitnessValidationError("Credential is marked revoked");
  }
  if (!Number.isInteger(currentEpoch) || currentEpoch < 0) {
    throw new WitnessValidationError(`Invalid currentEpoch: ${currentEpoch}`);
  }

  const org_secret = sanitizeOrgSecret(credential.orgSecret);
  const license_tier = sanitizeLicenseTier(credential.licenseTier);
  const jurisdiction_code = sanitizeJurisdictionCode(credential.jurisdictionMask);
  const expiry_epoch = sanitizeExpiryEpoch(credential.expiryEpoch);
  const call_index = sanitizeCallIndex(callIndex, policy.maxCallsPerEpoch);

  if (license_tier < policy.minTier) {
    throw new WitnessValidationError(
      `license_tier ${license_tier} is below policy minimum ${policy.minTier}`,
    );
  }
  if ((jurisdiction_code & policy.allowedJurisdictionMask) === 0) {
    throw new WitnessValidationError(
      `jurisdiction_code ${jurisdiction_code} does not intersect allowed mask ${policy.allowedJurisdictionMask}`,
    );
  }
  if (BigInt(currentEpoch) > expiry_epoch) {
    throw new WitnessValidationError(
      `Credential expired at epoch ${expiry_epoch.toString()} (current: ${currentEpoch})`,
    );
  }

  const merkle_path = buildMerklePath(credential.commitment, merkleSteps);

  return {
    org_secret,
    license_tier,
    jurisdiction_code,
    expiry_epoch,
    call_index,
    merkle_path,
  };
}

/**
 * Creates Midnight.js-compatible witness provider functions that expose private
 * inputs exclusively to the local proving circuit without mutating state.
 */
export function createPrivacyAppWitnessProviders(): PrivacyAppWitnessProviders {
  return {
    org_secret({ privateState }) {
      return [privateState, privateState.witness.org_secret];
    },
    license_tier({ privateState }) {
      return [privateState, BigInt(privateState.witness.license_tier)];
    },
    jurisdiction_code({ privateState }) {
      return [privateState, BigInt(privateState.witness.jurisdiction_code)];
    },
    expiry_epoch({ privateState }) {
      return [privateState, privateState.witness.expiry_epoch];
    },
    call_index({ privateState }) {
      return [privateState, BigInt(privateState.witness.call_index)];
    },
    merkle_path({ privateState }) {
      return [privateState, privateState.witness.merkle_path];
    },
  };
}

/**
 * Generates deterministic mock witness inputs for local development and unit tests
 * without requiring an active Midnight Proof Server or wallet connection.
 */
export function createMockWitnessInputs(overrides?: {
  orgSecret?: string;
  licenseTier?: number;
  jurisdictionMask?: number;
  expiryEpoch?: number;
  callIndex?: number;
}): SanitizedWitnessInputs {
  const orgSecret = overrides?.orgSecret ?? sha256Hex("veil402-mock-org-secret");
  const licenseTier = sanitizeLicenseTier(overrides?.licenseTier ?? 2);
  const jurisdictionMask = sanitizeJurisdictionCode(overrides?.jurisdictionMask ?? 1);
  const expiryEpoch = overrides?.expiryEpoch ?? 99_999;
  const callIndex = sanitizeCallIndex(overrides?.callIndex ?? 0);
  const commitment = computeCredentialCommitment(
    orgSecret,
    licenseTier,
    jurisdictionMask,
    expiryEpoch,
  );

  return {
    org_secret: sanitizeOrgSecret(orgSecret),
    license_tier: licenseTier,
    jurisdiction_code: jurisdictionMask,
    expiry_epoch: sanitizeExpiryEpoch(expiryEpoch),
    call_index: callIndex,
    merkle_path: buildMerklePath(commitment),
  };
}
