import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import {
  HTTP_HEADERS,
  getCurrentEpochDay,
  hexToUtf8,
  type MidnightAdapter,
  type RuntimeMode,
  type ZkAccessProofPayload,
  type ZkProofVerificationResult,
} from "@zk-turnover/contracts-spec";

export interface NullifierLogEntry {
  nullifierHash: string;
  policyId: string;
  endpointId: string;
  epoch: number;
  verifiedAt: string;
  mode: RuntimeMode;
}

export interface NullifierLogStore {
  has(nullifierHash: string): boolean;
  record(entry: NullifierLogEntry): void;
  list(): readonly NullifierLogEntry[];
}

export class InMemoryNullifierLogStore implements NullifierLogStore {
  private readonly entries = new Map<string, NullifierLogEntry>();

  has(nullifierHash: string): boolean {
    return this.entries.has(nullifierHash);
  }

  record(entry: NullifierLogEntry): void {
    this.entries.set(entry.nullifierHash, entry);
  }

  list(): readonly NullifierLogEntry[] {
    return Array.from(this.entries.values());
  }
}

export interface ZkAuthContext {
  proof: ZkAccessProofPayload;
  verification: ZkProofVerificationResult;
  nullifierLog: NullifierLogEntry;
}

export type ZkAuthVerificationOutcome =
  | {
      ok: true;
      context: ZkAuthContext;
    }
  | {
      ok: false;
      statusCode: 401 | 403;
      error: "MISSING_ZK_PROOF" | "INVALID_ZK_PROOF_FORMAT" | "ZK_PROOF_REJECTED" | "NULLIFIER_REPLAY";
      message: string;
      nullifierHash?: string;
    };

export interface ZkAuthPolicyResolverInput {
  endpointId?: string;
  policyId?: string;
  epoch?: number;
}

export interface ZkAuthMiddlewareOptions {
  midnightAdapter: MidnightAdapter;
  nullifierLogStore?: NullifierLogStore;
  resolvePolicy: (
    req: IncomingMessage,
  ) =>
    | Promise<{ endpointId: string; policyId: string; epoch?: number }>
    | { endpointId: string; policyId: string; epoch?: number };
  onNullifierLogged?: (entry: NullifierLogEntry) => void;
}

export interface ZkAuthenticatedRequest extends IncomingMessage {
  zkAuth?: ZkAuthContext;
}

function readHeaderValue(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  headerName: string,
): string | undefined {
  const target = headerName.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      if (Array.isArray(value)) {
        return value[0]?.trim();
      }
      return value?.trim();
    }
  }
  return undefined;
}

function isZkAccessProofPayload(candidate: unknown): candidate is ZkAccessProofPayload {
  if (!candidate || typeof candidate !== "object") {
    return false;
  }
  const obj = candidate as Record<string, unknown>;
  return (
    typeof obj["proofHex"] === "string" &&
    obj["proofHex"].length > 0 &&
    typeof obj["nullifierHash"] === "string" &&
    obj["nullifierHash"].length > 0 &&
    typeof obj["policyId"] === "string" &&
    obj["policyId"].length > 0 &&
    typeof obj["endpointId"] === "string" &&
    typeof obj["epoch"] === "number" &&
    typeof obj["issuerMerkleRoot"] === "string"
  );
}

/**
 * Extracts and parses `X-MIDNIGHT-ZK-PROOF` from request headers.
 * Supports JSON, base64-encoded JSON, hex-encoded JSON, or raw `proofHex` paired with
 * `X-MIDNIGHT-NULLIFIER` and `X-MIDNIGHT-POLICY-ID`.
 */
export function extractZkProofFromHeaders(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  fallback: ZkAuthPolicyResolverInput = {},
): ZkAccessProofPayload | null {
  const rawProof = readHeaderValue(headers, HTTP_HEADERS.MIDNIGHT_ZK_PROOF);
  if (!rawProof) {
    return null;
  }

  const tryParseJson = (text: string): ZkAccessProofPayload | null => {
    try {
      const parsed: unknown = JSON.parse(text);
      return isZkAccessProofPayload(parsed) ? parsed : null;
    } catch {
      return null;
    }
  };

  if (rawProof.startsWith("{")) {
    const direct = tryParseJson(rawProof);
    if (direct) {
      return direct;
    }
  }

  if (/^[0-9a-fA-F]+$/.test(rawProof) && rawProof.length % 2 === 0) {
    try {
      const fromHex = tryParseJson(hexToUtf8(rawProof));
      if (fromHex) {
        return fromHex;
      }
    } catch {
      // Fall through to base64 / raw proofHex handling.
    }
  }

  try {
    const decodedBase64 = Buffer.from(rawProof, "base64").toString("utf8");
    if (decodedBase64.startsWith("{")) {
      const fromBase64 = tryParseJson(decodedBase64);
      if (fromBase64) {
        return fromBase64;
      }
    }
  } catch {
    // Ignore invalid base64.
  }

  const nullifierHeader = readHeaderValue(headers, HTTP_HEADERS.MIDNIGHT_NULLIFIER);
  const policyHeader = readHeaderValue(headers, HTTP_HEADERS.MIDNIGHT_POLICY_ID) ?? fallback.policyId;
  if (/^[0-9a-fA-F]+$/.test(rawProof) && nullifierHeader && policyHeader) {
    return {
      proofHex: rawProof,
      nullifierHash: nullifierHeader,
      policyId: policyHeader,
      endpointId: fallback.endpointId ?? "",
      epoch: fallback.epoch ?? getCurrentEpochDay(),
      issuerMerkleRoot: "",
      mode: "live",
      generatedAt: new Date().toISOString(),
    };
  }

  throw new Error("Malformed X-MIDNIGHT-ZK-PROOF header");
}

/**
 * Verifies the extracted Midnight ZK proof against the configured `MidnightAdapter`
 * and logs the spent nullifier to prevent replay attacks.
 */
export async function verifyZkAuthHeaders(params: {
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>;
  midnightAdapter: MidnightAdapter;
  expectedPolicyId: string;
  expectedEndpointId?: string;
  expectedEpoch?: number;
  nullifierLogStore?: NullifierLogStore;
  onNullifierLogged?: (entry: NullifierLogEntry) => void;
}): Promise<ZkAuthVerificationOutcome> {
  const expectedEpoch = params.expectedEpoch ?? getCurrentEpochDay();

  let proof: ZkAccessProofPayload | null;
  try {
    proof = extractZkProofFromHeaders(params.headers, {
      policyId: params.expectedPolicyId,
      endpointId: params.expectedEndpointId,
      epoch: expectedEpoch,
    });
  } catch (error) {
    return {
      ok: false,
      statusCode: 401,
      error: "INVALID_ZK_PROOF_FORMAT",
      message: error instanceof Error ? error.message : "Malformed X-MIDNIGHT-ZK-PROOF header",
    };
  }

  if (!proof) {
    return {
      ok: false,
      statusCode: 401,
      error: "MISSING_ZK_PROOF",
      message: `Missing required ${HTTP_HEADERS.MIDNIGHT_ZK_PROOF} header`,
    };
  }

  if (params.expectedEndpointId && proof.endpointId !== params.expectedEndpointId) {
    return {
      ok: false,
      statusCode: 403,
      error: "ZK_PROOF_REJECTED",
      message: `Endpoint mismatch: expected ${params.expectedEndpointId}, received ${proof.endpointId}`,
      nullifierHash: proof.nullifierHash,
    };
  }

  if (params.nullifierLogStore?.has(proof.nullifierHash)) {
    return {
      ok: false,
      statusCode: 403,
      error: "NULLIFIER_REPLAY",
      message: `Nullifier ${proof.nullifierHash} has already been logged`,
      nullifierHash: proof.nullifierHash,
    };
  }

  const verification = await params.midnightAdapter.verifyAccessProof(
    proof,
    params.expectedPolicyId,
    expectedEpoch,
  );

  if (!verification.valid) {
    return {
      ok: false,
      statusCode: 403,
      error: "ZK_PROOF_REJECTED",
      message: verification.reason ?? "Midnight ZK proof verification failed",
      nullifierHash: verification.nullifierHash,
    };
  }

  const nullifierLog: NullifierLogEntry = {
    nullifierHash: verification.nullifierHash,
    policyId: verification.policyId,
    endpointId: proof.endpointId,
    epoch: proof.epoch,
    verifiedAt: verification.verifiedAt,
    mode: verification.mode,
  };

  params.nullifierLogStore?.record(nullifierLog);
  params.onNullifierLogged?.(nullifierLog);

  return {
    ok: true,
    context: {
      proof,
      verification,
      nullifierLog,
    },
  };
}

/**
 * Node / Express-compatible middleware that enforces `X-MIDNIGHT-ZK-PROOF`
 * verification and logs verified nullifiers.
 */
export function createZkAuthMiddleware(options: ZkAuthMiddlewareOptions) {
  const nullifierLogStore = options.nullifierLogStore ?? new InMemoryNullifierLogStore();

  return async function zkAuthMiddleware(
    req: ZkAuthenticatedRequest,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ): Promise<void> {
    try {
      const resolved = await options.resolvePolicy(req);
      const outcome = await verifyZkAuthHeaders({
        headers: req.headers,
        midnightAdapter: options.midnightAdapter,
        expectedPolicyId: resolved.policyId,
        expectedEndpointId: resolved.endpointId,
        expectedEpoch: resolved.epoch ?? getCurrentEpochDay(),
        nullifierLogStore,
        onNullifierLogged: options.onNullifierLogged,
      });

      if (!outcome.ok) {
        res.statusCode = outcome.statusCode;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            error: outcome.error,
            message: outcome.message,
            nullifierHash: outcome.nullifierHash,
          }),
        );
        return;
      }

      req.zkAuth = outcome.context;
      next();
    } catch (error) {
      next(error);
    }
  };
}
