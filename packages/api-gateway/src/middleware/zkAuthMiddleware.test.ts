import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import test from "node:test";
import {
  DEMO_CATALOG,
  HTTP_HEADERS,
  MockMidnightAdapter,
  getCurrentEpochDay,
} from "@zk-turnover/contracts-spec";
import {
  InMemoryNullifierLogStore,
  createZkAuthMiddleware,
  extractZkProofFromHeaders,
  verifyZkAuthHeaders,
  type ZkAuthenticatedRequest,
} from "./zkAuthMiddleware.js";

test("extractZkProofFromHeaders parses JSON, base64, and hex-encoded proof headers", async () => {
  const midnight = new MockMidnightAdapter();
  const endpoint = DEMO_CATALOG[0]!;
  const epoch = getCurrentEpochDay();
  const proof = await midnight.generateAccessProof({
    credential: midnight.getDemoCredential(),
    endpointId: endpoint.endpointId,
    policy: endpoint.policy,
    currentEpoch: epoch,
    callIndex: 0,
  });

  const jsonStr = JSON.stringify(proof);
  const fromJson = extractZkProofFromHeaders({
    [HTTP_HEADERS.MIDNIGHT_ZK_PROOF]: jsonStr,
  });
  assert.equal(fromJson?.nullifierHash, proof.nullifierHash);

  const fromBase64 = extractZkProofFromHeaders({
    "X-MIDNIGHT-ZK-PROOF": Buffer.from(jsonStr, "utf8").toString("base64"),
  });
  assert.equal(fromBase64?.nullifierHash, proof.nullifierHash);

  const fromHex = extractZkProofFromHeaders({
    "X-MIDNIGHT-ZK-PROOF": Buffer.from(jsonStr, "utf8").toString("hex"),
  });
  assert.equal(fromHex?.nullifierHash, proof.nullifierHash);
});

test("verifyZkAuthHeaders and createZkAuthMiddleware enforce proof validity and log nullifiers", async () => {
  const midnight = new MockMidnightAdapter();
  const endpoint = DEMO_CATALOG[0]!;
  const epoch = getCurrentEpochDay();
  const logStore = new InMemoryNullifierLogStore();

  // 1. Missing header -> 401
  const missing = await verifyZkAuthHeaders({
    headers: {},
    midnightAdapter: midnight,
    expectedPolicyId: endpoint.policy.policyId,
    expectedEndpointId: endpoint.endpointId,
    expectedEpoch: epoch,
    nullifierLogStore: logStore,
  });
  assert.equal(missing.ok, false);
  if (!missing.ok) {
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.error, "MISSING_ZK_PROOF");
  }

  // 2. Valid proof -> ok + nullifier logged
  const proof = await midnight.generateAccessProof({
    credential: midnight.getDemoCredential(),
    endpointId: endpoint.endpointId,
    policy: endpoint.policy,
    currentEpoch: epoch,
    callIndex: 0,
  });

  const middleware = createZkAuthMiddleware({
    midnightAdapter: midnight,
    nullifierLogStore: logStore,
    resolvePolicy: () => ({
      endpointId: endpoint.endpointId,
      policyId: endpoint.policy.policyId,
      epoch,
    }),
  });

  const req = {
    headers: { [HTTP_HEADERS.MIDNIGHT_ZK_PROOF]: JSON.stringify(proof) },
  } as unknown as ZkAuthenticatedRequest;

  let statusCode = 200;
  let body = "";
  const res = {
    set statusCode(code: number) {
      statusCode = code;
    },
    get statusCode() {
      return statusCode;
    },
    setHeader() {},
    end(chunk?: string) {
      body = chunk ?? "";
    },
  } as unknown as ServerResponse;

  let nextCalled = false;
  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(req.zkAuth?.verification.valid, true);
  assert.equal(logStore.has(proof.nullifierHash), true);
  assert.equal(logStore.list().length, 1);

  // 3. Replay with same proof -> 403 NULLIFIER_REPLAY
  let nextCalledReplay = false;
  await middleware(req as IncomingMessage, res, () => {
    nextCalledReplay = true;
  });
  assert.equal(nextCalledReplay, false);
  assert.equal(statusCode, 403);
  assert.match(body, /NULLIFIER_REPLAY/);
});
