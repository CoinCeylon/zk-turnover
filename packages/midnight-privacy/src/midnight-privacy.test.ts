import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  DEMO_CATALOG,
  JURISDICTION_FLAGS,
  LICENSE_TIERS,
  getCurrentEpochDay,
  sha256Hex,
} from "@zk-turnover/contracts-spec";
import {
  LiveMidnightAdapter,
  MidnightProofServerError,
  WitnessValidationError,
  buildSanitizedWitnessInputs,
  computeDeterministicNullifier,
  createMockWitnessInputs,
  createPrivacyAppWitnessProviders,
  sanitizeCallIndex,
  sanitizeJurisdictionCode,
  sanitizeLicenseTier,
  sanitizeOrgSecret,
} from "./index.js";

async function withMockProofServer<T>(
  fn: (proofServerUrl: string) => Promise<T>,
): Promise<T> {
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }
    const rawBody = Buffer.concat(chunks).toString("utf8");

    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    if (req.method === "POST" && req.url === "/prove") {
      const payload = JSON.parse(rawBody) as {
        publicInputs: { nullifierHash: string; policyId: string };
      };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          proofHex: sha256Hex(`mock-zk-snark:${payload.publicInputs.policyId}:${payload.publicInputs.nullifierHash}`),
          proverVersion: "compact-0.36.0-test",
          provingTimeMs: 12,
        }),
      );
      return;
    }

    if (req.method === "POST" && req.url === "/verify") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ valid: true }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to bind mock proof server");
  }
  const url = `http://127.0.0.1:${address.port}`;
  try {
    return await fn(url);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

test("witness sanitization enforces Compact 0.36.0 bounds and deterministic nullifiers", () => {
  const secretBytes = sanitizeOrgSecret("ceylon-org-secret");
  assert.equal(secretBytes.length, 32);

  assert.equal(sanitizeLicenseTier(2), 2);
  assert.throws(() => sanitizeLicenseTier(-1), WitnessValidationError);
  assert.throws(() => sanitizeLicenseTier(256), WitnessValidationError);

  assert.equal(sanitizeJurisdictionCode(JURISDICTION_FLAGS.LK | JURISDICTION_FLAGS.EU), 3);
  assert.throws(() => sanitizeJurisdictionCode(0), WitnessValidationError);

  assert.equal(sanitizeCallIndex(0, 5), 0);
  assert.throws(() => sanitizeCallIndex(5, 5), WitnessValidationError);

  const n1 = computeDeterministicNullifier({
    orgSecret: "ceylon-org-secret",
    endpointId: "lk-export-tariff-intel",
    epoch: 20500,
    callIndex: 0,
  });
  const n2 = computeDeterministicNullifier({
    orgSecret: "ceylon-org-secret",
    endpointId: "lk-export-tariff-intel",
    epoch: 20500,
    callIndex: 0,
  });
  const n3 = computeDeterministicNullifier({
    orgSecret: "ceylon-org-secret",
    endpointId: "lk-export-tariff-intel",
    epoch: 20501,
    callIndex: 0,
  });
  assert.equal(n1, n2);
  assert.notEqual(n1, n3);
});

test("LiveMidnightAdapter proves, verifies, and rejects replay/tier/jurisdiction/revocation", async () => {
  await withMockProofServer(async (proofServerUrl) => {
    const adapter = new LiveMidnightAdapter({
      proofServerUrl,
      contractAddress: "0xmidnight_privacy_app_test",
    });

    const health = await adapter.getClient().proofServer.healthCheck();
    assert.equal(health.healthy, true);

    const epoch = getCurrentEpochDay();
    const endpoint = DEMO_CATALOG[0]!;
    const demoCred = adapter.getClient().getDemoCredential();

    // Witness provider smoke check
    const sanitized = buildSanitizedWitnessInputs({
      credential: demoCred,
      endpointId: endpoint.endpointId,
      policy: endpoint.policy,
      currentEpoch: epoch,
      callIndex: 0,
    });
    const providers = createPrivacyAppWitnessProviders();
    const [, tierVal] = providers.license_tier({ privateState: { witness: sanitized } });
    assert.equal(tierVal, BigInt(LICENSE_TIERS.LICENSED_SME));

    // 1. Valid proof + verification (and verify zero private/linkable state in envelope)
    const mockWitness = createMockWitnessInputs();
    assert.equal(mockWitness.org_secret.length, 32);

    const proof = await adapter.generateAccessProof({
      credential: demoCred,
      endpointId: endpoint.endpointId,
      policy: endpoint.policy,
      currentEpoch: epoch,
      callIndex: 0,
    });
    assert.equal(proof.mode, "live");
    const decodedEnvelope = Buffer.from(proof.proofHex, "hex").toString("utf8");
    assert.equal(decodedEnvelope.includes(demoCred.orgSecret), false);
    assert.equal(decodedEnvelope.includes(demoCred.commitment), false);

    const verified = await adapter.verifyAccessProof(proof, endpoint.policy.policyId, epoch);
    assert.equal(verified.valid, true);

    // 2. Nullifier replay rejection
    const replay = await adapter.verifyAccessProof(proof, endpoint.policy.policyId, epoch);
    assert.equal(replay.valid, false);
    assert.match(replay.reason ?? "", /Nullifier already spent/i);

    // 3. Wrong tier rejection
    const lowTier = await adapter.issueDemoCredential({
      orgDisplayName: "Public Tier Org",
      licenseTier: LICENSE_TIERS.PUBLIC,
      jurisdictionMask: JURISDICTION_FLAGS.LK,
      expiryEpoch: epoch + 30,
    });
    await assert.rejects(
      () =>
        adapter.generateAccessProof({
          credential: lowTier.credential,
          endpointId: endpoint.endpointId,
          policy: endpoint.policy,
          currentEpoch: epoch,
          callIndex: 0,
        }),
      /license_tier/i,
    );

    // 4. Wrong jurisdiction rejection
    const usOnly = await adapter.issueDemoCredential({
      orgDisplayName: "US Only Org",
      licenseTier: LICENSE_TIERS.ENTERPRISE_REGULATED,
      jurisdictionMask: JURISDICTION_FLAGS.US,
      expiryEpoch: epoch + 30,
    });
    await assert.rejects(
      () =>
        adapter.generateAccessProof({
          credential: usOnly.credential,
          endpointId: endpoint.endpointId,
          policy: endpoint.policy,
          currentEpoch: epoch,
          callIndex: 0,
        }),
      /jurisdiction_code/i,
    );

    // 5. Revoked credential rejection
    const revocable = await adapter.issueDemoCredential({
      orgDisplayName: "Revocable Org",
      licenseTier: LICENSE_TIERS.ENTERPRISE_REGULATED,
      jurisdictionMask: JURISDICTION_FLAGS.LK,
      expiryEpoch: epoch + 30,
    });
    const revResult = await adapter.revokeCredential(revocable.credential.credentialId);
    assert.equal(revResult.revoked, true);
    await assert.rejects(
      () =>
        adapter.generateAccessProof({
          credential: revocable.credential,
          endpointId: endpoint.endpointId,
          policy: endpoint.policy,
          currentEpoch: epoch,
          callIndex: 0,
        }),
      /issuer_merkle_root/i,
    );
  });

  // 6. Unreachable Proof Server surfaces MidnightProofServerError when fallback disabled
  const offlineAdapter = new LiveMidnightAdapter({
    proofServerUrl: "http://127.0.0.1:1",
    contractAddress: "0xmidnight_privacy_app_test",
    requestTimeoutMs: 1000,
    allowLocalFallback: false,
  });
  const offlineEndpoint = DEMO_CATALOG[0]!;
  await assert.rejects(
    () =>
      offlineAdapter.generateAccessProof({
        credential: offlineAdapter.getClient().getDemoCredential(),
        endpointId: offlineEndpoint.endpointId,
        policy: offlineEndpoint.policy,
        currentEpoch: getCurrentEpochDay(),
        callIndex: 0,
      }),
    (err: unknown) => err instanceof MidnightProofServerError && err.code === "UNREACHABLE",
  );
});
