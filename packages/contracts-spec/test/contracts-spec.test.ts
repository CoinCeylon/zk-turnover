import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  calculateRevenueSplit,
  DEFAULT_REVENUE_SPLIT_BPS,
  DEMO_ADDRESSES,
  DEMO_CATALOG,
  getCurrentEpochDay,
  JURISDICTION_FLAGS,
  LICENSE_TIERS,
  MockCardanoAdapter,
  MockGatewayClient,
  MockMidnightAdapter,
  readSwitchboardConfig,
  sha256Hex,
} from "../src/index.js";

test("pure TS sha256Hex matches node:crypto sha256 exactly", () => {
  const samples = [
    "",
    "veil402",
    "Cardano Preprod + Midnight Compact ZK nullifier payload 1234567890!",
    "Sri Lanka Export Tariff Intelligence — Ceylon Tea & Cinnamon",
  ];
  for (const sample of samples) {
    const expected = createHash("sha256").update(sample, "utf8").digest("hex");
    assert.equal(sha256Hex(sample), expected);
  }
});

test("calculateRevenueSplit conserves total lovelace with exact 75/20/5 math", () => {
  const split = calculateRevenueSplit("2000001", DEFAULT_REVENUE_SPLIT_BPS);
  const sum =
    BigInt(split.datasetOwnerLovelace) +
    BigInt(split.apiOperatorLovelace) +
    BigInt(split.protocolTreasuryLovelace);
  assert.equal(sum, 2_000_001n);
  assert.equal(split.apiOperatorLovelace, "400000");
  assert.equal(split.protocolTreasuryLovelace, "100000");
  assert.equal(split.datasetOwnerLovelace, "1500001");
});

test("readSwitchboardConfig defaults safely to mock mode", () => {
  const defaults = readSwitchboardConfig({});
  assert.equal(defaults.gatewayMode, "mock");
  assert.equal(defaults.midnightMode, "mock");
  assert.equal(defaults.cardanoMode, "mock");

  const mixed = readSwitchboardConfig({
    GATEWAY_MODE: "live",
    CARDANO_MODE: "LIVE",
    MIDNIGHT_MODE: "mock",
  });
  assert.equal(mixed.gatewayMode, "live");
  assert.equal(mixed.cardanoMode, "live");
  assert.equal(mixed.midnightMode, "mock");
});

test("MockMidnightAdapter enforces policy, expiry, revocation, and nullifier replay", async () => {
  const midnight = new MockMidnightAdapter();
  const epoch = getCurrentEpochDay();
  const policy = DEMO_CATALOG[0]!.policy; // Tier 2, LK|EU|UK, max 25 calls

  const demoCred = midnight.getDemoCredential();
  const proof = await midnight.generateAccessProof({
    credential: demoCred,
    endpointId: DEMO_CATALOG[0]!.endpointId,
    policy,
    currentEpoch: epoch,
    callIndex: 0,
  });

  // First verification succeeds
  const firstVerify = await midnight.verifyAccessProof(proof, policy.policyId, epoch);
  assert.equal(firstVerify.valid, true);

  // Replaying same nullifier fails
  const replayVerify = await midnight.verifyAccessProof(proof, policy.policyId, epoch);
  assert.equal(replayVerify.valid, false);
  assert.match(replayVerify.reason ?? "", /Nullifier already spent/);

  // Low-tier credential fails circuit assertion
  const { credential: academicCred } = await midnight.issueDemoCredential({
    orgDisplayName: "University Research Lab",
    licenseTier: LICENSE_TIERS.ACADEMIC_RESEARCHER,
    jurisdictionMask: JURISDICTION_FLAGS.LK,
    expiryEpoch: epoch + 30,
  });
  await assert.rejects(
    () =>
      midnight.generateAccessProof({
        credential: academicCred,
        endpointId: DEMO_CATALOG[0]!.endpointId,
        policy,
        currentEpoch: epoch,
        callIndex: 0,
      }),
    /licenseTier/,
  );

  // Wrong jurisdiction fails circuit assertion
  const { credential: usCred } = await midnight.issueDemoCredential({
    orgDisplayName: "US Hedge Desk",
    licenseTier: LICENSE_TIERS.ENTERPRISE_REGULATED,
    jurisdictionMask: JURISDICTION_FLAGS.US,
    expiryEpoch: epoch + 30,
  });
  await assert.rejects(
    () =>
      midnight.generateAccessProof({
        credential: usCred,
        endpointId: DEMO_CATALOG[0]!.endpointId,
        policy,
        currentEpoch: epoch,
        callIndex: 0,
      }),
    /jurisdiction/,
  );

  // Revoked credential fails
  await midnight.revokeCredential(demoCred.credentialId);
  await assert.rejects(
    () =>
      midnight.generateAccessProof({
        credential: demoCred,
        endpointId: DEMO_CATALOG[0]!.endpointId,
        policy,
        currentEpoch: epoch,
        callIndex: 1,
      }),
    /Issuer Merkle root/,
  );
});

test("MockCardanoAdapter verifies x402 payment, rejects underpayment, and tracks SLA bonds", async () => {
  const cardano = new MockCardanoAdapter();
  const endpoint = DEMO_CATALOG[0]!;

  const unsigned = await cardano.buildX402PaymentTx({
    endpointId: endpoint.endpointId,
    toScriptAddress: endpoint.cardanoVaultScriptAddress,
    amountLovelace: endpoint.priceLovelace,
    payerAddress: DEMO_ADDRESSES.DEMO_BUYER_PREPROD,
    nullifierHash: sha256Hex("sample-nullifier"),
    policyId: endpoint.policy.policyId,
    splitBps: endpoint.splitBps,
  });

  // Unsigned tx is rejected
  const unsignedResult = await cardano.verifyAndSubmitX402Tx({
    signedTxCbor: unsigned.unsignedTxCbor,
    expectedLovelace: endpoint.priceLovelace,
    expectedScriptAddress: endpoint.cardanoVaultScriptAddress,
    endpointId: endpoint.endpointId,
    splitBps: endpoint.splitBps,
  });
  assert.equal(unsignedResult.valid, false);

  // Signed tx with exact payment succeeds
  const signed = MockCardanoAdapter.mockSignTx(unsigned.unsignedTxCbor);
  const settled = await cardano.verifyAndSubmitX402Tx({
    signedTxCbor: signed,
    expectedLovelace: endpoint.priceLovelace,
    expectedScriptAddress: endpoint.cardanoVaultScriptAddress,
    endpointId: endpoint.endpointId,
    splitBps: endpoint.splitBps,
  });
  assert.equal(settled.valid, true);
  assert.equal(settled.txHash.length, 64);
  assert.match(settled.explorerUrl, /^https:\/\/preprod\.cexplorer\.io\/tx\/[0-9a-f]{64}$/);
  assert.equal(settled.split.datasetOwnerLovelace, "1500000");
  assert.equal(settled.split.apiOperatorLovelace, "400000");
  assert.equal(settled.split.protocolTreasuryLovelace, "100000");

  // Underpayment fails
  const underpaid = await cardano.verifyAndSubmitX402Tx({
    signedTxCbor: signed,
    expectedLovelace: "5000000",
    expectedScriptAddress: endpoint.cardanoVaultScriptAddress,
    endpointId: endpoint.endpointId,
    splitBps: endpoint.splitBps,
  });
  assert.equal(underpaid.valid, false);
  assert.match(underpaid.reason ?? "", /Insufficient x402 payment/);

  // SLA bond reflects accrued revenue and resets after settle
  const bondBefore = await cardano.getSlaBondStatus(endpoint.endpointId);
  assert.equal(bondBefore?.accruedRevenueLovelace, "2000000");
  await cardano.buildSettleSplitTx(endpoint.endpointId);
  const bondAfter = await cardano.getSlaBondStatus(endpoint.endpointId);
  assert.equal(bondAfter?.accruedRevenueLovelace, "0");
});

test("MockGatewayClient runs full verified query and autonomous AI agent flow end-to-end", async () => {
  const gateway = new MockGatewayClient();
  const catalog = await gateway.listCatalog();
  assert.equal(catalog.length, 3);

  const response = await gateway.executeVerifiedQuery({
    endpointId: "lk-export-tariff-intel",
    params: { commodity: "Ceylon Black Tea", destination: "EU" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.advancedTrace.midnightProof.identityExposed, false);
  assert.equal(response.advancedTrace.cardanoSettlement.txHash.length, 64);

  const agentReport = await gateway.runAgentResearch({
    question: "Compare EU tariff rules and PDPA privacy obligations for tea exports",
  });
  assert.equal(agentReport.queriesExecuted, 2);
  assert.equal(agentReport.totalSpentLovelace, "3500000");
  assert.equal(agentReport.traces.length, 2);
});
