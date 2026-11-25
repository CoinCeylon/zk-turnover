# Member 3 Track — Cardano Aiken & `x402` Settlement (`@zk-turnover/cardano-settlement`)

## Ownership
1. Initialize the Aiken project inside `aiken/` and implement `validators/sla_revenue_vault.ak`:
   - `PostOrTopUpBond`: Lock provider SLA collateral on-chain.
   - `SettleRevenue`: Enforce exact **75% / 20% / 5%** split (`calculateRevenueSplit` parity) and bind Midnight `nullifierHash` + `policyId` metadata.
   - `ClaimSlaRefund`: Refund caller from provider SLA bond upon breach.
2. Implement `LiveCardanoAdapter` in `src/index.ts` using `@meshsdk/core`, `@meshsdk/x402`, and Blockfrost/Koios on **Cardano Preprod**.
3. Record verified Preprod transaction hashes and `preprod.cexplorer.io` links for the root `README.md`.

## Working Independently
You do not need Midnight, the API Gateway, or the Frontend. Prove your track solo with `aiken check` and a standalone Preprod settlement test script on `LiveCardanoAdapter`.
