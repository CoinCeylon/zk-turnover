# Member 2 Track — Midnight Privacy & ZK Circuits (`@zk-turnover/midnight-privacy`)

## Ownership
1. Configure MidSkills (`npx skills add Kali-Decoder/Midnight-skills -y`), Compact 0.36.0, Midnight.js 5.0.0, and Docker Proof Server (`docker compose --profile midnight up -d`).
2. Write `contracts/access_gate.compact`:
   - Public ledger: `issuer_merkle_root`, `endpoint_policies`, `spent_nullifiers`.
   - Private witness: `org_secret`, `license_tier`, `jurisdiction_code`, `expiry_epoch`, `merkle_path`, `call_index`.
   - Enforce Merkle inclusion, tier/jurisdiction bitmask, expiry, and unique unlinkable nullifier output.
3. Implement `LiveMidnightAdapter` in `src/index.ts` matching `MidnightAdapter` from `@zk-turnover/contracts-spec`.

## Working Independently
You do not need the Gateway, Cardano, or Next.js frontend. Prove your track works solo by passing unit + testnet integration tests on `LiveMidnightAdapter` (valid proof, wrong tier, wrong jurisdiction, revoked credential, and nullifier replay).
