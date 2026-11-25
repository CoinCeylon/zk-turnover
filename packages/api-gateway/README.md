# Member 1 Track — API Gateway, `x402` Middleware & AI Agent (`@zk-turnover/api-gateway`)

## Ownership
1. Serve `GET /api/catalog`, `POST /api/query/:endpointId` (returning `HTTP 402` challenge without headers, `HTTP 200` with verified data + `AdvancedVerificationTrace` once headers verify), `POST /api/agent/research`, and `POST /api/provider/endpoints`.
2. Enforce `HTTP_HEADERS.MIDNIGHT_ZK_PROOF` and `HTTP_HEADERS.PAYMENT_SIGNATURE` checks via `MidnightAdapter` and `CardanoAdapter`.
3. Build the autonomous AI Research Assistant loop that handles `HTTP 402` challenges automatically.

## Working Independently
Keep `MIDNIGHT_MODE=mock` and `CARDANO_MODE=mock` in `.env`. Both adapters from `@zk-turnover/contracts-spec` enforce real business rules (tier, jurisdiction, nullifier replay, underpayment) in memory so you never wait on Member 2 or Member 3.

## Solo Verification
```bash
npm run dev:gateway
npm run test:gateway
```
