# Veil402 (`CoinCeylon/zk-turnover`)

**ZK-Gated Pay-Per-Call API & Data Marketplace** built for **UniHack 2026 Sri Lanka** (*Blockchain for Real-World Adoption* — Business & Digital Services + Privacy & Trusted Applications).

- **Midnight (Compact ZK + Proof Server):** Proves business/researcher compliance, policy eligibility, and per-epoch rate limits without exposing corporate identity or linking queries across sessions.
- **Cardano (Mesh SDK `x402` + Aiken on Preprod):** Settles every verified API query natively over `HTTP 402 Payment Required`, backed by an **Aiken** smart contract enforcing provider **SLA bonds** and automated **75% / 20% / 5%** revenue splits.

---

## Zero-Wait 4-Member Architecture

All four tracks import a single frozen interface & mock package — [`packages/contracts-spec`](packages/contracts-spec) (`@zk-turnover/contracts-spec`) — so every teammate can build and test independently until switching `.env` flags from `mock` to `live`.

| Track | Folder | Package | Switchboard Flag |
| :--- | :--- | :--- | :--- |
| **Shared Spec & Mocks** | `packages/contracts-spec/` | `@zk-turnover/contracts-spec` | *(imported by all 4 tracks)* |
| **Member 1 — Gateway & AI Agent** | `packages/api-gateway/` | `@zk-turnover/api-gateway` | `GATEWAY_MODE=mock\|live` |
| **Member 2 — Midnight Privacy** | `packages/midnight-privacy/` | `@zk-turnover/midnight-privacy` | `MIDNIGHT_MODE=mock\|live` |
| **Member 3 — Cardano Settlement** | `packages/cardano-settlement/` | `@zk-turnover/cardano-settlement` | `CARDANO_MODE=mock\|live` |
| **Member 4 — Web Portal & Pitch** | `apps/web/` | `@zk-turnover/web` | `NEXT_PUBLIC_GATEWAY_MODE=mock\|live` |

---

## Quick Start (Clean Machine)

```bash
# 1. Copy environment template (defaults to mock mode so everything runs immediately)
cp .env.example .env

# 2. Install workspace dependencies
npm install

# 3. Build and run unit tests for the shared contract spec & mocks
npm run build:spec
npm run test:spec
```

### Starting the Midnight Proof Server (Member 2 / Full Integration)

```bash
docker compose --profile midnight up -d
```

---

## Security & Hackathon Compliance Checklist

- [x] Official UniHack 2026 GitHub repo (`https://github.com/CoinCeylon/zk-turnover`)
- [x] Open-sourced under **Apache 2.0** ([LICENSE](LICENSE))
- [x] `.env.example` included; `.env`, seed phrases, private keys, and API keys ignored via `.gitignore`
- [ ] Preprod Cardano demo transactions & CExplorer verification links added by Member 3
- [ ] Midnight Compact contract & Docker Proof Server instructions verified by Member 2
- [ ] 2–4 minute demo video & Adoption Brief added before **14 Dec 2026, 12:00 noon**
