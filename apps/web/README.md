# Member 4 Track — Frontend UI/UX, Wallets & Pitch (`@zk-turnover/web`)

## Ownership
1. Build the non-technical web portal (Next.js or Vite + React) with 4 views:
   - **Business Research Portal (Default):** Browse `DEMO_CATALOG`, click **Run Verified Query**, display plain-English status badges (`summaryBadge`) without raw hashes.
   - **Autonomous AI Research Assistant Tab:** Interactive query input displaying `AgentStepTrace` live.
   - **Provider Console:** Register endpoints, configure 75/20/5 revenue splits, and view SLA bond status.
   - **"Advanced / Verify On-Chain" Drawer:** Toggle rendering `advancedTrace` (`http402Challenge`, Midnight `nullifierHash`, Cardano `txHash` + clickable Preprod CExplorer link).
2. Wire CIP-30 **Lace** and **Eternl** wallets + Midnight wallet connect (`1AM` / Lace).
3. Lead the final `README.md`, Adoption Brief, **2–4 min Demo Video**, and **Dec 17 Finale Pitch Deck**.

## Working Independently
Import `createGatewayClient()` from `src/gatewayClient.ts`. With `NEXT_PUBLIC_GATEWAY_MODE=mock`, it executes the full stateful `HTTP 402 -> Midnight ZK -> Cardano x402` flow directly in the browser — zero backend or blockchain setup needed to polish 100% of the UI!
