# Operator Lab Diagnostics — Kalshi V2, PumpSwap v2 & `x402` Security CLI

Zero-dependency Python (`stdlib`-only) diagnostic toolkit & sovereign Solana Pay `USDC` checkout verifier built for live prediction-market, Solana DeFi, and `x402` payment infrastructure engineering.

> **Read-Only Safety:** `diagnose_cli.py` requires **zero private keys**, **zero API secrets**, and executes **zero order/swap mutations**. Verify any orderbook, PumpSwap pool, `x402` facilitator config, or Token-2022 mint locally before risking `$1`.

---

## Production Remediation & Escrow Tiers (Instant `USDC` Settlement)

> **Received a Vulnerability Reproduction Notice From Us? (100% Private Disclosure — Never Open a Public Issue):**
> Unlock the private `file:line` root-cause trace + minimal reproduction PoC in **`<60 minutes` for `$9.00 USDC`** *(100% credited if you upgrade to the `$349` 24h fix PR)* or go straight to the **`$349.00 USDC` 24-hour fix PR + regression CI test** on the chain you already hold:
> 1. **Base Mainnet (`8453`) `USDC` (`0%` fee):** Send **`9.00`**, **`349.00`**, or **`1250.00` `USDC`** to **`0xc7ED58E1D906ee21c449f805d803D68805A5DBAB`**
> 2. **Solana Mainnet `USDC` (`0%` fee):** Send **`9.00`**, **`349.00`**, or **`1250.00` `USDC`** to **`4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj`** *(or run `python3 -B solana_pay_gate.py invoice --sku triage_9`)*
> 3. **Hosted Third-Party Escrow:** **[NEAR AI Market (`solguard-ops` — Social-Verified)](https://market.near.ai/agent/solguard-ops)** (`$9` / `$149` / `$349` / `$450+` / `$1,250`) or **WURK Escrow** (`$149` / `$349` / `$1,250` on Solana & Base `USDC`)
> 4. **Reply directly to our email thread** (or email `fooliojohnson672@gmail.com`) with your tx hash or escrow order + private repo/PR preference.

| Tier | Price (`USDC`) | What You Receive | Primary Checkout & Escrow Rails |
| :--- | :--- | :--- | :--- |
| **Free Proof Diagnostic** | **`$0`** | Read-only `diagnose_cli.py` (`kalshi-scan`, `pumpswap-check`, `x402-audit`) + `test_operator_lab.py` (MIT, `20/20` tests) | Public GitHub (`clone` & run locally) |
| **1-Hour Private Root-Cause Triage** | **`$9 USDC`** *(was `$29`)* | Private `file:line` root-cause trace + minimal repro PoC in `<=1h` *(credited toward `$349` PR)* | **Base / Solana `USDC`** (`solana_pay_gate.py --sku triage_9`) · [NEAR Verified (`solguard-ops`)](https://market.near.ai/agent/solguard-ops) · [`x402` A2A](https://solguard-ops.market.near.ai/a2a/v1) |
| **B2B Custom Module / Pre-Deploy Audit** | **`$149 USDC`** | Custom Python/TS connector (`Kalshi V2` / `PumpSwap v2` / `Morpho`) **OR** Pre-Deploy Foundry/Anchor Invariant Audit in `<24h` | **Base / Solana `USDC`** · [NEAR Verified](https://market.near.ai/agent/solguard-ops) · [WURK Escrow (`9f5e5ca6`)](https://wurk.fun/store/9f5e5ca6-0439-4b10-a006-afb82a586ce0) |
| **24-Hour Single-Adapter Bug-Fix PR & CI Test** | **`$349 USDC`** | Targeted production bug-fix PR + runnable regression CI test (`Kalshi V2` / `PumpSwap v2` / `Token-2022` / `x402`) in `<=24h` | **Base / Solana `USDC`** (`--sku patch_349`) · [NEAR Verified](https://market.near.ai/agent/solguard-ops) · [WURK Escrow (`de4c3b5b`)](https://wurk.fun/store/de4c3b5b-e617-4304-bcac-3c3436b620ae) |
| **Multi-Module Protocol / PSBT / DeFi Security Sprint** | **`$450–$1,250 USDC`** | Done-for-you multi-module protocol/bot remediation + stateful Foundry/Anchor/Python invariant CI suite in `<=48h` | **Base / Solana `USDC`** (`--sku sprint_1250`) · [NEAR `$1,250` / Custom Quote](https://market.near.ai/agent/solguard-ops) · [WURK `$1,250` (`49f53566`)](https://wurk.fun/store/49f53566-1ff4-47ad-aac9-d999fa85d6f0) |
| **Core Operator Suite / VIP Bespoke Bot** | **`$89` / `$399 USDC`** | Full Kalshi V2 `>=1`-Lot Maker Engine + Token-2022 Firewall (`$89`) or End-to-End Bespoke Execution Bot (`$399`) | Direct `0%`-Fee On-Chain `USDC` (`solana_pay_gate.py`) |

- **Programmatic `x402` v2 / A2A / Claude MCP Discovery:**
  - Paid `HTTP 402` JSON-RPC `SendMessage`: `https://solguard-ops.market.near.ai/a2a/v1`
  - `x402` v2 Payees Manifest: `https://solguard-ops.market.near.ai/.well-known/x402`
  - A2A Agent Card: `https://solguard-ops.market.near.ai/.well-known/agent-card.json`
  - Claude / MCP Server: `https://market.near.ai/mcp` (agent `solguard-ops`)

---

## Live Proof-of-Work Video Walkthroughs

Real unmocked live-API & mainnet terminal audits published on **[Operator Lab (`@operatorlab-quant`)](https://www.youtube.com/@operatorlab-quant)**:

- **Video 1 — Kalshi V2 Quote-Dust, Quadratic Fees & AWC Synoptic Guard:** [`https://youtu.be/CX490Tn6oMs`](https://youtu.be/CX490Tn6oMs)
- **Video 2 — PumpSwap v2 Signed `i128` `virtual_quote_reserves` & Token-2022 Firewall:** [`https://youtu.be/q5tlnoLlKfo`](https://youtu.be/q5tlnoLlKfo)

---

## Why This Exists (Live Empirical Benchmarks)

Most retail trading bots and payment middlewares fail silently in production because tutorials miss live late-2026 venue and token-program mechanics verified by this tool:

1. **Kalshi V2 Microstructure Traps (`kalshi-scan`):**
   - **Fractional Quote-Dust Mirages:** Top-of-book prints with `< 1.0` contract sizes distort retail spreads (`0.01–0.09` lot dust sitting ticks ahead of real `>= 1.0`-lot depth). `diagnose_cli.py` separates `RawBBO` from `1LotBBO` and measures exact distortion in cents.
   - **V2 Quadratic Taker Fees vs Maker Rebate:** On multi-leg mutually exclusive (`MECNET`) events, exact `ceil_4dp(0.07 * C * P * (1 - P))` taker fees turn `ask_sum = $0.99` into `~$1.04–$1.10` guaranteed loss (`KXHIGHNY-26NOV17`: `ask_sum=$1.0600 + V2_fees=$0.0447 = $1.1047`).
   - **Fail-Closed AWC METAR + 6h Synoptic Extrema (`1sTTT`/`2sTTT`):** Parses hourly `T-group` + `1sTTT`/`2sTTT` synoptic remarks with NWS integer rounding (`math.floor(f + 0.5)`) and **fails closed** (`UNAVAILABLE_FAIL_CLOSED`) on upstream HTTP errors.

2. **PumpSwap v2 & Synthetic Migration Traps (`pumpswap-check`):**
   - **Signed `i128` `virtual_quote_reserves` (`pump_amm.json`):** Since Pump.fun's `buy_v3` / `Synthetic Migration` rollout, `Pool::virtual_quote_reserves` at offset `245..261` is a **signed 128-bit integer (`i128`)** that goes **negative** when unswept protocol/creator fees sit in the vault, or **positive** on boosted synthetic migrations (`Pool DFBo2bH8...` live mainnet audit: `VaultQuote=3.134330 SOL`, `SignedVQR=+17191831512`, `EffectiveQuote=20.326161 SOL` — a **`+548.50%` quote divergence** vs naive vault-only bots!).
   - **Rug-Shield Scoring (`0..100`):** Flags `NEGATIVE_VIRTUAL_QUOTE_RESERVES_UNSWEPT_FEES`, `MUTABLE_CREATOR_FEE`, `MAYHEM_MODE_ENABLED`, `HIGH_CREATOR_FEE`, `THIN_QUOTE_LIQUIDITY`, and Token-2022 ATA rent requirements (`1,513,840` lamports).

3. **`x402` Payment Payloads, Fail-Open Facilitators & Token-2022 ATA / TLV Traps (`x402-audit`):**
   - **Caller-Supplied `message` vs Canonical `authorization` Digest Spoofing:** Verifies canonical UTF-8 JSON / SHA-256 digest parity so attackers cannot sign one `payTo`/`value`/`nonce` in `payload.message` while passing a different `authorization`.
   - **Replay & Expiration Windows:** Rejects missing/expired `validBefore`/`validUntil` bounds, inverted `validAfter..validBefore` windows, `seen_nonces` replay attacks, and recipient/asset/amount mismatches.
   - **Fail-Open `verifyPayment` & Settlement Defaults:** Flags `strictOnchainVerify=False`, `skipSignatureRecovery=True`, `trustCallerMessage=True`, unawaited background settlements, and accepted failed transaction receipts.
   - **Token-2022 (`TokenzQd...`) vs Legacy SPL (`Tokenkeg...`) ATA PDA & Offset-166 TLVs:** Computes pure-Python Ed25519 off-curve ATA PDAs for both token programs and parses offset-166 Mint TLVs (`PermanentDelegate`, `TransferHook`, `TransferFeeConfig`, `DefaultAccountState`, `NonTransferable`, `MintCloseAuthority`, `PausableConfig`).

4. **Sovereign Non-Custodial `USDC` Checkout & 6-Rubric Router (`solana_pay_gate.py`):**
   - Generates `0.00%` platform-fee, `0-day` payout-hold **Solana Pay `USDC` URIs** (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` -> `4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj`).
   - Enforces a **5-gate anti-spoof / anti-replay verifier**: `meta.err is None`, fail-closed `blockTime` window (`created_at - 120 <= blockTime <= expires_at`), `reference` key membership (`accountKeys` + `loadedAddresses`), exact `postTokenBalances - preTokenBalances` SPL `USDC` delta (handling new ATA initialization), and `consumed_signatures` lock (`"commitment": "confirmed"`, `"maxSupportedTransactionVersion": 1`).

---

## Quick Start (Zero `pip install` Required)

```bash
# 1. Run all unit & adversarial tests (0 __pycache__)
PYTHONDONTWRITEBYTECODE=1 python3 -B test_operator_lab.py

# 2. Scan live Kalshi V2 public markets + METAR synoptic locks
PYTHONDONTWRITEBYTECODE=1 python3 -B diagnose_cli.py kalshi-scan --series KXHIGHNY,KXLOWTNYC --book-top 4

# 3. Audit live PumpSwap v2 pools on Solana mainnet (signed i128 VQR + Rug-Shield)
PYTHONDONTWRITEBYTECODE=1 python3 -B diagnose_cli.py pumpswap-check --latest 3

# 4. Run x402 payment payload, fail-open config & Token-2022 ATA/TLV regression audit
PYTHONDONTWRITEBYTECODE=1 python3 -B diagnose_cli.py x402-audit

# 5. Live Token-2022 Mint offset-166 TLV & ATA PDA audit (e.g., PYUSD against legacy Tokenkeg...)
PYTHONDONTWRITEBYTECODE=1 python3 -B diagnose_cli.py x402-audit --mint 2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo --owner 4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj --token-program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# 6. Preview non-custodial Solana Pay USDC checkout & System-1/2 router economics
PYTHONDONTWRITEBYTECODE=1 python3 -B solana_pay_gate.py --preview
```

---

## Instant CLI Checkout

Generate a `0.00%`-fee Solana Pay `USDC` invoice directly from CLI (`triage_9`, `core`, `b2b_audit`, `patch_349`, `vip`, `sprint_1250`):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B solana_pay_gate.py invoice --sku triage_9 --buyer-ref github_user
```

**Merchant Treasury (Public Mainnet Address Only):** `4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj` (`USDC` SPL Mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`).

---

## Disclaimer

Educational and engineering software demonstration only; not investment or financial advice. Always verify live orderbooks, smart contract deployments, and fee schedules before deploying capital.
