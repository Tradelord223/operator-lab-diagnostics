# Operator Lab Diagnostics — Kalshi V2 & PumpSwap v2 Proof-of-Work CLI

Zero-dependency Python (`stdlib`-only) diagnostic toolkit & sovereign Solana Pay `USDC` checkout verifier built for live prediction-market and Solana DeFi execution engineering.

> **Read-Only Safety:** `diagnose_cli.py` requires **zero private keys**, **zero API secrets**, and executes **zero order/swap mutations**. Verify any orderbook or PumpSwap pool locally before risking `$1`.

---

## Live Proof-of-Work Video Walkthroughs

Real unmocked live-API & mainnet terminal audits published on **[Operator Lab (`@operatorlab-quant`)](https://www.youtube.com/@operatorlab-quant)**:

- **Video 1 — Kalshi V2 Quote-Dust, Quadratic Fees & AWC Synoptic Guard:** [`https://youtu.be/CX490Tn6oMs`](https://youtu.be/CX490Tn6oMs)
- **Video 2 — PumpSwap v2 Signed `i128` `virtual_quote_reserves` & Token-2022 Firewall:** [`https://youtu.be/q5tlnoLlKfo`](https://youtu.be/q5tlnoLlKfo)

---

## Why This Exists (Live Empirical Benchmarks)

Most retail trading bots fail on Day 1 because public tutorials ignore live late-2026 venue mechanics verified by this tool:

1. **Kalshi V2 Microstructure Traps (`kalshi-scan`):**
   - **Fractional Quote-Dust Mirages:** Top-of-book prints with `< 1.0` contract sizes distort retail spreads (`0.01–0.09` lot dust sitting ticks ahead of real `>= 1.0`-lot depth). `diagnose_cli.py` separates `RawBBO` from `1LotBBO` and measures exact distortion in cents.
   - **V2 Quadratic Taker Fees vs Maker Rebate:** On multi-leg mutually exclusive (`MECNET`) events, exact `ceil_4dp(0.07 * C * P * (1 - P))` taker fees turn `ask_sum = $0.99` into `~$1.04–$1.10` guaranteed loss (`KXHIGHNY-26NOV17`: `ask_sum=$1.0600 + V2_fees=$0.0447 = $1.1047`).
   - **Fail-Closed AWC METAR + 6h Synoptic Extrema (`1sTTT`/`2sTTT`):** Parses hourly `T-group` + `1sTTT`/`2sTTT` synoptic remarks with NWS integer rounding (`math.floor(f + 0.5)`) and **fails closed** (`UNAVAILABLE_FAIL_CLOSED`) on upstream HTTP errors.

2. **PumpSwap v2 & Synthetic Migration Traps (`pumpswap-check`):**
   - **Signed `i128` `virtual_quote_reserves` (`pump_amm.json`):** Since Pump.fun's `buy_v3` / `Synthetic Migration` rollout, `Pool::virtual_quote_reserves` at offset `245..261` is a **signed 128-bit integer (`i128`)** that goes **negative** when unswept protocol/creator fees sit in the vault, or **positive** on boosted synthetic migrations (`Pool DFBo2bH8...` live mainnet audit: `VaultQuote=3.134330 SOL`, `SignedVQR=+17191831512`, `EffectiveQuote=20.326161 SOL` — a **`+548.50%` quote divergence** vs naive vault-only bots!).
   - **Rug-Shield Scoring (`0..100`):** Flags `NEGATIVE_VIRTUAL_QUOTE_RESERVES_UNSWEPT_FEES`, `MUTABLE_CREATOR_FEE`, `MAYHEM_MODE_ENABLED`, `HIGH_CREATOR_FEE`, `THIN_QUOTE_LIQUIDITY`, and Token-2022 ATA rent requirements (`1,513,840` lamports).

3. **Sovereign Non-Custodial `USDC` Checkout & 6-Rubric Router (`solana_pay_gate.py`):**
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

# 4. Preview non-custodial Solana Pay USDC checkout & System-1/2 router economics
PYTHONDONTWRITEBYTECODE=1 python3 -B solana_pay_gate.py --preview
```

---

## Production Engineering & Custom Build Tiers (Instant `USDC` Settlement)

Bypass 7–14 day card holds and third-party custody freezes. All paid tiers settle directly in **Solana `USDC`** (`~400ms` finality, `0%` chargebacks) or **WURK Escrow** (`wurk.fun/store` — `solguard_ops`):

| Tier | Price (`USDC`) | What You Receive | Settlement Rail |
| :--- | :--- | :--- | :--- |
| **Free Proof Diagnostic** | **`$0`** | Read-only `diagnose_cli.py` + `test_operator_lab.py` (MIT) | Public GitHub |
| **Core Operator Suite** | **`$89 USDC`** | Full Kalshi V2 Synoptic & `>=1`-Lot Maker Engine + Pre-Sign Solana/Token-2022 Firewall + Playbook | Instant Solana Pay `USDC` |
| **B2B Custom Module / Pre-Deploy Audit** | **`$149 USDC`** | Custom Python/TS connector (`Kalshi V2` / `PumpSwap v2` / `Morpho`) **OR** Pre-Deploy Foundry/Anchor Invariant Audit delivered with runnable fork tests in `<24h` (fix free within 12h or cancel unapproved WURK escrow if tests fail) | [WURK Store Escrow (`9f5e5ca6`)](https://wurk.fun/store/9f5e5ca6-0439-4b10-a006-afb82a586ce0) or Direct Solana Pay `USDC` |
| **VIP Bespoke Codex Bot + Invariant Suite** | **`$399 USDC`** | End-to-end custom execution bot + full stateful Foundry/Anchor invariant test suite + priority engineering integration | Instant Solana Pay `USDC` |
| **48-Hour Production Bug-Fix & Invariant CI Sprint** | **`$1,250 USDC`** | Done-for-you production bot/protocol remediation (Kalshi V2 `DELETE /orders`, PumpSwap `i128` `virtual_quote_reserves`, Token-2022 TLV guard) + runnable stateful invariant CI suite in `<=48h` | [WURK Store Escrow (`49f53566`)](https://wurk.fun/store/49f53566-1ff4-47ad-aac9-d999fa85d6f0) or Direct Solana Pay `USDC` |

Generate an instant checkout URI directly from CLI:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B solana_pay_gate.py invoice --sku sprint_1250 --buyer-ref github_user
```

**Merchant Treasury (Public Mainnet Address Only):** `4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj` (`USDC` SPL Mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`).

---

## Disclaimer

Educational and engineering software demonstration only; not investment or financial advice. Always verify live orderbooks, smart contract deployments, and fee schedules before deploying capital.
