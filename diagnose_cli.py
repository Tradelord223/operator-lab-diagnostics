#!/usr/bin/env python3
"""Read-only Proof-of-Work diagnostic CLI for Kalshi V2, PumpSwap v2 & x402 / Token-2022.

Self-contained Python stdlib diagnostic exposing:
  1. `kalshi-scan` (`kalshi`): Live Kalshi V2 public orderbook quote-dust
     (<1.0 lot mirage) detection, 4dp quadratic taker vs $0.0000 post-only
     maker fee math, MECNET event Dutch-book cost check, and fail-closed
     NOAA/AWC METAR (`T-group` + `1sTTT`/`2sTTT` 6h synoptic) parser.
  2. `pumpswap-check` (`pumpswap`): Live Solana mainnet PumpSwap `Pool` and
     Pump.fun `BondingCurve` binary decoder with signed `i128`
     `virtual_quote_reserves` accounting, Synthetic Migration delta analysis,
     and non-custodial Rug-Shield scoring.
  3. `x402-audit` (`x402`): Deterministic x402 payment payload & facilitator
     security auditor checking canonical `authorization` vs caller `message`
     digest parity, `validBefore`/`validUntil` & `nonce` replay bounds,
     fail-open `verifyPayment` defaults, Token-2022 (`TokenzQd...`) vs legacy
     SPL (`Tokenkeg...`) ATA PDA derivation mismatches, and offset-166 Mint
     TLV hazard extensions (`PermanentDelegate`, `TransferHook`, `TransferFeeConfig`).

No secrets, private keys, or order-mutation endpoints are used.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import hashlib
import json
import math
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from typing import Any

KALSHI_API_BASE = "https://api.elections.kalshi.com/trade-api/v2"
AWC_METAR_URL = "https://aviationweather.gov/api/data/metar"
SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"

PUMPSWAP_PROGRAM_ID = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
WSOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

TOKEN_2022_EXTENSION_NAMES: dict[int, str] = {
    1: "TransferFeeConfig",
    2: "TransferFeeAmount",
    3: "MintCloseAuthority",
    4: "ConfidentialTransferMint",
    5: "ConfidentialTransferAccount",
    6: "DefaultAccountState",
    7: "ImmutableOwner",
    8: "MemoTransfer",
    9: "NonTransferable",
    10: "InterestBearingConfig",
    11: "CpiGuard",
    12: "PermanentDelegate",
    13: "NonTransferableAccount",
    14: "TransferHook",
    15: "TransferHookAccount",
    16: "ConfidentialTransferFeeConfig",
    18: "MetadataPointer",
    19: "TokenMetadata",
    20: "GroupPointer",
    21: "TokenGroup",
    22: "GroupMemberPointer",
    23: "TokenGroupMember",
    25: "ScaledUiAmountConfig",
    26: "PausableConfig",
}

POOL_DISCRIMINATOR = bytes.fromhex("f19a6d0411b16dbc")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {ch: idx for idx, ch in enumerate(B58_ALPHABET)}

# Public ICAO climate station map for Kalshi KXHIGH* / KXLOW* weather contracts
WEATHER_STATIONS: dict[str, str] = {
    "NY": "KNYC",
    "NYC": "KNYC",
    "MIA": "KMIA",
    "TPA": "KTPA",
    "CHI": "KMDW",
    "LAX": "KLAX",
    "AUS": "KAUS",
    "ATL": "KATL",
    "SFO": "KSFO",
    "PHIL": "KPHL",
    "PHL": "KPHL",
    "HOU": "KHOU",
    "DEN": "KDEN",
    "DC": "KDCA",
    "DAL": "KDFW",
    "SEA": "KSEA",
    "BOS": "KBOS",
    "PHX": "KPHX",
    "MIN": "KMSP",
    "LV": "KLAS",
    "SATX": "KSAT",
    "OKC": "KOKC",
    "NOLA": "KMSY",
    "TTN": "KTTN",
    "SDF": "KSDF",
    "EWR": "KEWR",
}


def b58encode(raw: bytes) -> str:
    """Encode raw bytes into canonical Bitcoin/Solana Base58."""
    num = int.from_bytes(raw, "big")
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(B58_ALPHABET[rem])
    for byte in raw:
        if byte == 0:
            chars.append("1")
        else:
            break
    return "".join(reversed(chars)) or "1"


def b58decode(text: str, expected_len: int | None = None) -> bytes:
    """Decode Base58 string into raw bytes, enforcing alphabet and optional length."""
    if not text:
        raise ValueError("Empty Base58 input")
    num = 0
    for ch in text:
        idx = B58_INDEX.get(ch)
        if idx is None:
            raise ValueError(f"Invalid Base58 character: {ch!r}")
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    out = (b"\x00" * leading_zeros) + raw
    if expected_len is not None and len(out) != expected_len:
        raise ValueError(f"Decoded length {len(out)} != expected {expected_len}")
    return out


def http_json(
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> Any:
    """Execute a read-only HTTP GET or JSON POST request."""
    headers = {"User-Agent": "OperatorLabDiag/1.0"}
    data: bytes | None = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def solana_rpc(method: str, params: list[Any], rpc_url: str = SOLANA_MAINNET_RPC) -> Any:
    """Invoke a Solana JSON-RPC read-only method and raise on RPC-level error."""
    resp = http_json(
        rpc_url,
        payload={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=15.0,
    )
    if "error" in resp and resp["error"]:
        raise RuntimeError(f"Solana RPC error ({method}): {resp['error']}")
    return resp.get("result")


# ---------------------------------------------------------------------------
# Kalshi V2 Microstructure, Quadratic Fees & Fail-Closed METAR Diagnostics
# ---------------------------------------------------------------------------


def kalshi_v2_taker_fee_dollars(price_dollars: Decimal, count: int = 1) -> Decimal:
    """Compute exact Kalshi V2 quadratic taker fee rounded up to $0.0001 (4dp)."""
    if price_dollars <= Decimal("0") or price_dollars >= Decimal("1") or count <= 0:
        return Decimal("0.0000")
    raw = Decimal("0.07") * Decimal(count) * price_dollars * (Decimal("1") - price_dollars)
    return raw.quantize(Decimal("0.0001"), rounding=ROUND_CEILING)


def extract_bbo_from_orderbook(orderbook_fp: dict[str, Any]) -> dict[str, float | None]:
    """Separate raw BBO (size > 0) from >= 1.0-lot BBO to expose quote-dust traps."""
    yes_levels = orderbook_fp.get("yes_dollars") or []
    no_levels = orderbook_fp.get("no_dollars") or []

    def best_bid(levels: list[list[Any]], min_size: float) -> float | None:
        best: float | None = None
        for row in levels:
            if len(row) < 2:
                continue
            price, size = float(row[0]), float(row[1])
            if size >= min_size and (best is None or price > best):
                best = price
        return best

    raw_yb = best_bid(yes_levels, 1e-9)
    lot1_yb = best_bid(yes_levels, 1.0)
    raw_nb = best_bid(no_levels, 1e-9)
    lot1_nb = best_bid(no_levels, 1.0)

    raw_ya = round(1.0 - raw_nb, 4) if raw_nb is not None else None
    lot1_ya = round(1.0 - lot1_nb, 4) if lot1_nb is not None else None

    raw_spread = round(raw_ya - raw_yb, 4) if (raw_ya is not None and raw_yb is not None) else None
    lot1_spread = round(lot1_ya - lot1_yb, 4) if (lot1_ya is not None and lot1_yb is not None) else None
    dust_distortion_cents = 0.0
    if raw_yb != lot1_yb or raw_ya != lot1_ya:
        yb_diff = abs((lot1_yb or 0.0) - (raw_yb or 0.0))
        ya_diff = abs((lot1_ya or 1.0) - (raw_ya or 1.0))
        dust_distortion_cents = round((yb_diff + ya_diff) * 100.0, 2)

    return {
        "raw_yes_bid": raw_yb,
        "raw_yes_ask": raw_ya,
        "lot1_yes_bid": lot1_yb,
        "lot1_yes_ask": lot1_ya,
        "raw_spread": raw_spread,
        "lot1_spread": lot1_spread,
        "dust_distortion_cents": dust_distortion_cents,
    }


def parse_metar_observations(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract station min/max F including T-group and 1sTTT/2sTTT 6-hr synoptic remarks."""
    if not rows:
        return {"status": "UNAVAILABLE_FAIL_CLOSED", "min_f": None, "max_f": None, "synoptic_groups": 0}

    temps_f: list[float] = []
    synoptic_count = 0

    def _signed_tenths_c_to_f(sign_char: str, digits: str) -> float:
        sign = -1.0 if sign_char == "1" else 1.0
        temp_c = sign * (int(digits) / 10.0)
        return temp_c * 9.0 / 5.0 + 32.0

    for row in rows:
        tc = row.get("temp")
        if tc is not None:
            temps_f.append(float(tc) * 9.0 / 5.0 + 32.0)
        raw = str(row.get("rawOb") or "")
        m_t = re.search(r"\bT([01])(\d{3})(?:([01])(\d{3}))?\b", raw)
        if m_t:
            temps_f.append(_signed_tenths_c_to_f(m_t.group(1), m_t.group(2)))
        for m_syn in re.finditer(r"\b([12])([01])(\d{3})\b", raw):
            temps_f.append(_signed_tenths_c_to_f(m_syn.group(2), m_syn.group(3)))
            synoptic_count += 1

    if not temps_f:
        return {"status": "UNAVAILABLE_FAIL_CLOSED", "min_f": None, "max_f": None, "synoptic_groups": 0}

    mn_f = min(temps_f)
    mx_f = max(temps_f)
    return {
        "status": "OK",
        "min_f": round(mn_f, 2),
        "max_f": round(mx_f, 2),
        "nws_int_min_f": math.floor(mn_f + 0.5),
        "nws_int_max_f": math.floor(mx_f + 0.5),
        "synoptic_groups": synoptic_count,
    }


def fetch_metar_fail_closed(icao: str, hours: int = 18) -> dict[str, Any]:
    """Fetch live AWC METARs; fail closed if upstream HTTP or payload fails."""
    url = f"{AWC_METAR_URL}?ids={urllib.parse.quote(icao)}&format=json&hours={hours}"
    try:
        rows = http_json(url, timeout=8.0)
        if not isinstance(rows, list):
            return {"status": "UNAVAILABLE_FAIL_CLOSED", "error": "non-list response"}
        parsed = parse_metar_observations(rows)
        parsed["icao"] = icao
        return parsed
    except Exception as exc:
        return {"status": "UNAVAILABLE_FAIL_CLOSED", "icao": icao, "error": str(exc)}


@dataclass
class KalshiMarketDiag:
    ticker: str
    event_ticker: str
    series_ticker: str
    fee_type: str
    raw_yes_bid: float | None
    raw_yes_ask: float | None
    lot1_yes_bid: float | None
    lot1_yes_ask: float | None
    dust_distortion_cents: float
    taker_fee_at_ask_dollars: float
    maker_fee_dollars: float
    volume_24h: float
    flags: list[str]


def _extract_series(market: dict[str, Any]) -> str:
    ticker = str(market.get("ticker") or "")
    return str(market.get("series_ticker") or ticker.split("-", 1)[0])


def evaluate_mecnet_dutch_book(
    markets: list[dict[str, Any]],
    verify_remote_mutually_exclusive: bool = False,
) -> list[dict[str, Any]]:
    """Verify whether any multi-leg mutually exclusive event clears V2 taker fees."""
    by_event: dict[str, list[dict[str, Any]]] = {}
    for m in markets:
        ev = str(m.get("event_ticker") or "")
        if ev:
            by_event.setdefault(ev, []).append(m)

    candidates: list[dict[str, Any]] = []
    for ev, legs in by_event.items():
        if len(legs) < 3:
            continue
        raw_ask_sum = Decimal("0")
        taker_fee_sum = Decimal("0")
        valid = True
        for leg in legs:
            ask_str = leg.get("yes_ask_dollars")
            if ask_str is None:
                valid = False
                break
            ask_dec = Decimal(str(ask_str))
            if ask_dec <= Decimal("0") or ask_dec > Decimal("1"):
                valid = False
                break
            raw_ask_sum += ask_dec
            taker_fee_sum += kalshi_v2_taker_fee_dollars(ask_dec, 1)
        if not valid:
            continue
        all_in_cost = raw_ask_sum + taker_fee_sum
        candidates.append(
            {
                "event_ticker": ev,
                "legs": len(legs),
                "raw_ask_sum": float(raw_ask_sum),
                "v2_taker_fee_sum": float(taker_fee_sum),
                "all_in_cost": float(all_in_cost),
                "net_dutch_edge": round(1.0 - float(all_in_cost), 4),
            }
        )
    candidates.sort(key=lambda r: r["all_in_cost"])
    if not verify_remote_mutually_exclusive:
        return candidates

    verified: list[dict[str, Any]] = []
    for cand in candidates[:12]:
        if cand["raw_ask_sum"] > 1.35:
            break
        try:
            ev_meta = http_json(f"{KALSHI_API_BASE}/events/{urllib.parse.quote(cand['event_ticker'])}").get("event") or {}
            if ev_meta.get("mutually_exclusive") is True:
                verified.append(cand)
        except Exception:
            continue
    return verified


def run_kalshi_scan(
    series_list: list[str],
    limit: int = 200,
    book_top: int = 10,
    check_metar: bool = True,
) -> dict[str, Any]:
    """Run live read-only Kalshi V2 market, quote-dust, fee, and METAR diagnostic."""
    markets: list[dict[str, Any]] = []
    if series_list:
        for series in series_list:
            qs = urllib.parse.urlencode({"status": "open", "series_ticker": series.strip(), "limit": min(limit, 200)})
            resp = http_json(f"{KALSHI_API_BASE}/markets?{qs}")
            markets.extend(resp.get("markets") or [])
    else:
        cursor = ""
        while len(markets) < limit:
            batch_limit = min(200, limit - len(markets))
            params = {"status": "open", "mve_filter": "exclude", "limit": batch_limit}
            if cursor:
                params["cursor"] = cursor
            resp = http_json(f"{KALSHI_API_BASE}/markets?{urllib.parse.urlencode(params)}")
            batch = resp.get("markets") or []
            markets.extend(batch)
            cursor = str(resp.get("cursor") or "")
            if not cursor or not batch:
                break

    # Prioritize liquid / tight markets for deep /orderbook quote-dust checks
    def _rank_key(m: dict[str, Any]) -> tuple[float, float]:
        vol = float(m.get("volume_24h_fp") or 0.0)
        yb = float(m.get("yes_bid_dollars") or 0.0)
        ya = float(m.get("yes_ask_dollars") or 1.0)
        spread = ya - yb
        return (-vol, spread)

    ranked = sorted(markets, key=_rank_key)
    series_fee_cache: dict[str, str] = {}
    diagnostics: list[KalshiMarketDiag] = []

    for m in ranked[:book_top]:
        ticker = str(m.get("ticker") or "")
        series = _extract_series(m)
        if series not in series_fee_cache:
            try:
                s_info = http_json(f"{KALSHI_API_BASE}/series/{urllib.parse.quote(series)}").get("series") or {}
                series_fee_cache[series] = str(s_info.get("fee_type") or "unknown")
            except Exception:
                series_fee_cache[series] = "unknown"
        fee_type = series_fee_cache[series]

        try:
            ob = http_json(f"{KALSHI_API_BASE}/markets/{urllib.parse.quote(ticker)}/orderbook")
            bbo = extract_bbo_from_orderbook(ob.get("orderbook_fp") or {})
        except Exception:
            bbo = {
                "raw_yes_bid": None,
                "raw_yes_ask": None,
                "lot1_yes_bid": None,
                "lot1_yes_ask": None,
                "dust_distortion_cents": 0.0,
            }

        ask_for_fee = bbo["lot1_yes_ask"] if bbo["lot1_yes_ask"] is not None else bbo["raw_yes_ask"]
        taker_fee = float(kalshi_v2_taker_fee_dollars(Decimal(str(ask_for_fee)))) if ask_for_fee is not None else 0.0
        flags: list[str] = []
        if bbo["dust_distortion_cents"] > 0:
            flags.append(f"QUOTE_DUST_{bbo['dust_distortion_cents']}c")
        if fee_type == "quadratic":
            flags.append("V2_QUADRATIC_0_MAKER")
        if m.get("price_level_structure") == "deci_cent" or (
            bbo["lot1_yes_bid"] is not None and (bbo["lot1_yes_bid"] <= 0.10 or (bbo["lot1_yes_ask"] or 0.0) >= 0.90)
        ):
            flags.append("SUBPENNY_GRID")

        diagnostics.append(
            KalshiMarketDiag(
                ticker=ticker,
                event_ticker=str(m.get("event_ticker") or ""),
                series_ticker=series,
                fee_type=fee_type,
                raw_yes_bid=bbo["raw_yes_bid"],
                raw_yes_ask=bbo["raw_yes_ask"],
                lot1_yes_bid=bbo["lot1_yes_bid"],
                lot1_yes_ask=bbo["lot1_yes_ask"],
                dust_distortion_cents=float(bbo["dust_distortion_cents"]),
                taker_fee_at_ask_dollars=taker_fee,
                maker_fee_dollars=0.0,
                volume_24h=float(m.get("volume_24h_fp") or 0.0),
                flags=flags,
            )
        )

    metar_checks: dict[str, Any] = {}
    if check_metar:
        icaos_needed: set[str] = set()
        for m in markets:
            series = _extract_series(m)
            match = re.match(r"^(?:KXHIGHT|KXHIGH|KXLOWT|KXLOW)([A-Z]+)$", series)
            if match and match.group(1) in WEATHER_STATIONS:
                icaos_needed.add(WEATHER_STATIONS[match.group(1)])
        for icao in sorted(icaos_needed)[:6]:
            metar_checks[icao] = fetch_metar_fail_closed(icao)

    dutch_books = evaluate_mecnet_dutch_book(markets, verify_remote_mutually_exclusive=True)[:5]
    return {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "markets_scanned": len(markets),
        "deep_orderbooks_checked": len(diagnostics),
        "dust_traps_detected": sum(1 for d in diagnostics if d.dust_distortion_cents > 0),
        "orderbooks": [asdict(d) for d in diagnostics],
        "tightest_mecnet_events": dutch_books,
        "metar_synoptic_checks": metar_checks,
    }


# ---------------------------------------------------------------------------
# PumpSwap v2 & BondingCurve Signed-Reserve / Rug-Shield Analyzer
# ---------------------------------------------------------------------------


def decode_pumpswap_pool(raw: bytes, pool_pubkey: str = "") -> dict[str, Any]:
    """Decode PumpSwap Pool account per pump_amm.json with signed i128 virtual_quote_reserves."""
    if len(raw) < 287:
        raise ValueError(f"Pool account data too short: {len(raw)} bytes < 287")
    if raw[:8] != POOL_DISCRIMINATOR:
        raise ValueError(f"Unexpected Pool discriminator: {raw[:8].hex()}")

    pool_bump, index = struct.unpack_from("<BH", raw, 8)
    creator = b58encode(raw[11:43])
    base_mint = b58encode(raw[43:75])
    quote_mint = b58encode(raw[75:107])
    lp_mint = b58encode(raw[107:139])
    pool_base_ta = b58encode(raw[139:171])
    pool_quote_ta = b58encode(raw[171:203])
    lp_supply = struct.unpack_from("<Q", raw, 203)[0]
    coin_creator = b58encode(raw[211:243])
    is_mayhem_mode = bool(raw[243])
    is_cashback_coin = bool(raw[244])

    # Critical Oct 2026 layout: virtual_quote_reserves is signed i128 (little-endian)
    vqr_i128 = int.from_bytes(raw[245:261], "little", signed=True)
    vqr_buggy_u128 = int.from_bytes(raw[245:261], "little", signed=False)

    creator_fee_bps = struct.unpack_from("<Q", raw, 261)[0]
    can_edit_creator_fee = bool(raw[269])
    is_holder_reward = bool(raw[270])
    protocol_fees, creator_fees = struct.unpack_from("<QQ", raw, 271)

    return {
        "pool_pubkey": pool_pubkey,
        "pool_bump": pool_bump,
        "index": index,
        "creator": creator,
        "base_mint": base_mint,
        "quote_mint": quote_mint,
        "lp_mint": lp_mint,
        "pool_base_token_account": pool_base_ta,
        "pool_quote_token_account": pool_quote_ta,
        "lp_supply": lp_supply,
        "coin_creator": coin_creator,
        "is_mayhem_mode": is_mayhem_mode,
        "is_cashback_coin": is_cashback_coin,
        "virtual_quote_reserves_i128": vqr_i128,
        "buggy_unsigned_u128_value": vqr_buggy_u128 if vqr_i128 < 0 else None,
        "creator_fee_bps": creator_fee_bps,
        "can_edit_creator_fee": can_edit_creator_fee,
        "is_holder_reward": is_holder_reward,
        "protocol_fees_raw": protocol_fees,
        "creator_fees_raw": creator_fees,
    }


def decode_pump_bonding_curve(raw: bytes, curve_pubkey: str = "") -> dict[str, Any]:
    """Decode Pump.fun BondingCurve account (legacy >=81B and Oct 2026 >=166B)."""
    if len(raw) < 81:
        raise ValueError(f"BondingCurve data too short: {len(raw)} bytes < 81")
    v_tok, v_quote, r_tok, r_quote, supply = struct.unpack_from("<QQQQQ", raw, 8)
    complete = bool(raw[48])
    creator = b58encode(raw[49:81])
    out: dict[str, Any] = {
        "curve_pubkey": curve_pubkey,
        "virtual_token_reserves": v_tok,
        "virtual_quote_reserves": v_quote,
        "real_token_reserves": r_tok,
        "real_quote_reserves": r_quote,
        "token_total_supply": supply,
        "complete": complete,
        "creator": creator,
    }
    if len(raw) >= 166:
        out["is_mayhem_mode"] = bool(raw[81])
        out["is_cashback_coin"] = bool(raw[82])
        out["quote_mint"] = b58encode(raw[83:115])
        out["creator_fee_bps"] = struct.unpack_from("<Q", raw, 115)[0]
        out["can_edit_creator_fee"] = bool(raw[123])
        out["is_holder_reward"] = bool(raw[124])
        out["creator_fee_pending"] = struct.unpack_from("<Q", raw, 125)[0]
        out["protocol_fees_pending"] = struct.unpack_from("<Q", raw, 133)[0]
        out["depth"] = raw[141]
        out["initial_virtual_quote_reserves"] = struct.unpack_from("<Q", raw, 142)[0]
        out["post_complete_base_out"] = struct.unpack_from("<Q", raw, 150)[0]
        out["post_complete_quote_in"] = struct.unpack_from("<Q", raw, 158)[0]
    return out


def assess_pumpswap_pool(
    decoded: dict[str, Any],
    vault_base_raw: int,
    vault_quote_raw: int,
    quote_decimals: int = 9,
) -> dict[str, Any]:
    """Compute effective quote reserves, legacy divergence, and Rug-Shield score."""
    vqr = int(decoded["virtual_quote_reserves_i128"])
    effective_quote_raw = vault_quote_raw + vqr
    scale = 10**quote_decimals
    vault_quote_ui = vault_quote_raw / scale
    effective_quote_ui = effective_quote_raw / scale

    divergence_pct = 0.0
    if vault_quote_raw > 0:
        divergence_pct = round(((effective_quote_raw - vault_quote_raw) / vault_quote_raw) * 100.0, 2)

    flags: list[str] = []
    penalty = 0

    if vqr < 0:
        flags.append("NEGATIVE_VIRTUAL_QUOTE_RESERVES_UNSWEPT_FEES")
        penalty += 15
    elif vqr > 0:
        flags.append("SYNTHETIC_MIGRATION_VIRTUAL_BOOST_ACTIVE")

    if effective_quote_raw <= 0:
        flags.append("NON_POSITIVE_EFFECTIVE_QUOTE_RESERVES")
        penalty += 60
    elif decoded["quote_mint"] == WSOL_MINT and effective_quote_ui < 5.0:
        flags.append(f"THIN_QUOTE_LIQUIDITY_{effective_quote_ui:.2f}_SOL")
        penalty += 25

    if decoded["can_edit_creator_fee"]:
        flags.append("MUTABLE_CREATOR_FEE")
        penalty += 20
    if decoded["creator_fee_bps"] >= 100:
        flags.append(f"HIGH_CREATOR_FEE_{decoded['creator_fee_bps']}_BPS")
        penalty += 15
    if decoded["is_mayhem_mode"]:
        flags.append("MAYHEM_MODE_ENABLED")
        penalty += 15
    if decoded["is_cashback_coin"]:
        flags.append("DEPRECATED_CASHBACK_FLAG")
        penalty += 5
    if decoded["lp_supply"] == 0:
        flags.append("ZERO_LP_CIRCULATING_SUPPLY")
        penalty += 20

    shield_score = max(0, 100 - penalty)
    return {
        **decoded,
        "vault_base_raw": vault_base_raw,
        "vault_quote_raw": vault_quote_raw,
        "vault_quote_ui": round(vault_quote_ui, 6),
        "effective_quote_raw": effective_quote_raw,
        "effective_quote_ui": round(effective_quote_ui, 6),
        "legacy_vault_only_divergence_pct": divergence_pct,
        "shield_score": shield_score,
        "risk_flags": flags,
    }


def _discover_latest_pumpswap_pools(limit: int, rpc_url: str) -> list[str]:
    sigs = solana_rpc("getSignaturesForAddress", [PUMPSWAP_PROGRAM_ID, {"limit": max(limit * 6, 12)}], rpc_url)
    pools: list[str] = []
    seen: set[str] = set()
    for entry in sigs or []:
        if entry.get("err") is not None:
            continue
        sig = entry.get("signature")
        if not sig:
            continue
        tx = solana_rpc(
            "getTransaction",
            [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 1}],
            rpc_url,
        )
        if not tx:
            continue
        msg = (tx.get("transaction") or {}).get("message") or {}
        all_ixs = list(msg.get("instructions") or [])
        for inner in (tx.get("meta") or {}).get("innerInstructions") or []:
            all_ixs.extend(inner.get("instructions") or [])
        for ix in all_ixs:
            if ix.get("programId") != PUMPSWAP_PROGRAM_ID:
                continue
            accts = ix.get("accounts") or []
            if not accts:
                continue
            cand = str(accts[0])
            if cand in seen:
                continue
            seen.add(cand)
            acc = solana_rpc("getAccountInfo", [cand, {"encoding": "base64"}], rpc_url)
            val = (acc or {}).get("value")
            if not val or val.get("owner") != PUMPSWAP_PROGRAM_ID:
                continue
            raw = base64.b64decode(val["data"][0])
            if len(raw) >= 287 and raw[:8] == POOL_DISCRIMINATOR:
                pools.append(cand)
                if len(pools) >= limit:
                    return pools
    return pools


def run_pumpswap_check(
    pool_pubkeys: list[str],
    latest: int = 3,
    bonding_curve: str | None = None,
    wallet: str | None = None,
    rpc_url: str = SOLANA_MAINNET_RPC,
) -> dict[str, Any]:
    """Audit live PumpSwap pools, optional BondingCurve, and optional wallet ATA rent."""
    targets = list(pool_pubkeys)
    if not targets:
        targets = _discover_latest_pumpswap_pools(latest, rpc_url)

    pool_reports: list[dict[str, Any]] = []
    for pool_pk in targets:
        acc = solana_rpc("getAccountInfo", [pool_pk, {"encoding": "base64"}], rpc_url)
        val = (acc or {}).get("value")
        if not val:
            pool_reports.append({"pool_pubkey": pool_pk, "error": "account_not_found"})
            continue
        raw = base64.b64decode(val["data"][0])
        decoded = decode_pumpswap_pool(raw, pool_pk)
        b_bal = solana_rpc("getTokenAccountBalance", [decoded["pool_base_token_account"]], rpc_url)
        q_bal = solana_rpc("getTokenAccountBalance", [decoded["pool_quote_token_account"]], rpc_url)
        b_raw = int(((b_bal or {}).get("value") or {}).get("amount") or 0)
        q_val = (q_bal or {}).get("value") or {}
        q_raw = int(q_val.get("amount") or 0)
        q_dec = int(q_val.get("decimals") or 9)
        pool_reports.append(assess_pumpswap_pool(decoded, b_raw, q_raw, quote_decimals=q_dec))

    curve_report: dict[str, Any] | None = None
    if bonding_curve:
        acc = solana_rpc("getAccountInfo", [bonding_curve, {"encoding": "base64"}], rpc_url)
        val = (acc or {}).get("value")
        if val:
            curve_report = decode_pump_bonding_curve(base64.b64decode(val["data"][0]), bonding_curve)
        else:
            curve_report = {"curve_pubkey": bonding_curve, "error": "account_not_found"}

    wallet_rent: dict[str, Any] | None = None
    if wallet:
        bal = solana_rpc("getBalance", [wallet], rpc_url)
        lamports = int((bal or {}).get("value") or 0)
        rent_ata = int(solana_rpc("getMinimumBalanceForRentExemption", [165], rpc_url) or 0)
        rent_t22 = int(solana_rpc("getMinimumBalanceForRentExemption", [170], rpc_url) or 0)
        wallet_rent = {
            "wallet": wallet,
            "lamports": lamports,
            "sol": round(lamports / 1e9, 9),
            "spl_ata_rent_lamports": rent_ata,
            "token2022_ata_rent_lamports": rent_t22,
            "can_init_token2022_ata": lamports >= (650_240 + rent_t22),
        }

    return {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pools_checked": len(pool_reports),
        "pools": pool_reports,
        "bonding_curve": curve_report,
        "wallet_rent_check": wallet_rent,
    }


def _fmt_bbo(bid: float | None, ask: float | None) -> str:
    b = f"{bid:.2f}" if bid is not None else "--"
    a = f"{ask:.2f}" if ask is not None else "--"
    return f"{b}/{a}"


def _print_kalshi_human(report: dict[str, Any]) -> None:
    print(f"=== Kalshi V2 Diagnostic ({report['timestamp_utc']}) ===")
    print(
        f"Scanned: {report['markets_scanned']} open markets | "
        f"Deep Books: {report['deep_orderbooks_checked']} | "
        f"Quote-Dust Mirages: {report['dust_traps_detected']}"
    )
    print("-" * 92)
    print(f"{'Ticker':34} {'FeeType':14} {'RawBBO':11} {'1LotBBO':11} {'Dust':6} {'TakerFee':8} Flags")
    for ob in report["orderbooks"]:
        raw_s = _fmt_bbo(ob["raw_yes_bid"], ob["raw_yes_ask"])
        lot_s = _fmt_bbo(ob["lot1_yes_bid"], ob["lot1_yes_ask"])
        print(
            f"{ob['ticker'][:34]:34} {ob['fee_type'][:14]:14} "
            f"{raw_s:11} {lot_s:11} {ob['dust_distortion_cents']:4.1f}c "
            f"${ob['taker_fee_at_ask_dollars']:6.4f} {','.join(ob['flags'])}"
        )
    if report["tightest_mecnet_events"]:
        print("-" * 86)
        print("Tightest Multi-Leg MECNET Events (All-YES Taker Cost vs $1.00):")
        for ev in report["tightest_mecnet_events"]:
            print(
                f"  {ev['event_ticker']} ({ev['legs']} legs): ask_sum=${ev['raw_ask_sum']:.4f} "
                f"+ V2_fees=${ev['v2_taker_fee_sum']:.4f} = ${ev['all_in_cost']:.4f} "
                f"(net_edge={ev['net_dutch_edge']:+.4f})"
            )
    if report["metar_synoptic_checks"]:
        print("-" * 86)
        print("Live AWC METAR + Synoptic (1sTTT/2sTTT) Checks:")
        for icao, m in report["metar_synoptic_checks"].items():
            print(
                f"  {icao}: status={m['status']} min={m.get('min_f')}F max={m.get('max_f')}F "
                f"synoptic_groups={m.get('synoptic_groups', 0)}"
            )


def _print_pumpswap_human(report: dict[str, Any]) -> None:
    print(f"=== PumpSwap v2 / Synthetic Migration Diagnostic ({report['timestamp_utc']}) ===")
    for p in report["pools"]:
        if "error" in p:
            print(f"Pool {p['pool_pubkey']}: ERROR {p['error']}")
            continue
        print(
            f"Pool {p['pool_pubkey']} | Base {p['base_mint'][:8]}.. | Shield={p['shield_score']}/100\n"
            f"  VaultQuote={p['vault_quote_ui']:.6f} | SignedVQR(i128)={p['virtual_quote_reserves_i128']} "
            f"| EffectiveQuote={p['effective_quote_ui']:.6f} (Delta={p['legacy_vault_only_divergence_pct']:+.2f}%)\n"
            f"  CreatorFee={p['creator_fee_bps']}bps mutable={p['can_edit_creator_fee']} "
            f"holder_reward={p['is_holder_reward']} mayhem={p['is_mayhem_mode']} "
            f"Flags={p['risk_flags'] or ['CLEAN']}"
        )
    if report["wallet_rent_check"]:
        w = report["wallet_rent_check"]
        print(
            f"Wallet Rent Check {w['wallet']}: {w['sol']:.6f} SOL | "
            f"Token-2022 ATA rent={w['token2022_ata_rent_lamports']} lamports | "
            f"can_init_t22={w['can_init_token2022_ata']}"
        )


# ---------------------------------------------------------------------------
# x402 Payment Security & Token-2022 Extension / ATA Audit (Zero External Deps)
# ---------------------------------------------------------------------------

_ED_P = (1 << 255) - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_PDA_MARKER = b"ProgramDerivedAddress"


def _is_on_ed25519_curve(candidate: bytes) -> bool:
    """Return True if 32-byte compressed point lies on Ed25519 (PDAs must be off-curve)."""
    if len(candidate) != 32:
        return False
    y = int.from_bytes(candidate, "little") & ((1 << 255) - 1)
    if y >= _ED_P:
        return False
    sign = candidate[31] >> 7
    x2 = ((y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return sign == 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    return (x * x - x2) % _ED_P == 0


def derive_solana_pda(seeds: list[bytes], program_id: str) -> str:
    """Derive canonical Solana Program Derived Address (off-curve SHA-256 search)."""
    prog_bytes = b58decode(program_id, 32)
    base_prefix = b"".join(seeds)
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(base_prefix + bytes([bump]) + prog_bytes + _PDA_MARKER).digest()
        if not _is_on_ed25519_curve(digest):
            return b58encode(digest)
    raise ValueError("Unable to derive off-curve Solana PDA")


def derive_associated_token_address(
    owner: str,
    mint: str,
    token_program_id: str = SPL_TOKEN_PROGRAM_ID,
) -> str:
    """Derive SPL / Token-2022 Associated Token Account (ATA) PDA without external SDKs."""
    return derive_solana_pda(
        [b58decode(owner, 32), b58decode(token_program_id, 32), b58decode(mint, 32)],
        ATOKEN_PROGRAM_ID,
    )


def _read_optional_pubkey(raw: bytes, offset: int) -> str | None:
    chunk = raw[offset : offset + 32]
    return None if len(chunk) < 32 or chunk == b"\x00" * 32 else b58encode(chunk)


def decode_token_mint(
    raw: bytes,
    owner_program: str | None = None,
    mint_pubkey: str = "",
) -> dict[str, Any]:
    """Decode SPL / Token-2022 Mint header (82B) plus offset-166 TLV extensions."""
    if len(raw) < 82:
        raise ValueError(f"Expected >=82 bytes for Solana Mint, got {len(raw)}")
    mint_auth_opt = struct.unpack_from("<I", raw, 0)[0]
    mint_authority = b58encode(raw[4:36]) if mint_auth_opt == 1 else None
    supply = struct.unpack_from("<Q", raw, 36)[0]
    decimals = raw[44]
    is_initialized = raw[45] == 1
    freeze_auth_opt = struct.unpack_from("<I", raw, 46)[0]
    freeze_authority = b58encode(raw[50:82]) if freeze_auth_opt == 1 else None

    is_token_2022 = owner_program == TOKEN_2022_PROGRAM_ID or len(raw) > 82
    inferred_program = TOKEN_2022_PROGRAM_ID if is_token_2022 else SPL_TOKEN_PROGRAM_ID
    extensions: list[dict[str, Any]] = []
    permanent_delegate: str | None = None
    transfer_hook_program_id: str | None = None
    transfer_fee_bps = 0
    max_transfer_fee = 0
    default_frozen = False
    non_transferable = False
    pausable_authority: str | None = None
    mint_close_authority: str | None = None

    if len(raw) >= 170 and raw[165] == 1:
        cursor = 166
        while cursor + 4 <= len(raw):
            ext_type, ext_len = struct.unpack_from("<HH", raw, cursor)
            cursor += 4
            if ext_type == 0 and ext_len == 0:
                break
            if cursor + ext_len > len(raw):
                break
            ext_slice = raw[cursor : cursor + ext_len]
            entry: dict[str, Any] = {
                "type": ext_type,
                "name": TOKEN_2022_EXTENSION_NAMES.get(ext_type, f"UnknownExtension({ext_type})"),
                "length": ext_len,
            }
            if ext_type == 1 and ext_len >= 108:
                older_bps = struct.unpack_from("<H", ext_slice, 72 + 16)[0]
                max_transfer_fee = struct.unpack_from("<Q", ext_slice, 90 + 8)[0]
                newer_bps = struct.unpack_from("<H", ext_slice, 90 + 16)[0]
                transfer_fee_bps = max(older_bps, newer_bps)
                entry.update({"transfer_fee_bps": transfer_fee_bps, "maximum_fee": max_transfer_fee})
            elif ext_type == 3 and ext_len >= 32:
                mint_close_authority = _read_optional_pubkey(ext_slice, 0)
                entry["close_authority"] = mint_close_authority
            elif ext_type == 6 and ext_len >= 1:
                default_frozen = ext_slice[0] == 2
                entry["default_account_state"] = ext_slice[0]
            elif ext_type == 9:
                non_transferable = True
            elif ext_type == 12 and ext_len >= 32:
                if ext_len >= 36:
                    opt = struct.unpack_from("<I", ext_slice, 0)[0]
                    permanent_delegate = _read_optional_pubkey(ext_slice, 4) if opt == 1 else None
                else:
                    permanent_delegate = _read_optional_pubkey(ext_slice, 0)
                entry["permanent_delegate"] = permanent_delegate
            elif ext_type == 14 and ext_len >= 64:
                transfer_hook_program_id = _read_optional_pubkey(ext_slice, 32)
                entry["program_id"] = transfer_hook_program_id
            elif ext_type == 26 and ext_len >= 32:
                pausable_authority = _read_optional_pubkey(ext_slice, 0)
                entry["pausable_authority"] = pausable_authority

            extensions.append(entry)
            cursor += ext_len

    flags: list[str] = []
    if permanent_delegate:
        flags.append("TOKEN_2022_PERMANENT_DELEGATE")
    if transfer_hook_program_id:
        flags.append("TOKEN_2022_TRANSFER_HOOK")
    if transfer_fee_bps > 0:
        flags.append(f"TOKEN_2022_TRANSFER_FEE_{transfer_fee_bps}_BPS")
    if default_frozen:
        flags.append("TOKEN_2022_DEFAULT_FROZEN")
    if non_transferable:
        flags.append("TOKEN_2022_NON_TRANSFERABLE")
    if pausable_authority:
        flags.append("TOKEN_2022_PAUSABLE")
    if mint_close_authority:
        flags.append("TOKEN_2022_MINT_CLOSE_AUTHORITY")

    return {
        "mint_pubkey": mint_pubkey,
        "owner_program": owner_program or inferred_program,
        "inferred_program": inferred_program,
        "account_bytes": len(raw),
        "decimals": decimals,
        "supply_raw": supply,
        "is_initialized": is_initialized,
        "mint_authority": mint_authority,
        "freeze_authority": freeze_authority,
        "extensions": extensions,
        "permanent_delegate": permanent_delegate,
        "transfer_hook_program_id": transfer_hook_program_id,
        "transfer_fee_bps": transfer_fee_bps,
        "max_transfer_fee": max_transfer_fee,
        "default_frozen": default_frozen,
        "non_transferable": non_transferable,
        "pausable_authority": pausable_authority,
        "mint_close_authority": mint_close_authority,
        "risk_flags": flags,
    }


def canonicalize_x402_authorization(auth: dict[str, Any]) -> tuple[str, str]:
    """Compute canonical UTF-8 JSON representation and SHA-256 hex digest of authorization."""
    canonical_msg = json.dumps(auth, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = "0x" + hashlib.sha256(canonical_msg.encode("utf-8")).hexdigest()
    return canonical_msg, digest


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in mapping and mapping[k] is not None:
            return mapping[k]
    return None


def _coerce_int(val: Any) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.strip().lstrip("-").isdigit():
        return int(val.strip())
    return None


_FAIL_OPEN_CONFIG_RULES: tuple[tuple[str, str, tuple[str, ...], bool, str], ...] = (
    (
        "X402_FAIL_OPEN_VERIFY_DEFAULT",
        "CRITICAL",
        ("failOpen", "fail_open", "allowUnverifiedFallback", "allow_unverified_fallback"),
        True,
        "Facilitator fails open instead of rejecting unverified payment proofs",
    ),
    (
        "X402_FAIL_OPEN_VERIFY_DEFAULT",
        "CRITICAL",
        ("strictOnchainVerify", "strict_onchain_verify", "strictMode", "strict_mode"),
        False,
        "Strict on-chain payment verification is disabled by default",
    ),
    (
        "X402_SIGNATURE_RECOVERY_SKIPPED",
        "CRITICAL",
        ("skipSignatureRecovery", "skip_signature_recovery", "skipSigVerify", "skip_sig_verify"),
        True,
        "EIP-3009 / Ed25519 signature recovery is bypassed",
    ),
    (
        "X402_SIGNATURE_RECOVERY_SKIPPED",
        "CRITICAL",
        ("requireSignatureRecovery", "require_signature_recovery", "verifySignature", "verify_signature"),
        False,
        "Signature recovery enforcement is disabled in facilitator config",
    ),
    (
        "X402_UNTRUSTED_CALLER_MESSAGE_ACCEPTED",
        "CRITICAL",
        ("trustCallerMessage", "trust_caller_message"),
        True,
        "Verifier passes caller-supplied message string directly instead of rebuilding from authorization",
    ),
    (
        "X402_UNTRUSTED_CALLER_MESSAGE_ACCEPTED",
        "CRITICAL",
        ("recomputeCanonicalMessage", "recompute_canonical_message"),
        False,
        "Facilitator does not recompute canonical message from structured authorization",
    ),
    (
        "X402_UNAWAITED_BACKGROUND_SETTLEMENT",
        "HIGH",
        ("backgroundUnawaitedSettle", "background_unawaited_settle", "unawaitedSettle", "unawaited_settle"),
        True,
        "Settlement runs unawaited in background after granting paid response",
    ),
    (
        "X402_UNAWAITED_BACKGROUND_SETTLEMENT",
        "HIGH",
        ("awaitSettlement", "await_settlement"),
        False,
        "Facilitator does not await settlement finality before returning access",
    ),
    (
        "X402_FAIL_OPEN_FAILED_TX_RECEIPT",
        "CRITICAL",
        ("allowFailedTx", "allow_failed_tx", "acceptUnverifiedTx", "accept_unverified_tx"),
        True,
        "Receipt validator accepts failed or unverified on-chain transactions",
    ),
    (
        "X402_FAIL_OPEN_FAILED_TX_RECEIPT",
        "CRITICAL",
        ("requireTxSuccess", "require_tx_success"),
        False,
        "On-chain transaction success (`meta.err is None` / `status == 1`) is not enforced",
    ),
)


def _extract_x402_inner_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Unwrap nested x402 envelope shapes (`decoded.payload`, `paymentPayload.payload`, `payload`)."""
    cur = payload
    for key in ("paymentPayload", "decoded", "payload"):
        sub = cur.get(key)
        if isinstance(sub, dict) and (
            "authorization" in sub or "message" in sub or "nonce" in sub or "validBefore" in sub
            or "payload" in sub
        ):
            cur = sub
            if key == "decoded" and isinstance(cur.get("payload"), dict):
                cur = cur["payload"]
    return cur


def _add_finding(
    findings: list[dict[str, str]],
    seen_codes: set[str],
    code: str,
    severity: str,
    category: str,
    detail: str,
) -> None:
    if code in seen_codes:
        return
    seen_codes.add(code)
    findings.append({"code": code, "severity": severity, "category": category, "detail": detail})


def _audit_x402_canonical_auth(
    auth: dict[str, Any],
    inner: dict[str, Any],
    has_payload: bool,
    findings: list[dict[str, str]],
    seen_codes: set[str],
) -> tuple[str, str]:
    """Verify caller-supplied message/digest parity against canonical authorization."""
    canonical_msg, canonical_digest = canonicalize_x402_authorization(auth)
    caller_msg = _first_present(inner, ("message", "signedMessage", "canonicalMessage"))
    if caller_msg is not None:
        caller_norm = (
            json.dumps(caller_msg, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            if isinstance(caller_msg, dict)
            else str(caller_msg)
        )
        if caller_norm != canonical_msg and caller_norm.lower() != canonical_digest.lower():
            _add_finding(
                findings,
                seen_codes,
                "X402_CALLER_MESSAGE_AUTH_MISMATCH",
                "CRITICAL",
                "canonical_auth",
                "Caller-supplied signed message differs from canonical serialization/digest of authorization",
            )
    caller_digest = _first_present(inner, ("authorizationDigest", "digest"))
    if caller_digest is not None and str(caller_digest).lower() != canonical_digest.lower():
        _add_finding(
            findings,
            seen_codes,
            "X402_AUTH_DIGEST_MISMATCH",
            "CRITICAL",
            "canonical_auth",
            f"Authorization digest mismatch: got {caller_digest}, expected {canonical_digest}",
        )
    sig = _first_present(inner, ("signature", "sig"))
    sig_valid = _first_present(inner, ("signatureValid", "signature_valid", "verifiedSignature"))
    if has_payload and (sig is None or str(sig).strip() == "" or sig_valid is False):
        _add_finding(
            findings,
            seen_codes,
            "X402_MISSING_OR_UNVERIFIED_SIGNATURE",
            "CRITICAL",
            "canonical_auth",
            "Payment payload lacks a non-empty signature or carries signatureValid=False",
        )
    return canonical_msg, canonical_digest


def _audit_x402_replay_and_bounds(
    auth: dict[str, Any],
    cfg: dict[str, Any],
    reqs: dict[str, Any],
    seen_nonce_set: set[str],
    ts: int,
    expected_recipient: str | None,
    expected_asset: str | None,
    min_amount: int | None,
    findings: list[dict[str, str]],
    seen_codes: set[str],
) -> None:
    """Verify validBefore/validUntil window, anti-replay nonce, recipient, asset, and amount."""
    valid_before = _coerce_int(
        _first_present(auth, ("validBefore", "valid_before", "validUntil", "valid_until", "expiresAt", "expiry"))
    )
    valid_after = _coerce_int(_first_present(auth, ("validAfter", "valid_after", "notBefore")))
    if valid_before is None or valid_before <= 0:
        _add_finding(
            findings, seen_codes, "X402_MISSING_EXPIRATION_BOUND", "CRITICAL", "replay_window",
            "Authorization missing positive integer validBefore / validUntil expiration timestamp",
        )
    else:
        if valid_after is not None and valid_before <= valid_after:
            _add_finding(
                findings, seen_codes, "X402_INVALID_VALIDITY_WINDOW", "CRITICAL", "replay_window",
                f"validBefore ({valid_before}) <= validAfter ({valid_after})",
            )
        if valid_before <= ts:
            _add_finding(
                findings, seen_codes, "X402_EXPIRED_AUTHORIZATION", "CRITICAL", "replay_window",
                f"Authorization expired at {valid_before} (now={ts})",
            )
    if valid_after is not None and valid_after > ts:
        _add_finding(
            findings, seen_codes, "X402_AUTHORIZATION_NOT_YET_VALID", "HIGH", "replay_window",
            f"Authorization not valid until {valid_after} (now={ts})",
        )

    nonce_val = _first_present(auth, ("nonce", "idempotencyKey", "idempotency_key"))
    if nonce_val is None or str(nonce_val).strip() == "":
        _add_finding(findings, seen_codes, "X402_MISSING_REPLAY_NONCE", "CRITICAL", "replay_window", "Authorization missing anti-replay nonce")
    elif str(nonce_val).strip() in seen_nonce_set:
        _add_finding(
            findings, seen_codes, "X402_NONCE_REPLAY_DETECTED", "CRITICAL", "replay_window",
            f"Replay attack detected: nonce {nonce_val!r} already consumed",
        )

    exp_rcpt = expected_recipient or _first_present(reqs, ("payTo", "recipient")) or _first_present(cfg, ("expectedRecipient", "payTo", "recipient"))
    got_rcpt = _first_present(auth, ("payTo", "to", "recipient"))
    if exp_rcpt and str(got_rcpt or "") != str(exp_rcpt):
        _add_finding(findings, seen_codes, "X402_RECIPIENT_MISMATCH", "CRITICAL", "replay_window", f"Recipient mismatch: got {got_rcpt!r}, expected {exp_rcpt!r}")

    exp_asset = expected_asset or _first_present(reqs, ("asset", "mint")) or _first_present(cfg, ("expectedAsset", "asset", "mint"))
    got_asset = _first_present(auth, ("asset", "mint", "token"))
    if exp_asset and str(got_asset or "") != str(exp_asset):
        _add_finding(findings, seen_codes, "X402_ASSET_MISMATCH", "CRITICAL", "replay_window", f"Asset/mint mismatch: got {got_asset!r}, expected {exp_asset!r}")

    req_amt = (
        min_amount
        if min_amount is not None
        else _coerce_int(_first_present(reqs, ("maxAmountRequired", "amount"))) or _coerce_int(_first_present(cfg, ("minAmount", "maxAmountRequired")))
    )
    got_amt = _coerce_int(_first_present(auth, ("value", "amount")))
    if req_amt is not None and (got_amt is None or got_amt < req_amt):
        _add_finding(findings, seen_codes, "X402_INSUFFICIENT_PAYMENT_AMOUNT", "CRITICAL", "replay_window", f"Payment amount {got_amt} below required minimum {req_amt}")


def _audit_x402_fail_open_config(
    raw_payload: dict[str, Any],
    inner: dict[str, Any],
    cfg: dict[str, Any],
    findings: list[dict[str, str]],
    seen_codes: set[str],
) -> None:
    """Detect fail-open verifyPayment/settlePayment defaults and failed tx acceptance."""
    for flag_code, severity, keys, bad_state, detail in _FAIL_OPEN_CONFIG_RULES:
        val = _first_present(cfg, keys)
        if val is not None and bool(val) is bad_state:
            _add_finding(findings, seen_codes, flag_code, severity, "fail_open_config", detail)

    tx_err = _first_present(raw_payload, ("txError", "err")) or _first_present(inner, ("txError", "err"))
    tx_status = _first_present(raw_payload, ("txStatus", "receiptStatus", "status")) or _first_present(inner, ("txStatus", "receiptStatus", "status"))
    tx_ok = _first_present(raw_payload, ("txSuccess", "onchainVerified"))
    if tx_ok is None:
        tx_ok = _first_present(inner, ("txSuccess", "onchainVerified"))
    if tx_err is not None or tx_ok is False or (isinstance(tx_status, str) and tx_status.lower() in ("failed", "reverted", "error")):
        _add_finding(
            findings, seen_codes, "X402_FAILED_TX_ACCEPTED", "CRITICAL", "fail_open_config",
            "Transaction receipt indicates failure or failed on-chain verification",
        )


def _audit_x402_token_2022(
    auth: dict[str, Any] | None,
    inner: dict[str, Any],
    cfg: dict[str, Any],
    *,
    expected_recipient: str | None,
    expected_asset: str | None,
    mint_account_raw: bytes | None,
    mint_owner_program: str | None,
    owner_pubkey: str | None,
    destination_ata: str | None,
    configured_token_program: str | None,
    findings: list[dict[str, str]],
    seen_codes: set[str],
) -> tuple[dict[str, str], dict[str, Any] | None]:
    """Audit Token-2022 vs legacy SPL ATA PDA mismatch and offset-166 Mint TLV risk flags."""
    eff_mint = (
        expected_asset
        or (_first_present(auth, ("asset", "mint", "token")) if auth else None)
        or _first_present(cfg, ("expectedAsset", "asset", "mint"))
    )
    decoded_mint: dict[str, Any] | None = None
    if mint_account_raw is not None:
        decoded_mint = decode_token_mint(mint_account_raw, owner_program=mint_owner_program, mint_pubkey=str(eff_mint or ""))
        for tlv_flag in decoded_mint["risk_flags"]:
            sev = "CRITICAL" if any(k in tlv_flag for k in ("PERMANENT_DELEGATE", "TRANSFER_HOOK", "NON_TRANSFERABLE", "DEFAULT_FROZEN")) else "HIGH"
            _add_finding(findings, seen_codes, tlv_flag, sev, "token_2022_tlv", f"Mint offset-166 TLV hazard detected: {tlv_flag}")

    eff_mint_owner = (
        mint_owner_program
        or (decoded_mint["owner_program"] if decoded_mint else None)
        or _first_present(cfg, ("mintProgram", "mint_program", "mintOwnerProgram", "mint_owner_program"))
    )
    eff_tok_prog = (
        configured_token_program
        or _first_present(cfg, ("tokenProgram", "token_program", "programId", "program_id"))
        or (_first_present(inner, ("tokenProgram", "token_program")) if inner else None)
    )
    if eff_mint_owner == TOKEN_2022_PROGRAM_ID and eff_tok_prog == SPL_TOKEN_PROGRAM_ID:
        _add_finding(
            findings, seen_codes, "TOKEN_2022_PROGRAM_ID_HARDCODED_LEGACY_SPL", "CRITICAL", "token_2022_ata",
            "Config/tx specifies legacy SPL Tokenkeg... for a Token-2022 (TokenzQd...) mint -> IncorrectProgramId / wrong ATA",
        )

    eff_owner = (
        owner_pubkey
        or expected_recipient
        or (_first_present(auth, ("payTo", "to", "recipient")) if auth else None)
        or _first_present(cfg, ("expectedRecipient", "payTo", "recipient"))
    )
    eff_ata = destination_ata or _first_present(inner, ("destinationAta", "destination_ata", "ata"))
    derived_atas: dict[str, str] = {}
    if eff_owner and eff_mint:
        try:
            legacy_ata = derive_associated_token_address(eff_owner, str(eff_mint), SPL_TOKEN_PROGRAM_ID)
            t22_ata = derive_associated_token_address(eff_owner, str(eff_mint), TOKEN_2022_PROGRAM_ID)
            derived_atas = {"legacy_spl_ata": legacy_ata, "token_2022_ata": t22_ata}
            if eff_ata:
                expected_prog = eff_mint_owner or eff_tok_prog or SPL_TOKEN_PROGRAM_ID
                expected_ata = t22_ata if expected_prog == TOKEN_2022_PROGRAM_ID else legacy_ata
                if str(eff_ata) != expected_ata:
                    _add_finding(
                        findings, seen_codes, "TOKEN_2022_ATA_PDA_MISMATCH", "CRITICAL", "token_2022_ata",
                        f"Supplied ATA {eff_ata} mismatches expected PDA {expected_ata} (program={expected_prog})",
                    )
        except ValueError:
            pass

    for ext_flag, code, detail in (
        ("permanentDelegate", "TOKEN_2022_PERMANENT_DELEGATE", "Mint enables PermanentDelegate seizure authority"),
        ("transferHook", "TOKEN_2022_TRANSFER_HOOK", "Mint invokes arbitrary TransferHook CPI on transfer"),
    ):
        if _first_present(cfg, (ext_flag,)):
            _add_finding(findings, seen_codes, code, "CRITICAL", "token_2022_tlv", detail)
    return derived_atas, decoded_mint


def audit_x402_payload_and_config(
    payload: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    *,
    seen_nonces: set[str] | list[str] | None = None,
    now_ts: int | None = None,
    expected_recipient: str | None = None,
    expected_asset: str | None = None,
    min_amount: int | None = None,
    mint_account_raw: bytes | None = None,
    mint_owner_program: str | None = None,
    owner_pubkey: str | None = None,
    destination_ata: str | None = None,
    configured_token_program: str | None = None,
) -> dict[str, Any]:
    """Deterministically audit x402 payment payload, facilitator config, ATA PDA, and Token-2022 TLVs."""
    ts = int(time.time()) if now_ts is None else int(now_ts)
    seen_nonce_set = {str(n).strip() for n in (seen_nonces or ()) if str(n).strip()}
    raw_payload = payload or {}
    cfg = config or {}
    reqs = raw_payload.get("paymentRequirements") if isinstance(raw_payload.get("paymentRequirements"), dict) else {}
    inner = _extract_x402_inner_payload(raw_payload)
    auth = inner.get("authorization") if isinstance(inner.get("authorization"), dict) else None
    if auth is None and any(
        k in inner for k in ("payTo", "to", "recipient", "validBefore", "validUntil", "nonce", "value", "amount")
    ):
        auth = inner

    findings: list[dict[str, str]] = []
    seen_codes: set[str] = set()
    canonical_msg: str | None = None
    canonical_digest: str | None = None

    if auth is not None:
        canonical_msg, canonical_digest = _audit_x402_canonical_auth(
            auth, inner, bool(raw_payload), findings, seen_codes
        )
        _audit_x402_replay_and_bounds(
            auth, cfg, reqs, seen_nonce_set, ts,
            expected_recipient, expected_asset, min_amount, findings, seen_codes,
        )

    _audit_x402_fail_open_config(raw_payload, inner, cfg, findings, seen_codes)
    derived_atas, decoded_mint = _audit_x402_token_2022(
        auth, inner, cfg,
        expected_recipient=expected_recipient,
        expected_asset=expected_asset,
        mint_account_raw=mint_account_raw,
        mint_owner_program=mint_owner_program,
        owner_pubkey=owner_pubkey,
        destination_ata=destination_ata,
        configured_token_program=configured_token_program,
        findings=findings,
        seen_codes=seen_codes,
    )

    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    verdict = "BLOCK_CRITICAL" if crit_count > 0 else ("WARN" if high_count > 0 else "PASS")

    return {
        "verdict": verdict,
        "passed": crit_count == 0,
        "risk_score": min(100, (crit_count * 40) + (high_count * 15)),
        "critical_count": crit_count,
        "high_count": high_count,
        "risk_flags": [f["code"] for f in findings],
        "findings": findings,
        "canonical_message": canonical_msg,
        "canonical_digest": canonical_digest,
        "derived_atas": derived_atas,
        "decoded_mint": decoded_mint,
    }


def _build_builtin_x402_vectors(now_ts: int) -> list[dict[str, Any]]:
    """Build deterministic self-audit vectors mirroring live 2026 x402 / Token-2022 failure classes."""
    base_auth = {
        "from": "0x1111111111111111111111111111111111111111",
        "payTo": "4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj",
        "asset": USDC_MINT,
        "value": "349000000",
        "validAfter": now_ts - 60,
        "validBefore": now_ts + 900,
        "nonce": "nonce_clean_001",
    }
    clean_msg, _ = canonicalize_x402_authorization(base_auth)
    spoof_msg, _ = canonicalize_x402_authorization({**base_auth, "payTo": "AttackerWallet111111111111111111111111111111"})
    legacy_ata = derive_associated_token_address(base_auth["payTo"], USDC_MINT, SPL_TOKEN_PROGRAM_ID)

    # Synthetic 166+ byte Token-2022 Mint carrying PermanentDelegate (tag 12) + TransferFeeConfig (tag 1)
    pd_tlv = struct.pack("<HH", 12, 32) + b58decode(base_auth["payTo"], 32)
    t22_mint = bytearray(166)
    t22_mint[44] = 6
    t22_mint[45] = 1
    t22_mint[165] = 1
    t22_mint.extend(pd_tlv)

    return [
        {
            "case": "clean_canonical_usdc_payment",
            "report": audit_x402_payload_and_config(
                payload={"authorization": base_auth, "message": clean_msg, "signature": "0xsig_valid"},
                config={"strictOnchainVerify": True, "requireSignatureRecovery": True, "awaitSettlement": True},
                now_ts=now_ts,
                expected_recipient=base_auth["payTo"],
                expected_asset=USDC_MINT,
                min_amount=349_000_000,
            ),
        },
        {
            "case": "caller_message_vs_canonical_auth_spoof",
            "report": audit_x402_payload_and_config(
                payload={"authorization": base_auth, "message": spoof_msg, "signature": "0xsig_spoofed"},
                config={"trustCallerMessage": True},
                now_ts=now_ts,
            ),
        },
        {
            "case": "expired_auth_and_nonce_replay",
            "report": audit_x402_payload_and_config(
                payload={
                    "authorization": {**base_auth, "validBefore": now_ts - 10, "nonce": "nonce_reused_99"},
                    "signature": "0xsig",
                },
                seen_nonces={"nonce_reused_99"},
                now_ts=now_ts,
            ),
        },
        {
            "case": "fail_open_verify_payment_defaults",
            "report": audit_x402_payload_and_config(
                payload={"authorization": base_auth, "signature": "0xsig", "txStatus": "failed"},
                config={
                    "strictOnchainVerify": False,
                    "skipSignatureRecovery": True,
                    "awaitSettlement": False,
                    "allowFailedTx": True,
                },
                now_ts=now_ts,
            ),
        },
        {
            "case": "token2022_legacy_ata_and_offset166_tlv_trap",
            "report": audit_x402_payload_and_config(
                payload={"authorization": base_auth, "signature": "0xsig"},
                config={"tokenProgram": SPL_TOKEN_PROGRAM_ID, "mintOwnerProgram": TOKEN_2022_PROGRAM_ID},
                mint_account_raw=bytes(t22_mint),
                mint_owner_program=TOKEN_2022_PROGRAM_ID,
                owner_pubkey=base_auth["payTo"],
                destination_ata=legacy_ata,
                configured_token_program=SPL_TOKEN_PROGRAM_ID,
                now_ts=now_ts,
            ),
        },
    ]


def run_x402_audit(
    *,
    payload: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    mint_pubkey: str | None = None,
    mint_b64: str | None = None,
    owner_pubkey: str | None = None,
    destination_ata: str | None = None,
    configured_token_program: str | None = None,
    seen_nonces: list[str] | None = None,
    now_ts: int | None = None,
    expected_recipient: str | None = None,
    expected_asset: str | None = None,
    min_amount: int | None = None,
    rpc_url: str = SOLANA_MAINNET_RPC,
) -> dict[str, Any]:
    """Run targeted x402 payload/config/mint audit or built-in 5-vector self-audit suite."""
    ts = int(time.time()) if now_ts is None else int(now_ts)
    mint_raw: bytes | None = base64.b64decode(mint_b64) if mint_b64 else None
    mint_owner: str | None = None

    if mint_pubkey and mint_raw is None:
        acc = solana_rpc("getAccountInfo", [mint_pubkey, {"encoding": "base64"}], rpc_url)
        val = (acc or {}).get("value")
        if not val:
            raise ValueError(f"Mint account {mint_pubkey} not found on RPC {rpc_url}")
        mint_owner = val.get("owner")
        mint_raw = base64.b64decode(val["data"][0])

    custom_mode = any(
        x is not None
        for x in (payload, config, mint_raw, owner_pubkey, destination_ata, configured_token_program, expected_recipient, expected_asset, min_amount)
    ) or bool(seen_nonces)

    if custom_mode:
        audit = audit_x402_payload_and_config(
            payload=payload,
            config=config,
            seen_nonces=seen_nonces,
            now_ts=ts,
            expected_recipient=expected_recipient,
            expected_asset=expected_asset or mint_pubkey,
            min_amount=min_amount,
            mint_account_raw=mint_raw,
            mint_owner_program=mint_owner,
            owner_pubkey=owner_pubkey,
            destination_ata=destination_ata,
            configured_token_program=configured_token_program,
        )
        return {
            "mode": "targeted",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "audit": audit,
        }

    vectors = _build_builtin_x402_vectors(ts)
    return {
        "mode": "self_audit_vectors",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "vectors_tested": len(vectors),
        "critical_vectors_caught": sum(1 for v in vectors if v["report"]["verdict"] == "BLOCK_CRITICAL"),
        "results": vectors,
    }


def _print_x402_human(report: dict[str, Any]) -> None:
    print(f"=== x402 Security & Token-2022 Audit ({report['timestamp_utc']}) mode={report['mode']} ===")
    if report["mode"] == "targeted":
        a = report["audit"]
        print(f"Verdict={a['verdict']} RiskScore={a['risk_score']}/100 Flags={a['risk_flags'] or ['CLEAN']}")
        for f in a["findings"]:
            print(f"  [{f['severity']}] {f['code']} ({f['category']}): {f['detail']}")
        if a["derived_atas"]:
            print(f"  Derived ATAs: legacy={a['derived_atas']['legacy_spl_ata']} token2022={a['derived_atas']['token_2022_ata']}")
        return
    for item in report["results"]:
        a = item["report"]
        print(f"  [{item['case']}] Verdict={a['verdict']} Risk={a['risk_score']}/100 Flags={a['risk_flags'] or ['CLEAN']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Kalshi V2, PumpSwap v2 & x402 diagnostic CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_kalshi = sub.add_parser("kalshi-scan", aliases=["kalshi"], help="Scan live Kalshi V2 markets & METARs")
    p_kalshi.add_argument("--series", default="", help="Comma-separated Kalshi series tickers (e.g. KXHIGHNY,KXLOWTNYC)")
    p_kalshi.add_argument("--limit", type=int, default=200, help="Max open non-MVE markets to scan")
    p_kalshi.add_argument("--book-top", type=int, default=8, help="Number of deep /orderbook audits to run")
    p_kalshi.add_argument("--no-metar", action="store_true", help="Skip AWC METAR fetch")
    p_kalshi.add_argument("--json", action="store_true", help="Emit JSON output")

    p_pump = sub.add_parser("pumpswap-check", aliases=["pumpswap"], help="Audit PumpSwap Pool & signed i128 VQR")
    p_pump.add_argument("--pool", action="append", default=[], help="PumpSwap Pool pubkey (repeatable)")
    p_pump.add_argument("--latest", type=int, default=3, help="Auto-discover N latest PumpSwap pools if --pool omitted")
    p_pump.add_argument("--bonding-curve", default=None, help="Optional Pump.fun BondingCurve pubkey")
    p_pump.add_argument("--wallet", default=None, help="Optional wallet pubkey for SOL ATA rent check")
    p_pump.add_argument("--rpc-url", default=SOLANA_MAINNET_RPC, help="Solana RPC endpoint")
    p_pump.add_argument("--json", action="store_true", help="Emit JSON output")

    p_x402 = sub.add_parser("x402-audit", aliases=["x402"], help="Audit x402 payloads, facilitator configs & Token-2022 TLVs/ATAs")
    p_x402.add_argument("--payload-file", default=None, help="Path to JSON file containing x402 payment payload")
    p_x402.add_argument("--payload-json", default=None, help="Inline JSON string for x402 payment payload")
    p_x402.add_argument("--config-file", default=None, help="Path to JSON file containing facilitator verify config")
    p_x402.add_argument("--config-json", default=None, help="Inline JSON string for facilitator verify config")
    p_x402.add_argument("--mint", default=None, help="Optional Solana mint pubkey to fetch & decode offset-166 TLVs")
    p_x402.add_argument("--mint-b64", default=None, help="Optional base64 Mint account bytes for offline TLV decoding")
    p_x402.add_argument("--owner", default=None, help="Optional recipient/owner pubkey for ATA PDA cross-check")
    p_x402.add_argument("--ata", default=None, help="Optional destination ATA pubkey to verify against Mint owner program")
    p_x402.add_argument("--token-program", default=None, help="Configured token program ID (e.g. Tokenkeg... or TokenzQd...)")
    p_x402.add_argument("--seen-nonce", action="append", default=[], help="Previously consumed nonce to test replay block (repeatable)")
    p_x402.add_argument("--now-ts", type=int, default=None, help="Override Unix timestamp for deterministic expiry testing")
    p_x402.add_argument("--expected-recipient", default=None, help="Expected payTo / recipient address")
    p_x402.add_argument("--expected-asset", default=None, help="Expected asset / mint address")
    p_x402.add_argument("--min-amount", type=int, default=None, help="Minimum required atomic payment amount")
    p_x402.add_argument("--rpc-url", default=SOLANA_MAINNET_RPC, help="Solana RPC endpoint (used with --mint)")
    p_x402.add_argument("--strict-exit", action="store_true", help="Exit 2 when targeted audit verdict is BLOCK_CRITICAL")
    p_x402.add_argument("--json", action="store_true", help="Emit JSON output")

    return parser


def _load_json_arg(file_path: str | None, inline_json: str | None) -> dict[str, Any] | None:
    if file_path:
        with open(file_path, encoding="utf-8") as fh:
            return json.loads(fh.read())
    if inline_json:
        return json.loads(inline_json)
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd in ("kalshi-scan", "kalshi"):
        series = [s for s in args.series.split(",") if s.strip()]
        report = run_kalshi_scan(series, limit=args.limit, book_top=args.book_top, check_metar=not args.no_metar)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_kalshi_human(report)
        return 0

    if args.cmd in ("pumpswap-check", "pumpswap"):
        report = run_pumpswap_check(
            pool_pubkeys=args.pool,
            latest=args.latest,
            bonding_curve=args.bonding_curve,
            wallet=args.wallet,
            rpc_url=args.rpc_url,
        )
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_pumpswap_human(report)
        return 0

    if args.cmd in ("x402-audit", "x402"):
        report = run_x402_audit(
            payload=_load_json_arg(args.payload_file, args.payload_json),
            config=_load_json_arg(args.config_file, args.config_json),
            mint_pubkey=args.mint,
            mint_b64=args.mint_b64,
            owner_pubkey=args.owner,
            destination_ata=args.ata,
            configured_token_program=args.token_program,
            seen_nonces=args.seen_nonce,
            now_ts=args.now_ts,
            expected_recipient=args.expected_recipient,
            expected_asset=args.expected_asset,
            min_amount=args.min_amount,
            rpc_url=args.rpc_url,
        )
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_x402_human(report)
        if args.strict_exit and report.get("mode") == "targeted" and not report["audit"]["passed"]:
            return 2
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
