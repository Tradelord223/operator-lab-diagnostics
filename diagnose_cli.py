#!/usr/bin/env python3
"""Read-only Proof-of-Work diagnostic CLI for Kalshi V2 and PumpSwap v2.

Self-contained Python stdlib diagnostic exposing:
  1. `kalshi-scan` (`kalshi`): Live Kalshi V2 public orderbook quote-dust
     (<1.0 lot mirage) detection, 4dp quadratic taker vs $0.0000 post-only
     maker fee math, MECNET event Dutch-book cost check, and fail-closed
     NOAA/AWC METAR (`T-group` + `1sTTT`/`2sTTT` 6h synoptic) parser.
  2. `pumpswap-check` (`pumpswap`): Live Solana mainnet PumpSwap `Pool` and
     Pump.fun `BondingCurve` binary decoder with signed `i128`
     `virtual_quote_reserves` accounting, Synthetic Migration delta analysis,
     and non-custodial Rug-Shield scoring.

No secrets, private keys, or order-mutation endpoints are used.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Kalshi V2 & PumpSwap v2 diagnostic CLI")
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

    return parser


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

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
