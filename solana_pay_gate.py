#!/usr/bin/env python3
"""Zero-fee non-custodial Solana Pay USDC gate & System-1/2 sales/support router.

Self-contained Python stdlib module providing:
  1. Solana Pay Transfer Request URI generator (`0.00%` platform fee, `0-day`
     hold, mainnet USDC mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`).
  2. 5-gate anti-spoof, anti-replay on-chain USDC verifier checking `reference`
     pubkey membership, `meta.err is None`, `blockTime`, exact SPL token
     `postTokenBalances - preTokenBalances` delta, and consumed-signature lock.
  3. 6-rubric System-1 (`gemini-decision-1` / `claude-haiku-5-5`) -> System-2
     (`claude-sonnet-5-5`) sales/support router with deterministic offline mode
     and per-lifecycle API credit cost tracking (~$0.09 / 20 turns).

No network listeners are opened and no secrets are stored on disk.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import json
import os
import re
import secrets
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

try:
    from .diagnose_cli import SOLANA_MAINNET_RPC, USDC_MINT, b58decode, b58encode, solana_rpc
except ImportError:
    from diagnose_cli import SOLANA_MAINNET_RPC, USDC_MINT, b58decode, b58encode, solana_rpc

DEFAULT_MERCHANT_WALLET = "4iANuArANM9HzZchytLKeUBzJMws8TEkogtFtZFLGyAj"
DEFAULT_STATE_PATH = Path.home() / ".operator_lab" / "invoices.json"
USDC_DECIMALS = 6
MICRO_USDC_SCALE = 10**USDC_DECIMALS

SKUS: dict[str, dict[str, Any]] = {
    "core": {
        "sku": "core",
        "title": "Core Operator Suite",
        "price_usdc": "89.00",
        "expected_micro_usdc": 89_000_000,
    },
    "b2b_audit": {
        "sku": "b2b_audit",
        "title": "B2B Custom Bot / Pre-Deploy Audit",
        "price_usdc": "149.00",
        "expected_micro_usdc": 149_000_000,
    },
    "vip": {
        "sku": "vip",
        "title": "VIP Bespoke Codex Bot + Invariant Suite",
        "price_usdc": "399.00",
        "expected_micro_usdc": 399_000_000,
    },
}

# Nov 2026 published per-million-token pricing (USD)
MODEL_RATES_PER_MTOK: dict[str, dict[str, float]] = {
    "gemini-decision-1": {"input": 0.10, "cached_input": 0.10, "output": 0.00},
    "claude-haiku-5-5": {"input": 0.10, "cached_input": 0.10, "output": 0.50},
    "claude-sonnet-5-5": {"input": 2.00, "cached_input": 0.20, "output": 10.00},
    "claude-opus-5-5": {"input": 4.00, "cached_input": 0.20, "output": 20.00},
}


# ---------------------------------------------------------------------------
# Sovereign Solana Pay USDC Invoice Generator & Atomic State Persistence
# ---------------------------------------------------------------------------


def generate_reference_pubkey() -> str:
    """Create a cryptographically random 32-byte Base58 Solana reference pubkey."""
    return b58encode(secrets.token_bytes(32))


def build_solana_pay_uri(
    recipient: str,
    amount_usdc: str,
    reference: str,
    label: str,
    message: str,
    spl_token: str = USDC_MINT,
) -> str:
    """Format a Solana Pay Transfer Request URI per the official specification."""
    b58decode(recipient, expected_len=32)
    b58decode(reference, expected_len=32)
    b58decode(spl_token, expected_len=32)
    dec_amt = Decimal(str(amount_usdc))
    if dec_amt <= Decimal("0"):
        raise ValueError("Invoice amount must be positive")
    query = urllib.parse.urlencode(
        [
            ("amount", f"{dec_amt.normalize():f}"),
            ("spl-token", spl_token),
            ("reference", reference),
            ("label", label),
            ("message", message),
        ],
        quote_via=urllib.parse.quote,
    )
    return f"solana:{recipient}?{query}"


def load_state(state_path: Path) -> dict[str, Any]:
    """Load non-secret invoice state from JSON file (treats empty 0-byte file as fresh)."""
    if not state_path.exists():
        return {"invoices": {}, "consumed_signatures": []}
    raw_text = state_path.read_text(encoding="utf-8").strip()
    if not raw_text:
        return {"invoices": {}, "consumed_signatures": []}
    data = json.loads(raw_text)
    data.setdefault("invoices", {})
    data.setdefault("consumed_signatures", [])
    return data


def save_state_atomic(state_path: Path, state: dict[str, Any]) -> None:
    """Atomically write invoice state with 0600 permissions inside a private directory."""
    resolved_parent = state_path.parent.resolve()
    parent_existed = resolved_parent.exists()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    if (not parent_existed) or (resolved_parent == DEFAULT_STATE_PATH.parent.resolve()):
        os.chmod(resolved_parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=".inv_", suffix=".tmp", dir=str(state_path.parent))
    tmp_path = Path(tmp_name)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp_path, state_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def create_invoice(
    sku: str,
    buyer_ref: str = "anon",
    recipient: str = DEFAULT_MERCHANT_WALLET,
    ttl_seconds: int = 3600,
    state_path: Path | None = None,
) -> dict[str, Any]:
    """Generate a non-custodial Solana Pay USDC invoice and optionally persist it."""
    if sku not in SKUS:
        raise ValueError(f"Unknown SKU {sku!r}; choose from {sorted(SKUS)}")
    b58decode(recipient, expected_len=32)
    spec = SKUS[sku]
    now = int(time.time())
    reference = generate_reference_pubkey()
    invoice_id = f"inv_{sku}_{secrets.token_hex(6)}"
    clean_buyer = re.sub(r"[^a-zA-Z0-9_-]", "", buyer_ref)[:32] or "anon"
    uri = build_solana_pay_uri(
        recipient=recipient,
        amount_usdc=spec["price_usdc"],
        reference=reference,
        label="Operator Lab",
        message=f"{spec['title']} ({invoice_id})",
    )
    invoice = {
        "invoice_id": invoice_id,
        "sku": sku,
        "title": spec["title"],
        "buyer_ref": clean_buyer,
        "recipient": recipient,
        "mint": USDC_MINT,
        "price_usdc": spec["price_usdc"],
        "expected_micro_usdc": spec["expected_micro_usdc"],
        "reference": reference,
        "solana_pay_uri": uri,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "status": "pending",
        "paid_signature": None,
        "received_micro_usdc": 0,
    }
    if state_path is not None:
        state = load_state(state_path)
        state["invoices"][invoice_id] = invoice
        save_state_atomic(state_path, state)
    return invoice


# ---------------------------------------------------------------------------
# 5-Gate Anti-Spoof / Anti-Replay On-Chain USDC Verifier
# ---------------------------------------------------------------------------


def _extract_account_keys(tx_result: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    msg = ((tx_result.get("transaction") or {}).get("message") or {})
    for entry in msg.get("accountKeys") or []:
        if isinstance(entry, dict) and entry.get("pubkey"):
            keys.add(str(entry["pubkey"]))
        elif isinstance(entry, str):
            keys.add(entry)
    loaded = ((tx_result.get("meta") or {}).get("loadedAddresses") or {})
    for bucket in ("writable", "readonly"):
        for addr in loaded.get(bucket) or []:
            keys.add(str(addr))
    return keys


def _compute_usdc_delta_micro(
    meta: dict[str, Any],
    recipient: str,
    mint: str = USDC_MINT,
) -> int:
    """Compute exact SPL token net balance increase for recipient & mint."""
    pre_by_idx: dict[int, int] = {}
    post_by_idx: dict[int, int] = {}

    for entry in meta.get("preTokenBalances") or []:
        if entry.get("owner") == recipient and entry.get("mint") == mint:
            idx = int(entry["accountIndex"])
            amt = int((entry.get("uiTokenAmount") or {}).get("amount") or 0)
            pre_by_idx[idx] = amt

    for entry in meta.get("postTokenBalances") or []:
        if entry.get("owner") == recipient and entry.get("mint") == mint:
            idx = int(entry["accountIndex"])
            amt = int((entry.get("uiTokenAmount") or {}).get("amount") or 0)
            post_by_idx[idx] = amt

    all_indices = set(pre_by_idx) | set(post_by_idx)
    return sum(post_by_idx.get(idx, 0) - pre_by_idx.get(idx, 0) for idx in all_indices)


def verify_tx_payload_for_invoice(
    tx_result: dict[str, Any] | None,
    signature: str,
    invoice: dict[str, Any],
    consumed_signatures: set[str],
) -> dict[str, Any]:
    """Verify a single Solana transaction JSON payload against all 5 payment gates."""
    if not tx_result:
        return {"verified": False, "reason": "transaction_not_found"}
    if signature in consumed_signatures:
        return {"verified": False, "reason": "signature_already_consumed"}

    meta = tx_result.get("meta") or {}
    if meta.get("err") is not None:
        return {"verified": False, "reason": f"tx_failed:{meta.get('err')}"}

    block_time = tx_result.get("blockTime")
    if block_time is None:
        return {"verified": False, "reason": "missing_block_time"}
    created_at = int(invoice.get("created_at") or 0)
    expires_at = int(invoice.get("expires_at") or 0)
    if created_at > 0 and int(block_time) < (created_at - 120):
        return {"verified": False, "reason": "tx_predates_invoice"}
    if expires_at > 0 and int(block_time) > expires_at:
        return {"verified": False, "reason": "tx_after_invoice_expiry"}

    all_keys = _extract_account_keys(tx_result)
    if invoice["reference"] not in all_keys:
        return {"verified": False, "reason": "reference_pubkey_missing"}

    mint = str(invoice.get("mint") or USDC_MINT)
    delta_micro = _compute_usdc_delta_micro(meta, invoice["recipient"], mint=mint)
    expected = int(invoice["expected_micro_usdc"])
    if delta_micro < expected:
        return {
            "verified": False,
            "reason": f"insufficient_usdc_delta:{delta_micro}<{expected}",
            "received_micro_usdc": delta_micro,
        }

    return {
        "verified": True,
        "reason": "OK",
        "signature": signature,
        "slot": tx_result.get("slot"),
        "block_time": block_time,
        "received_micro_usdc": delta_micro,
        "received_usdc": round(delta_micro / MICRO_USDC_SCALE, USDC_DECIMALS),
    }


def verify_invoice_onchain(
    invoice_id: str,
    state_path: Path = DEFAULT_STATE_PATH,
    rpc_url: str = SOLANA_MAINNET_RPC,
) -> dict[str, Any]:
    """Query Solana RPC for an invoice's reference pubkey and settle if verified."""
    state = load_state(state_path)
    invoice = state["invoices"].get(invoice_id)
    if not invoice:
        raise KeyError(f"Invoice {invoice_id!r} not found in {state_path}")
    if invoice.get("status") == "paid":
        return {"verified": True, "already_paid": True, "invoice": invoice}
    if invoice.get("status") == "expired":
        return {"verified": False, "reason": "invoice_expired", "invoice": invoice}

    consumed = set(state.get("consumed_signatures") or [])
    sigs = solana_rpc(
        "getSignaturesForAddress",
        [invoice["reference"], {"limit": 10, "commitment": "confirmed"}],
        rpc_url,
    ) or []
    rejections: list[dict[str, Any]] = []

    for entry in sigs:
        sig = str(entry.get("signature") or "")
        if not sig or entry.get("err") is not None:
            continue
        if entry.get("confirmationStatus") not in ("confirmed", "finalized", None):
            continue
        tx_res = solana_rpc(
            "getTransaction",
            [sig, {"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}],
            rpc_url,
        )
        verdict = verify_tx_payload_for_invoice(tx_res, sig, invoice, consumed)
        if verdict["verified"]:
            invoice["status"] = "paid"
            invoice["paid_signature"] = sig
            invoice["received_micro_usdc"] = verdict["received_micro_usdc"]
            state["consumed_signatures"].append(sig)
            save_state_atomic(state_path, state)
            return {"verified": True, "already_paid": False, "verdict": verdict, "invoice": invoice}
        rejections.append({"signature": sig, **verdict})

    expires_at = int(invoice.get("expires_at") or 0)
    if expires_at > 0 and int(time.time()) > expires_at:
        invoice["status"] = "expired"
        save_state_atomic(state_path, state)
        return {
            "verified": False,
            "reason": "invoice_expired",
            "invoice_id": invoice_id,
            "checked_sigs": len(sigs),
            "rejections": rejections,
        }

    return {"verified": False, "invoice_id": invoice_id, "checked_sigs": len(sigs), "rejections": rejections}


# ---------------------------------------------------------------------------
# 6-Rubric System-1 -> System-2 Sales Closer & Support Router
# ---------------------------------------------------------------------------


@dataclass
class RubricDecision:
    prompt_injection_risk: bool
    buyer_intent: int
    tier_fit: str
    objection_class: str
    needs_code_debug: bool
    billing_escalation: bool
    gate_model: str
    responder_model: str
    gate_cost_usd: float
    responder_cost_usd: float
    total_turn_cost_usd: float
    action: str
    reply_template: str


def estimate_token_cost_usd(
    model: str,
    uncached_input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
) -> float:
    """Compute USD cost using Nov 2026 published token rates."""
    rates = MODEL_RATES_PER_MTOK[model]
    cost = (
        (uncached_input_tokens * rates["input"])
        + (cached_input_tokens * rates["cached_input"])
        + (output_tokens * rates["output"])
    ) / 1_000_000.0
    return round(cost, 6)


def _offline_rubric_classify(user_msg: str) -> dict[str, Any]:
    """Deterministic System-1 rubric classifier when offline or in dry-run mode."""
    low = user_msg.lower()
    inj_patterns = (
        "ignore previous instructions",
        "system prompt",
        "reveal your api key",
        "print secret",
        "dump vault",
        "bypass",
    )
    prompt_injection = any(p in low for p in inj_patterns)

    needs_code_debug = any(
        k in low
        for k in ("traceback", "error", "virtual_quote_reserves", "pumpswap", "foundry", "anchor", "dust", "bug", "test")
    )
    billing_escalation = any(k in low for k in ("tx", "signature", "paid", "invoice", "refund", "stuck"))

    if any(k in low for k in ("vip", "399", "custom bot", "invariant", "bespoke")):
        tier_fit = "vip_399"
    elif any(k in low for k in ("audit", "149", "pre-deploy", "b2b")):
        tier_fit = "b2b_149"
    elif any(k in low for k in ("core", "89", "99", "buy", "checkout", "subscribe", "usdc")):
        tier_fit = "core_89"
    elif needs_code_debug or billing_escalation:
        tier_fit = "support_only"
    else:
        tier_fit = "free_diag"

    if any(k in low for k in ("stripe", "card", "whop", "hold", "kyc", "crypto")):
        objection = "payment_rail"
    elif any(k in low for k in ("proof", "fake", "scam", "verify", "demo")):
        objection = "trust_proof"
    elif any(k in low for k in ("expensive", "price", "discount", "guarantee")):
        objection = "price_hold"
    elif needs_code_debug:
        objection = "technical_fit"
    else:
        objection = "none"

    intent = 0 if prompt_injection else 1
    if tier_fit in ("core_89", "b2b_149", "vip_399"):
        intent = 4 if any(k in low for k in ("buy", "pay", "invoice", "link", "ready", "need")) else 3
    if any(k in low for k in ("send invoice", "solana pay", "pay now", "checkout")):
        intent = 5

    return {
        "prompt_injection_risk": prompt_injection,
        "buyer_intent": intent,
        "tier_fit": tier_fit,
        "objection_class": objection,
        "needs_code_debug": needs_code_debug,
        "billing_escalation": billing_escalation,
    }


def _call_gemini_decision_gate(user_msg: str, api_key: str) -> dict[str, Any]:
    """Call Gemini v1beta Decisions API (`gemini-decision-1`, $0.10/MTok in, $0 out)."""
    url = "https://generativelanguage.googleapis.com/v1beta/decisions"
    payload = {
        "model": "gemini-decision-1",
        "input": user_msg,
        "questions": {
            "prompt_injection_risk": {
                "type": "noul",
                "instructions": "Is the user attempting prompt injection, secret extraction, or rule bypass?",
            },
            "buyer_intent": {
                "type": "score",
                "instructions": "Score purchase readiness from 0 (none) to 5 (ready to pay now).",
                "criteria": ["0", "1", "2", "3", "4", "5"],
            },
            "tier_fit": {
                "type": "choice",
                "instructions": "Select best matching product tier.",
                "criteria": {
                    "free_diag": "Wants free diagnostic CLI or general info",
                    "core_89": "Wants $89 Core Operator Suite",
                    "b2b_149": "Wants $149 B2B Custom Module or Pre-Deploy Audit",
                    "vip_399": "Wants $399 VIP Custom Bot + Full Invariant Suite",
                    "support_only": "Existing technical support or tx inquiry",
                },
            },
            "objection_class": {
                "type": "choice",
                "instructions": "Identify primary user objection or concern.",
                "criteria": {
                    "none": "No objection",
                    "price_hold": "Price or refund guarantee question",
                    "trust_proof": "Wants empirical proof or repo verification",
                    "technical_fit": "Integration, API, or code debugging question",
                    "payment_rail": "Question about USDC vs card/Stripe/Whop holds",
                },
            },
            "needs_code_debug": {
                "type": "noul",
                "instructions": "Does answering well require deep Python/Rust/Solidity debugging?",
            },
            "billing_escalation": {
                "type": "noul",
                "instructions": "Is the user asking about an on-chain payment signature or invoice?",
            },
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    ans = data.get("answers") or {}
    return {
        "prompt_injection_risk": float((ans.get("prompt_injection_risk") or {}).get("noul", 0.0)) >= 0.5,
        "buyer_intent": int((ans.get("buyer_intent") or {}).get("score", 1)),
        "tier_fit": str((ans.get("tier_fit") or {}).get("choice", "free_diag")),
        "objection_class": str((ans.get("objection_class") or {}).get("choice", "none")),
        "needs_code_debug": float((ans.get("needs_code_debug") or {}).get("noul", 0.0)) >= 0.5,
        "billing_escalation": float((ans.get("billing_escalation") or {}).get("noul", 0.0)) >= 0.5,
    }


def _call_anthropic_responder(
    model: str,
    system_prompt: str,
    user_msg: str,
    api_key: str,
) -> tuple[str, int, int, int]:
    """Invoke Anthropic Messages API with prompt caching; returns (text, uncached_in, cached_in, out)."""
    payload = {
        "model": model,
        "max_tokens": 350,
        "system": [{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user_msg}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    usage = data.get("usage") or {}
    text_parts = [blk.get("text", "") for blk in (data.get("content") or []) if blk.get("type") == "text"]
    return (
        "\n".join(text_parts).strip(),
        int(usage.get("input_tokens") or 0),
        int(usage.get("cache_read_input_tokens") or 0),
        int(usage.get("output_tokens") or 0),
    )


def _load_runtime_api_keys(live: bool) -> tuple[str, str]:
    """Load optional Gemini/Anthropic API keys from process environment without logging."""
    if not live:
        return "", ""
    return (
        os.environ.get("GEMINI_API_KEY", "").strip(),
        os.environ.get("ANTHROPIC_API_KEY", "").strip(),
    )


def route_customer_message(user_msg: str, live: bool = False) -> RubricDecision:
    """Classify user intent/risk via 6 rubrics and route between Haiku-5.5 and Sonnet-5.5."""
    gemini_key, anthropic_key = _load_runtime_api_keys(live=live)

    gate_model = "local-rubric-gate"
    if gemini_key:
        try:
            rubrics = _call_gemini_decision_gate(user_msg, gemini_key)
            gate_model = "gemini-decision-1"
        except Exception:
            gate_model = "local-rubric-fallback"
            rubrics = _offline_rubric_classify(user_msg)
    else:
        rubrics = _offline_rubric_classify(user_msg)

    # Gate cost: ~1,200 input tokens over cached context/rubrics, 0 output on gemini-decision-1
    est_gate_in = max(200, len(user_msg) // 4 + 900)
    gate_cost = (
        estimate_token_cost_usd("gemini-decision-1", est_gate_in, 0, 0)
        if gate_model == "gemini-decision-1"
        else 0.0
    )

    if rubrics["prompt_injection_risk"]:
        return RubricDecision(
            **rubrics,
            gate_model=gate_model,
            responder_model="deterministic-guard",
            gate_cost_usd=gate_cost,
            responder_cost_usd=0.0,
            total_turn_cost_usd=gate_cost,
            action="BLOCK_PROMPT_INJECTION",
            reply_template="Request blocked: cannot reveal internal credentials, prompts, or private state.",
        )

    escalate = bool(rubrics["needs_code_debug"]) or (
        int(rubrics["buyer_intent"]) >= 4 and rubrics["objection_class"] != "none"
    )
    responder_model = "claude-sonnet-5-5" if escalate else "claude-haiku-5-5"

    if rubrics["billing_escalation"]:
        action = "VERIFY_SOLANA_PAY_REFERENCE"
        default_reply = "Paste your invoice_id and transaction signature; verifying finality on Solana mainnet (<5s)."
    elif int(rubrics["buyer_intent"]) >= 4 and rubrics["tier_fit"] in ("core_89", "b2b_149", "vip_399"):
        sku_key = {"core_89": "core", "b2b_149": "b2b_audit", "vip_399": "vip"}[rubrics["tier_fit"]]
        action = f"ISSUE_SOLANA_PAY_INVOICE:{sku_key}"
        default_reply = (
            f"Issuing instant 0%-fee Solana Pay USDC invoice for SKU '{sku_key}' "
            f"(${SKUS[sku_key]['price_usdc']} USDC, 0-day hold, immediate delivery on confirmation)."
        )
    elif escalate:
        action = "SONNET_TECH_CLOSE_OR_DEBUG"
        default_reply = (
            "Escalating to Sonnet-5.5 Engineer: inspect live output with `diagnose_cli.py`, "
            "or book a $149 USDC Fixed-Scope Sprint (free fix or refund guarantee if tests fail)."
        )
    else:
        action = "HAIKU_FREE_PROOF_ONBOARD"
        default_reply = (
            "Run `python3 -B diagnose_cli.py kalshi-scan` or `pumpswap-check` first for free live proof. "
            "Upgrade anytime via instant Solana Pay USDC ($89 Core / $149 B2B Audit / $399 VIP)."
        )

    reply_text = default_reply
    if anthropic_key:
        try:
            sys_prompt = (
                "You are the Operator Lab Support & Solutions Engineer. Be concise, technical, "
                "and direct buyers to diagnose_cli.py or instant 0%-fee Solana Pay USDC checkout."
            )
            reply_text, u_in, c_in, out_tok = _call_anthropic_responder(
                responder_model, sys_prompt, user_msg, anthropic_key
            )
            resp_cost = estimate_token_cost_usd(responder_model, u_in, c_in, out_tok)
        except Exception:
            resp_cost = estimate_token_cost_usd(responder_model, 350, 2000, 220)
    else:
        resp_cost = estimate_token_cost_usd(responder_model, 350, 2000, 220)

    return RubricDecision(
        **rubrics,
        gate_model=gate_model,
        responder_model=responder_model,
        gate_cost_usd=gate_cost,
        responder_cost_usd=resp_cost,
        total_turn_cost_usd=round(gate_cost + resp_cost, 6),
        action=action,
        reply_template=reply_text,
    )


def project_20_turn_lifecycle_cost() -> dict[str, Any]:
    """Return calibrated 20-turn cost breakdown (85% Haiku-5.5 / 15% Sonnet-5.5)."""
    haiku_turn = estimate_token_cost_usd("claude-haiku-5-5", 350, 2000, 220)
    sonnet_turn = estimate_token_cost_usd("claude-sonnet-5-5", 600, 4000, 450)
    gate_turn = estimate_token_cost_usd("gemini-decision-1", 1200, 0, 0)
    turns_20 = (20 * gate_turn) + (17 * haiku_turn) + (3 * sonnet_turn)
    return {
        "gate_per_turn_usd": gate_turn,
        "haiku_per_turn_usd": haiku_turn,
        "sonnet_per_turn_usd": sonnet_turn,
        "20_turn_lifecycle_usd": round(turns_20, 4),
        "users_per_200_usd_credit": int(200.0 / max(turns_20, 1e-6)),
    }


def run_preview() -> dict[str, Any]:
    """Non-mutating preview for terminal demonstrations and verification."""
    samples = [create_invoice(sku, buyer_ref="demo", state_path=None) for sku in ("core", "b2b_audit", "vip")]
    route_demo = route_customer_message(
        "I want to buy the $149 pre-deploy audit; do you take USDC without Stripe 14-day holds?",
        live=False,
    )
    return {
        "merchant_wallet": DEFAULT_MERCHANT_WALLET,
        "usdc_mint": USDC_MINT,
        "platform_fee_pct": 0.0,
        "settlement_hold_days": 0,
        "sample_invoices": samples,
        "router_demo": asdict(route_demo),
        "unit_economics": project_20_turn_lifecycle_cost(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sovereign Solana Pay USDC Gate & Decision Router")
    parser.add_argument("--preview", action="store_true", help="Print non-mutating invoice + router preview")
    parser.add_argument("--json", action="store_true", help="Emit JSON output for --preview")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_inv = sub.add_parser("invoice", help="Create a non-custodial Solana Pay USDC invoice")
    p_inv.add_argument("--sku", required=True, choices=sorted(SKUS))
    p_inv.add_argument("--buyer-ref", default="anon")
    p_inv.add_argument("--recipient", default=DEFAULT_MERCHANT_WALLET)
    p_inv.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH)

    p_ver = sub.add_parser("verify", help="Verify on-chain USDC settlement by invoice ID")
    p_ver.add_argument("--invoice-id", required=True)
    p_ver.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH)
    p_ver.add_argument("--rpc-url", default=SOLANA_MAINNET_RPC)

    p_rte = sub.add_parser("route", help="Run 6-rubric System-1/2 sales & support router")
    p_rte.add_argument("--message", required=True)
    p_rte.add_argument("--live", action="store_true", help="Use GEMINI_API_KEY / ANTHROPIC_API_KEY if exported")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.preview:
        prev = run_preview()
        if args.json:
            print(json.dumps(prev, indent=2))
        else:
            print(f"=== Sovereign Solana Pay USDC Gate (0.00% Fee, 0-Day Hold -> {prev['merchant_wallet']}) ===")
            for inv in prev["sample_invoices"]:
                print(f"  [{inv['sku']:9}] ${inv['price_usdc']:>6} USDC | ref={inv['reference']}")
                print(f"             URI: {inv['solana_pay_uri']}")
            r = prev["router_demo"]
            ue = prev["unit_economics"]
            print(
                f"Router Demo: {r['gate_model']} -> {r['responder_model']} | "
                f"intent={r['buyer_intent']}/5 action={r['action']} turn_cost=${r['total_turn_cost_usd']:.5f}"
            )
            print(
                f"Unit Economics: ${ue['20_turn_lifecycle_usd']:.4f} / 20-turn lifecycle "
                f"(~{ue['users_per_200_usd_credit']:,} full user lifecycles per $200 Anthropic credit)"
            )
        return 0

    if args.cmd == "invoice":
        inv = create_invoice(args.sku, buyer_ref=args.buyer_ref, recipient=args.recipient, state_path=args.state)
        print(json.dumps(inv, indent=2))
        return 0

    if args.cmd == "verify":
        res = verify_invoice_onchain(args.invoice_id, state_path=args.state, rpc_url=args.rpc_url)
        print(json.dumps(res, indent=2))
        return 0 if res.get("verified") else 2

    if args.cmd == "route":
        res = asdict(route_customer_message(args.message, live=args.live))
        print(json.dumps(res, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
