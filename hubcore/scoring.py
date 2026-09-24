# -*- coding: utf-8 -*-
"""Deterministic node scoring (Phase 10).

PURE function of (Node + its existing measurements). No network, no
DNS, no GeoIP queries, no new measurements, no clock, no randomness —
the same input always yields the same score.

FORMULA — the project's OWN contract, extracted verbatim from the
legacy engine (``multi_bot/engine.py`` line 238) so no new weights are
invented::

    score = (1000 / measured_ms) - 1.5 * jitter_ms
            + arch_bonus + port_bonus

with the legacy gate ``avg_ping >= MAX_FINAL_PING_MS -> no score``
(MAX_FINAL_PING_MS == Phase 9's LATENCY_THRESHOLD_MS == 500) and
``port_bonus = 100`` iff the port is in the legacy GOLDEN_PORTS set.
The arch-bonus table (XHTTP-Elite 500, Reality-Vision 450 (+50 padding),
Reality-gRPC 420, Reality 380, Hysteria2 320, VLESS-TLS 300, VMess-TLS
280, Trojan-TLS 260, CF-CleanIP 200, CF-Worker 180, default 100) and its
EXACT matching order are reproduced from ``detect_arch_and_bonus``.

WHAT IS DELIBERATELY NOT INHERITED (legacy's fabricated-data cheats):
* legacy replaced a failed ping with ``ping=150.0, jitter=10.0`` for
  vless/vmess  -> here: unscorable, never fabricated;
* legacy fabricated ``jitter=10.0`` when the second ping failed
  -> here: insufficient_data, never fabricated (Phase 9 already
  refuses single-probe jitter).
Documented inherited quirks of the legacy formula (flagged, unchanged):
* latency is a GATE (>=500 -> unscorable) but jitter is NOT — it only
  contributes the -1.5* penalty term (so jitter=74/75/76 change the
  score smoothly by 1.5 each; there is no jitter gate in the contract);
* as measured_ms -> 0+, 1000/measured grows without bound (finite but
  large scores are inherited behaviour).

INPUT POLICY (measurement integrity):
* latency   = ``node.measured_latency`` ONLY; its kind must be
  LatencyKind.MEASURED (a TCP_CONNECT or PROTOCOL_HANDSHAKE sample is
  refused — never converted, never substituted);
* jitter    = ``node.jitter_ms`` ONLY (set by Phase 9 only when two
  independent probes succeeded); missing jitter != 0;
* GeoIP/DNS = metadata ONLY — country/city/flag/ASN never move the
  score (no legacy contract says otherwise);
* the scorer never mutates the node and never writes measurements.

STATUS TAXONOMY (Unsupported ≠ Failed ≠ Insufficient ≠ Scored):
* ``scored``           — full valid data; score computed;
* ``unsupported``      — the shared Phase 8/9 probe gate says this
  protocol/transport cannot be measured honestly (VMess, SS,
  Hysteria2/QUIC, REALITY, non-TCP transports...) -> never scored,
  even if a measured sample somehow exists;
* ``unscorable``       — measurement attempted but unusable: sample
  value is None (failed observation kept for audit), non-finite,
  non-positive, or >= 500ms (over the latency gate);
* ``insufficient_data``— measurable protocol but no MEASURED sample at
  all, or a MEASURED sample without jitter (missing != 0).

EXPLAINABILITY: every outcome carries its components (latency term,
jitter penalty, arch label + bonus, port bonus, threshold echoes) so
any score can be audited by hand.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from hubcore.handshake import probe_gate
from hubcore.latency import LatencyKind
from hubcore.model import Node

__all__ = [
    "ScoreOutcome",
    "score_node",
    "LATENCY_GATE_MS",
    "JITTER_PENALTY_WEIGHT",
    "GOLDEN_PORTS",
    "PORT_BONUS",
]

# ---- the project's own constants (provenance: multi_bot/engine.py) ----
LATENCY_GATE_MS = 500.0          # == legacy MAX_FINAL_PING_MS == Phase 9 LATENCY_THRESHOLD_MS
JITTER_PENALTY_WEIGHT = 1.5      # legacy: jitter * 1.5 penalty term
GOLDEN_PORTS = frozenset({443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880})
PORT_BONUS = 100                 # legacy: 100 iff port in GOLDEN_PORTS


@dataclass
class ScoreOutcome:
    """Explainable scoring result for one node."""

    status: str                     # scored|unsupported|unscorable|insufficient_data
    score: Optional[float] = None   # None unless status == "scored"
    detail: str = ""                # short reason code when not scored
    components: dict = field(default_factory=dict)   # audit trail


def _arch_bonus(node: Node):
    """Legacy ``detect_arch_and_bonus`` mapped onto the canonical Node,
    preserving its EXACT matching order (first match wins)."""
    proto = node.protocol.value
    sec = node.security.name.lower()
    net = node.transport.value
    flow = (node.flow or "").lower()
    svc = node.service_name or ""
    host = node.endpoint.host or ""

    if net == "xhttp":
        return "XHTTP-Elite", 500
    if sec == "reality" and "xtls-rprx-vision" in flow:
        bonus = 450
        # legacy sniffs the raw link for padding markers; identical,
        # deterministic behaviour on the canonical node:
        if "xpaddingbytes" in (node.raw_url or "").lower() \
                or "padding" in (node.raw_url or "").lower():
            bonus += 50
        return "Reality-Vision", bonus
    if sec == "reality" and (net == "grpc" or svc):
        return "Reality-gRPC", 420
    if sec == "reality":
        return "Reality", 380
    if proto == "vless":
        return "VLESS-TLS", 300
    if proto == "vmess":
        return "VMess-TLS", 280
    if proto == "hysteria2":
        return "Hysteria2", 320
    if proto == "trojan":
        return "Trojan-TLS", 260
    if "workers.dev" in host or "pages.dev" in host:
        return "CF-Worker", 180
    pts = host.split(".")
    if len(pts) == 4 and all(x.isdigit() for x in pts):
        return "CF-CleanIP", 200
    return ("Shadowsocks", 100) if proto == "shadowsocks" \
        else (proto.upper(), 100)


def score_node(node: Node) -> ScoreOutcome:
    """Score one node from its EXISTING measurements (pure; no I/O)."""
    components = {
        "latency_gate_ms": LATENCY_GATE_MS,
        "jitter_penalty_weight": JITTER_PENALTY_WEIGHT,
        "golden_ports": sorted(GOLDEN_PORTS),   # sorted: dict-order-proof
        "port_in_golden": node.endpoint.port in GOLDEN_PORTS,
        "port_bonus": PORT_BONUS if node.endpoint.port in GOLDEN_PORTS else 0,
        "has_tcp_sample": node.tcp_connect is not None,
        "has_handshake_sample": node.protocol_handshake is not None,
        "has_measured_sample": node.measured_latency is not None,
        "has_jitter": node.jitter_ms is not None,
    }

    # ---- 1. protocol gate: unsupported protocols are never scored ----
    gate = probe_gate(node, allow_credential_probe=True)
    # (credential flag only affects Trojan probing, not measurability
    # classification; scoring is gate-identical for both settings)
    if gate is not None:
        reason, _ = gate
        components["unsupported_reason"] = reason
        return ScoreOutcome(status="unsupported",
                            detail="unsupported_protocol",
                            components=components)

    # ---- 2. latency input: MEASURED sample only, kind-checked --------
    sample = node.measured_latency
    if sample is None:
        return ScoreOutcome(status="insufficient_data",
                            detail="no_measured_sample",
                            components=components)
    if sample.kind is not LatencyKind.MEASURED:
        # integrity: a TCP/handshake sample must never be consumed
        return ScoreOutcome(status="unscorable",
                            detail="measured_kind_invalid",
                            components=components)
    ms = sample.value_ms
    if ms is None:
        return ScoreOutcome(status="unscorable",
                            detail="measured_failed_null",
                            components=components)
    if not math.isfinite(ms):
        return ScoreOutcome(status="unscorable",
                            detail="nonfinite_latency",
                            components=components)
    if ms <= 0:
        return ScoreOutcome(status="unscorable",
                            detail="latency_nonpositive",
                            components=components)
    if ms >= LATENCY_GATE_MS:
        # legacy gate: avg_ping >= MAX_FINAL_PING_MS -> no score
        # (boundary pinned by tests: 500 -> unscorable, 499.99 -> scored)
        return ScoreOutcome(status="unscorable",
                            detail="latency_over_threshold",
                            components=components)

    # ---- 3. jitter input: only a real two-probe jitter ----------------
    jitter = node.jitter_ms
    if jitter is None:
        # legacy fabricated 10.0 here — refused; missing != 0
        components["latency_term"] = round(1000.0 / ms, 4)
        return ScoreOutcome(status="insufficient_data",
                            detail="jitter_missing",
                            components=components)
    if not math.isfinite(jitter) or jitter < 0:
        return ScoreOutcome(status="unscorable",
                            detail="invalid_jitter",
                            components=components)

    # ---- 4. the legacy formula, verbatim ------------------------------
    arch_label, arch_bonus = _arch_bonus(node)
    port_bonus = PORT_BONUS if node.endpoint.port in GOLDEN_PORTS else 0
    latency_term = 1000.0 / ms
    jitter_penalty = JITTER_PENALTY_WEIGHT * jitter
    score = latency_term - jitter_penalty + arch_bonus + port_bonus

    if not math.isfinite(score):
        # cannot happen with finite inputs; kept as a hard guarantee
        return ScoreOutcome(status="unscorable",
                            detail="nonfinite_score",
                            components=components)

    components.update({
        "latency_term": round(latency_term, 4),
        "jitter_penalty": round(jitter_penalty, 4),
        "arch_label": arch_label,
        "arch_bonus": arch_bonus,
        "port_bonus": port_bonus,
        "jitter_within_threshold": jitter < 75.0,   # raw flag, NOT a gate
        "latency_within_threshold": ms < LATENCY_GATE_MS,
    })
    return ScoreOutcome(
        status="scored",
        score=round(score, 2),          # legacy rounds to 2 decimals
        components=components,
    )
