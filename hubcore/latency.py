# -*- coding: utf-8 -*-
"""Latency measurement taxonomy for the hub data model (Phase 1).

The legacy pipeline reports a raw TCP connect time as if it were a
"real ping". The canonical model forbids that ambiguity: every latency
value carries its measurement kind. Three kinds are distinguished:

- TCP_CONNECT:        bare TCP handshake to host:port (what the legacy
                      pipeline measures today)
- PROTOCOL_HANDSHAKE: actual proxy/protocol-level handshake (not yet
                      implemented anywhere in this repo)
- MEASURED:           the value the scoring/output system is allowed to
                      use, whatever produced it (with provenance)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, unique
from time import time, time_ns

__all__ = ["LatencyKind", "LatencySample", "tcp_connect_sample"]


@unique
class LatencyKind(Enum):
    """What the number actually measures. Never conflate these."""

    TCP_CONNECT = "tcp_connect"
    PROTOCOL_HANDSHAKE = "protocol_handshake"
    MEASURED = "measured"


@dataclass(frozen=True, slots=True)
class LatencySample:
    """One immutable latency observation.

    value_ms   : latency in milliseconds; ``None`` = measurement failed
                 (kept so failures are auditable, not silently dropped)
    kind       : which measurement produced this value
    attempts   : how many attempts the probe made (jitter analysis input)
    measured_at: unix timestamp (seconds, float) of the observation
    provenance : short free-form tag, e.g. "legacy_engine.ping_node"
    """

    value_ms: float | None
    kind: LatencyKind
    attempts: int = 1
    measured_at: float = field(default_factory=time)
    provenance: str = ""

    def __post_init__(self):
        if self.value_ms is not None and self.value_ms < 0:
            raise ValueError("value_ms must be >= 0 or None")
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")

    @property
    def ok(self) -> bool:
        """True when a numeric latency was actually observed."""
        return self.value_ms is not None


def tcp_connect_sample(value_ms, attempts=1, provenance=""):
    """Factory for TCP-connect observations (the legacy kind)."""
    return LatencySample(
        value_ms=value_ms,
        kind=LatencyKind.TCP_CONNECT,
        attempts=attempts,
        measured_at=time(),
        provenance=provenance or f"ts={time_ns()}",
    )
