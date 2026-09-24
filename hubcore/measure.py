# -*- coding: utf-8 -*-
"""Measured proxy latency + jitter (Phase 9).

Produces ``LatencyKind.MEASURED`` — the value later scoring/output is
allowed to use — from REAL, repeatable end-to-end proxy interactions.
It never invents a number, never converts TCP_CONNECT or
PROTOCOL_HANDSHAKE into MEASURED, and never re-resolves a hostname.

MEASUREMENT DEFINITION (exact, and matching Phase 8's taxonomy):

A "probe cycle" is a COMPLETE, independent end-to-end interaction:

    socket creation (excluded)
      -> TCP connect to the PINNED IP (excluded)
      -> TLS wrap with SNI = original hostname (included)
      -> protocol request bytes (included)
      -> bounded read until the FIRST protocol-qualified response
         byte arrives (included)

    MEASURED = monotonic-clock elapsed of the INCLUDED portion,
    i.e. TLS + request + time-to-first-qualifying-byte.

This is a full round trip through the proxy path — not a TCP connect
and not merely "a TLS handshake succeeded". Two probe cycles are
INDEPENDENT (fresh socket each time); the second never reuses the
first's result. jitter = |probe2 - probe1| over two VALID cycles;
each cycle's MEASURED sample and the jitter live as separate fields.

PREREQUISITE GATE: a node is measurable only if Phase 8 could validate
it (same shared gate). Unsupported protocols get status "unsupported"
with the same reason codes — never a fabricated latency.

CLOCK: time.monotonic() for durations (immune to wall-clock jumps),
injected via ``clock`` for tests; wall timestamps come from the
LatencySample default. Sleeps between the two probes are injected via
``sleeper`` so tests do not really wait.

THRESHOLD CONSTANTS (raw classification only — NO scoring here):
    LATENCY_THRESHOLD_MS = 500   (contract from the original design)
    JITTER_THRESHOLD_MS  = 75
Thresholds are exposed as documented constants + a raw
``within_threshold`` flag on the outcome; they never become a score.

SECURITY: bounded reads, short error codes, no credential/OS-text
leakage, sockets closed on every path, no eval/exec/subprocess.
"""
from __future__ import annotations

import math
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from hubcore.handshake import (
    HandshakeValidator,
    probe_bytes,
    probe_gate,
    quiet_close,
    response_matches_protocol,
    sni_for,
)
from hubcore.latency import LatencyKind, LatencySample
from hubcore.model import Node
from hubcore.resolver import classify_ip

__all__ = [
    "MeasureOutcome",
    "ProxyMeasurer",
    "LATENCY_THRESHOLD_MS",
    "JITTER_THRESHOLD_MS",
]

LATENCY_THRESHOLD_MS = 500.0   # raw threshold (documented; NOT a score)
JITTER_THRESHOLD_MS = 75.0     # raw threshold (documented; NOT a score)

DEFAULT_PROBE_GAP_SECONDS = 0.135   # ~120–150 ms between jitter probes


@dataclass
class MeasureOutcome:
    """Result of measuring one node (Phase 9)."""

    ok: bool
    status: str          # success|partial|unsupported|timeout|tls_error|protocol_error|no_pinned_ip|internal_error
    reason: str = ""     # short, credential-free detail code
    unsupported_reason: str = ""
    identity_hostname: str = ""     # ORIGINAL host (SNI source) — never the IP
    dial_target: str = ""           # pinned IP the probes dialed
    probes: list = field(default_factory=list)   # per-probe short reports
    jitter_ms: Optional[float] = None
    latency: Optional[LatencySample] = None      # kind == MEASURED (probe1)
    latency2: Optional[LatencySample] = None     # kind == MEASURED (probe2)
    within_threshold: bool = False  # raw latency classification, NOT a score
    jitter_within_threshold: bool = False
    notes: tuple = field(default_factory=tuple)


@dataclass
class _ProbeReport:
    """Internal short per-probe record (no payload, audit-friendly)."""

    index: int
    ok: bool
    status: str = ""
    reason: str = ""
    ms: Optional[float] = None


class ProxyMeasurer:
    """Two-probe MEASURED-latency + jitter engine (fully injectable).

    ``connect_factory`` — Phase 7/8 contract: creates a socket-like
    object; the measurer dials ``connect((pinned_ip, port))`` itself.

    ``tls_wrap`` — Phase 8 contract (verification always on unless the
    explicit ``accept_injected_tls`` test seam is acknowledged).

    ``clock`` — injected zero-arg callable returning float seconds,
    monotonic. Defaults to ``time.monotonic``.

    ``sleeper`` — injected one-arg callable (seconds). Defaults to
    ``time.sleep``. Tests inject a recorder instead of really waiting.
    """

    def __init__(
        self,
        connect_factory: Optional[Callable[..., object]] = None,
        tls_wrap: Optional[Callable[[object, str], object]] = None,
        *,
        timeout: float = 4.0,
        allow_credential_probe: bool = False,
        accept_injected_tls: bool = False,
        probe_gap_seconds: float = DEFAULT_PROBE_GAP_SECONDS,
        clock: Optional[Callable[[], float]] = None,
        sleeper: Optional[Callable[[float]], None] = None,
    ):
        if tls_wrap is not None and not accept_injected_tls:
            raise ValueError(
                "custom tls_wrap requires accept_injected_tls=True (test seam)")
        self._connect_factory = connect_factory or HandshakeValidator._default_connect_factory
        self._tls_wrap = tls_wrap or HandshakeValidator._default_tls_wrap
        self.timeout = timeout
        self.allow_credential_probe = allow_credential_probe
        self.probe_gap_seconds = float(probe_gap_seconds)
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep

    # ------------------------------------------------------------------
    def measure(self, node: Node) -> MeasureOutcome:
        ep = node.endpoint
        outcome = MeasureOutcome(
            ok=False, status="unsupported",
            identity_hostname=ep.host,
        )

        # ---- 1. pinned destination (fail-closed; NEVER re-resolve) ----
        if ep.resolved_ip:
            target = ep.resolved_ip.strip("[]")
        elif ep.host and self._is_literal(ep.host):
            target = ep.host.strip("[]")
        else:
            outcome.status = "no_pinned_ip"
            outcome.reason = "no_pinned_ip"
            return outcome

        # ---- 2. destination policy gate (defense in depth) ------------
        kind = self._kind_or_unknown(target)
        if kind == "unknown":
            outcome.status = "unsupported"
            outcome.unsupported_reason = "unparseable_ip"
            outcome.reason = "unparseable_ip"
            return outcome
        if kind in ("loopback", "private", "link_local", "reserved",
                    "multicast", "unspecified"):
            outcome.status = "unsupported"
            outcome.unsupported_reason = f"forbidden_target:{kind}"
            outcome.reason = "forbidden_target"
            return outcome
        outcome.dial_target = target   # only AFTER the gate

        # ---- 3. protocol gate (SAME shared gate as Phase 8) -----------
        gate = probe_gate(node, self.allow_credential_probe)
        if gate is not None:
            reason, _ = gate
            outcome.status = "unsupported"
            outcome.unsupported_reason = reason
            outcome.reason = "unsupported_protocol"
            outcome.notes = (f"refused:{reason}",)
            return outcome

        # ---- 4. two INDEPENDENT full-cycle probes ---------------------
        r1 = self._probe_cycle(node, target)
        outcome.probes.append(r1)
        if not r1.ok:
            outcome.status = r1.status or "protocol_error"
            outcome.reason = r1.reason or "probe1_failed"
            return outcome
        outcome.latency = self._sample(r1, 1)

        # inter-probe gap (injectable; tests never really sleep)
        try:
            self._sleeper(self.probe_gap_seconds)
        except Exception:
            outcome.notes = outcome.notes + ("sleep_interrupted",)

        r2 = self._probe_cycle(node, target)
        outcome.probes.append(r2)
        if not r2.ok:
            # probe1 stays valid: NEVER discard a real measurement, and
            # NEVER fabricate jitter from one sample.
            outcome.status = "partial"
            outcome.reason = r2.reason or "probe2_failed"
            outcome.latency2 = None
            outcome.jitter_ms = None
            outcome.ok = True          # one real MEASURED sample exists
            outcome.within_threshold = outcome.latency.value_ms < LATENCY_THRESHOLD_MS
            return outcome

        outcome.latency2 = self._sample(r2, 2)
        v1 = r1.ms or 0.0
        v2 = r2.ms or 0.0
        jitter = abs(v2 - v1)
        if not math.isfinite(jitter):
            # defensive: hostile clock values cannot fabricate jitter
            outcome.status = "internal_error"
            outcome.reason = "nonfinite_jitter"
            return outcome
        outcome.jitter_ms = round(jitter, 2)
        outcome.ok = True
        outcome.status = "success"
        outcome.within_threshold = outcome.latency.value_ms < LATENCY_THRESHOLD_MS
        outcome.jitter_within_threshold = outcome.jitter_ms < JITTER_THRESHOLD_MS
        return outcome

    # ------------------------------------------------------------------
    def attach(self, node: Node) -> Node:
        """Return a new Node with MEASURED samples (+ jitter) attached.

        Guarded against kind confusion: only MEASURED samples are
        stored on measured_latency; TCP/handshake samples already on
        the node are untouched (no retroactive rewrite). Nodes whose
        measurement did not succeed are returned unchanged.
        """
        out = self.measure(node)
        if out.latency is None:
            return node
        new_node = node.with_measured(out.latency)
        if out.latency2 is not None:
            # keep both independent samples: second replaces the first
            # slot only if the model allows; we store probe2's value on
            # measured_latency (the latest observation) and keep jitter
            # as the derived field. probe1's sample is preserved in the
            # outcome for audit.
            new_node = new_node.with_measured(out.latency2)
        if out.jitter_ms is not None:
            new_node = new_node.with_jitter(out.jitter_ms)
        return new_node

    # ------------------------------------------------------------------
    def _sample(self, rep: _ProbeReport, index: int) -> LatencySample:
        return LatencySample(
            value_ms=rep.ms,
            kind=LatencyKind.MEASURED,
            attempts=1,
            measured_at=time.time(),
            provenance=f"measured:probe{index}:{rep.status}",
        )

    def _probe_cycle(self, node: Node, target: str) -> _ProbeReport:
        """One COMPLETE end-to-end probe cycle (fresh socket)."""
        ep = node.endpoint
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        sock = None
        try:
            sock = self._connect_factory(family, socket.SOCK_STREAM, target,
                                         ep.port, self.timeout)
            sock.connect((target, ep.port))
        except Exception as exc:
            if sock is not None:
                quiet_close(sock)
            if isinstance(exc, (TimeoutError, socket.timeout)):
                return _ProbeReport(1, False, status="timeout", reason="tcp_timeout")
            return _ProbeReport(1, False, status="protocol_error",
                                reason="tcp_failed")
        try:
            t0 = self._clock()          # INCLUDED window starts here:
                                        # TLS + request + first byte
            try:
                tls_sock = self._tls_wrap(sock, sni_for(node))
            except Exception:
                return _ProbeReport(1, False, status="tls_error",
                                    reason="tls_handshake_failed")
            try:
                probe = probe_bytes(node)
                if probe is None:
                    return _ProbeReport(1, False, status="internal_error",
                                        reason="probe_build_failed")
                try:
                    tls_sock.sendall(probe)
                except (TimeoutError, socket.timeout):
                    return _ProbeReport(1, False, status="timeout",
                                        reason="send_timeout")
                except Exception:
                    return _ProbeReport(1, False, status="protocol_error",
                                        reason="send_failed")

                # bounded read until FIRST qualifying byte
                data = b""
                got = False
                for _ in range(4):      # same cap as Phase 8
                    try:
                        chunk = tls_sock.recv(4096)
                    except (TimeoutError, socket.timeout):
                        if got:
                            break
                        return _ProbeReport(1, False, status="timeout",
                                            reason="recv_timeout")
                    except Exception:
                        if got:
                            break
                        return _ProbeReport(1, False, status="protocol_error",
                                            reason="recv_failed")
                    if not chunk:
                        break           # clean EOF
                    data += chunk
                    if response_matches_protocol(node, data):
                        got = True
                        break           # stop at first qualifying byte
                    if len(data) >= 4096:
                        break
                if not got:
                    if not data:
                        return _ProbeReport(1, False, status="protocol_error",
                                            reason="closed_without_response")
                    return _ProbeReport(1, False, status="protocol_error",
                                        reason="unexpected_response")
                t1 = self._clock()
                ms = (t1 - t0) * 1000.0
                if not math.isfinite(ms) or ms < 0:
                    # hostile/odd clock -> refuse to fabricate a number
                    return _ProbeReport(1, False, status="internal_error",
                                        reason="nonfinite_latency")
                return _ProbeReport(1, True, status="success",
                                    ms=round(ms, 2))
            finally:
                quiet_close(tls_sock)
        finally:
            quiet_close(sock)

    # ------------------------------------------------------------------
    @staticmethod
    def _is_literal(host: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _kind_or_unknown(ip: str) -> str:
        try:
            return classify_ip(ip).kind
        except Exception:
            return "unknown"
