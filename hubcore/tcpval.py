# -*- coding: utf-8 -*-
"""TCP validation with pinned resolved IP (Phase 7).

Scope (per approved plan): LAYER-4 REACHABILITY ONLY. This module does
NOT perform a protocol handshake and does NOT measure "proxy ping".
The latency value it produces is a raw ``TCP_CONNECT`` sample and MUST
NOT be treated as protocol/proxy latency by later scoring (Phase 1's
``LatencyKind`` taxonomy enforces this at the model level).

Pinning policy (closes the Phase 6 documented TOCTOU gap as far as this
layer can):
- connection targets ``endpoint.resolved_ip`` when present — the OS is
  never asked to re-resolve the hostname;
- the original hostname is PRESERVED in the result
  (``identity_hostname``) so later TLS/SNI and Host-header construction
  (Phase 8+) use the real name, not the IP;
- when no resolved IP is available the validator does NOT silently fall
  back to hostname connect; the caller decides (explicit
  ``allow_direct_hostname`` flag, default False) — this keeps the
  rebinding guarantee the default.
- mixed-v4/v6 endpoints: each address is attempted; verdict is success
  if ANY address connects, and the report lists per-address outcomes
  (partial failure is explicit, not hidden).

Security: errors carry short codes only; never the destination IP of
private ranges, never OS exception text. Sockets are always closed
(finally + quiet close); a validation run cannot leak descriptors.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from hubcore.latency import LatencyKind, LatencySample
from hubcore.model import Node
from hubcore.resolver import Resolver, classify_ip

__all__ = [
    "TcpOutcome",
    "AttemptReport",
    "TcpValidator",
    "TcpError",
]

ConnectFactory = Callable[..., object]   # returns socket-like object


class TcpError(Exception):
    """Controlled TCP validation failure (no sensitive payload)."""


@dataclass(frozen=True)
class AttemptReport:
    """One per-address attempt outcome."""

    target_ip: str
    version: int            # 4 | 6
    ok: bool
    error: str = ""         # one of: 'timeout' | 'refused' | 'unreachable' | 'blocked' | 'invalid_ip' | 'resolve' | 'os_error'
    latency_ms: Optional[float] = None

    @property
    def kind(self) -> str:
        try:
            return classify_ip(self.target_ip).kind
        except Exception:
            return "unknown"


@dataclass
class TcpOutcome:
    """Full result of validating one node's endpoint."""

    ok: bool
    attempts: list = field(default_factory=list)          # list[AttemptReport]
    identity_hostname: str = ""    # ORIGINAL host for SNI/Host later
    pinned_ip: str = ""            # the IP actually connected (first ok)
    latency: Optional[LatencySample] = None   # kind == TCP_CONNECT, raw
    error: str = ""                # short verdict code when not ok ("" on success)
    used_hostname_dial: bool = False   # audit: explicit hostname opt-in was used

    @property
    def any_attempt_blocked(self) -> bool:
        return any(a.kind in ("loopback", "private", "link_local", "reserved",
                              "multicast", "unspecified")
                   for a in self.attempts)


def _short_error(exc: Exception) -> str:
    """Map socket exceptions to short codes (never embed OS text)."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.timeout):
        return "timeout"
    err = getattr(exc, "errno", None)
    if err in (111, 10061):        # ECONNREFUSED / WSAECONNREFUSED
        return "refused"
    if err in (113, 10051):        # EHOSTUNREACH / WSAENETUNREACH
        return "unreachable"
    if err in (101, 10050):        # ENETUNREACH-ish variants
        return "unreachable"
    if isinstance(exc, socket.gaierror):
        return "resolve"           # should not happen when pinned
    return "os_error"


class TcpValidator:
    """Pinned TCP-connect validator with injectable socket factory.

    ``connect_factory`` signature (injected for offline tests)::

        factory(family: int, socktype: int, target: str, port: int,
                timeout: float) -> socket-like with .connect(addr) and
                .close()

    CONTRACT: the factory only CREATES the socket (and applies the
    timeout); the validator itself performs ``sock.connect((target,
    port))`` and times exactly that call — this is what makes the
    latency sample a genuine TCP_CONNECT measurement and what lets
    injected fake sockets observe the dial (regression-tested).
    Exceptions from ``connect`` are mapped to short codes, never OS
    text.
    """

    def __init__(
        self,
        connect_factory: Optional[ConnectFactory] = None,
        *,
        timeout: float = 3.0,
        resolver: Optional[Resolver] = None,
        allow_direct_hostname: bool = False,
    ):
        self._factory = connect_factory or self._default_factory
        self.timeout = timeout
        self._resolver = resolver
        self.allow_direct_hostname = allow_direct_hostname

    # ------------------------------------------------------------------
    @staticmethod
    def _default_factory(family: int, socktype: int, target: str,
                         port: int, timeout: float):
        # CREATION ONLY: the dial happens in _attempt so the measured
        # window is exactly connect() (and fakes see the dial).
        sock = socket.socket(family, socktype)
        sock.settimeout(timeout)
        return sock

    # ------------------------------------------------------------------
    def validate(self, node: Node) -> TcpOutcome:
        """Validate one node's endpoint via pinned IP (never re-resolves
        when ``resolved_ip`` is present)."""
        ep = node.endpoint
        outcome = TcpOutcome(ok=False, identity_hostname=ep.host)

        ips: list = []
        if ep.resolved_ip:
            ips = [ep.resolved_ip]
        elif ep.host and self._looks_like_literal(ep.host):
            ips = [ep.host.strip("[]")]
        elif self.allow_direct_hostname:
            # hostname connect is EXPLICIT opt-in; identity preserved and
            # the host string itself is the target (OS resolves — caller
            # accepted rebinding risk explicitly).
            outcome.used_hostname_dial = True
            rep = self._attempt(ep.host, ep.port, prefer_v6=False)
            outcome.attempts.append(rep)
            if rep.ok:
                outcome.ok = True
                outcome.pinned_ip = ep.host   # audit only; NOT written to resolved_ip
                outcome.latency = self._sample(rep)
            else:
                outcome.error = rep.error or "attempt_error"
            return outcome
        else:
            # nothing pinned and hostname connect not allowed: fail closed
            outcome.error = "no_pinned_ip"
            return outcome

        if not ips or not ips[0]:
            outcome.error = "no_pinned_ip"
            return outcome

        # policy: forbidden (private/loopback/...) targets are not probed
        # at all — validation exists to find usable egress endpoints
        ordered = self._order_for_dialing(ips)
        for target, version in ordered:
            kind = self._kind_or_unknown(target)
            if kind == "unknown":
                # not parseable as an IP (e.g. octal '0177.0.0.1' which the
                # OS could still interpret as 127.0.0.1) -> never handed to
                # the dial path; fail this address explicitly
                outcome.attempts.append(AttemptReport(
                    target_ip=target, version=version, ok=False,
                    error="invalid_ip"))
                continue
            if kind in ("loopback", "private", "link_local", "reserved",
                        "multicast", "unspecified"):
                outcome.attempts.append(AttemptReport(
                    target_ip=target, version=version, ok=False,
                    error="blocked"))
                continue
            rep = self._attempt(target, ep.port, prefer_v6=(version == 6))
            outcome.attempts.append(rep)
            if rep.ok and not outcome.ok:
                outcome.ok = True
                outcome.pinned_ip = target
                outcome.latency = self._sample(rep)
        if not outcome.ok:
            outcome.error = self._aggregate_error(outcome.attempts)
        return outcome

    # ------------------------------------------------------------------
    def validate_and_attach(self, node: Node) -> tuple:
        """Validate and return ``(new_node, outcome)`` where new_node has
        ``tcp_connect`` sample and ``endpoint.resolved_ip`` pinned to the
        working address. Original hostname is untouched (SNI later)."""
        outcome = self.validate(node)
        if not outcome.ok:
            return node, outcome

        sample = outcome.latency
        new_ep = node.endpoint
        if self._looks_like_literal(outcome.pinned_ip):
            # only a genuine IP literal may pin resolved_ip; the hostname
            # opt-in path reports the hostname it dialed but must not
            # write it into the IP field (identity stays where it belongs)
            new_ep = replace(node.endpoint, resolved_ip=outcome.pinned_ip)
        new_node = node.with_tcp_connect(sample)
        new_node = replace(new_node, endpoint=new_ep)
        return new_node, outcome

    # ------------------------------------------------------------------
    def _attempt(self, target: str, port: int, *, prefer_v6: bool) -> AttemptReport:
        family = socket.AF_INET6 if (":" in target or prefer_v6) else socket.AF_INET
        version = 6 if family == socket.AF_INET6 else 4
        sock = None
        try:
            sock = self._factory(family, socket.SOCK_STREAM, target, port,
                                 self.timeout)
            t0 = time.monotonic()
            sock.connect((target, port))          # THE dial (timed only)
            ms = round((time.monotonic() - t0) * 1000.0, 2)
            return AttemptReport(target_ip=target, version=version, ok=True,
                                 latency_ms=ms)
        except Exception as exc:      # containment IS the contract
            try:
                code = _short_error(exc)
            except Exception:
                code = "os_error"     # mapping itself must never raise
            return AttemptReport(target_ip=target, version=version, ok=False,
                                 error=code)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _sample(self, rep: AttemptReport, attempts: int = 1) -> LatencySample:
        return LatencySample(
            value_ms=rep.latency_ms,
            kind=LatencyKind.TCP_CONNECT,
            attempts=max(1, attempts),
            provenance=f"tcpval:{rep.target_ip}",
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _looks_like_literal(host: str) -> bool:
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

    @staticmethod
    def _order_for_dialing(ips) -> list:
        """Deterministic: IPv4 first (fast path), then IPv6; input order
        preserved inside each family."""
        v4, v6 = [], []
        for ip in ips:
            bare = ip.strip("[]")
            (v6 if ":" in bare else v4).append((bare, 6 if ":" in bare else 4))
        return v4 + v6

    @staticmethod
    def _aggregate_error(attempts) -> str:
        errs = [a.error for a in attempts if a.error]
        if errs and all(e == "timeout" for e in errs):
            return "timeout"
        if "refused" in errs:
            return "refused"
        if "blocked" in errs:
            return "blocked"
        if "unreachable" in errs:
            return "unreachable"
        if errs:
            return errs[0]
        return "unknown"
