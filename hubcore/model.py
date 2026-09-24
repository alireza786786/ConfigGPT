# -*- coding: utf-8 -*-
"""Canonical immutable Node model (Phase 1).

One Node is one proxy configuration. The model is frozen: updates (geo,
latency, score) happen through :func:`dataclasses.replace`, never by
mutating fields. ``protocol_fields`` carries protocol-specific identity
material as a sorted tuple of (key, value) pairs so Phase 2+ parsers can
add fields (Reality pubkey/shortId, SS plugin, Hysteria2 obfs, VMess
encryption, ALPN/fingerprint, XHTTP mode, ...) without redesigning Node.
No parser logic and no I/O lives here.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

from .enums import Protocol, Security, Transport
from .latency import LatencyKind, LatencySample

__all__ = ["Endpoint", "GeoInfo", "Node"]


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Network endpoint (host + port), optionally with a resolved IP.

    ``resolved_ip`` stays None until DNS resolution happens in a later
    phase; identity defaults to the configured host until then.
    """

    host: str
    port: int
    resolved_ip: Optional[str] = None

    def __post_init__(self):
        if not self.host or not str(self.host).strip():
            raise ValueError("Endpoint.host must be non-empty")
        p = self.port
        try:
            p = int(p)
        except (TypeError, ValueError):
            raise ValueError(f"Endpoint.port must be an integer: {self.port!r}")
        if not (0 < p < 65536):
            raise ValueError(f"Endpoint.port out of range: {p}")
        object.__setattr__(self, "port", p)
        host = str(self.host).strip().lower()
        # RFC 3986: reg-names are percent-decoded; cross-phase bug fix so
        # 'ex%61mple.com' and 'example.com' share one identity everywhere
        host = unquote(host)
        # textual IPv6 canonicalization (compressed lowercase form) so
        # '2001:db8::1' == '2001:db8:0:0:0:0:0:1'; pure textual, NO DNS
        if ":" in host:
            try:
                host = str(ipaddress.ip_address(host)).lower()
            except ValueError:
                pass  # not a parseable IPv6 literal; keep the text form
        object.__setattr__(self, "host", host)
        if self.resolved_ip is not None:
            object.__setattr__(self, "resolved_ip", str(self.resolved_ip).strip())

    @property
    def identity_host(self) -> str:
        """Host used for endpoint identity: resolved IP first, else host."""
        return self.resolved_ip or self.host


@dataclass(frozen=True, slots=True)
class GeoInfo:
    """Geographic classification result (populated from GeoIP later)."""

    country: str = "Unknown"
    city: str = "Unknown"
    country_code: str = "XX"
    flag: str = "🌐"

    _MAX_TEXT = 128  # defensive clamp on provider-sourced strings

    def __post_init__(self):
        object.__setattr__(self, "country", (self.country or "Unknown").strip()[:self._MAX_TEXT])
        object.__setattr__(self, "city", (self.city or "Unknown").strip()[:self._MAX_TEXT])
        object.__setattr__(self, "country_code", (self.country_code or "XX").strip().upper()[:2])
        object.__setattr__(self, "flag", (self.flag or "🌐").strip()[:8])


@dataclass(frozen=True, slots=True)
class Node:
    """One proxy configuration (immutable canonical record).

    ``protocol_fields``: sorted tuple of (key, value) pairs for
    protocol-specific identity material, e.g.::

        ("vless.reality.pubkey", "..."), ("vmess.encryption", "auto"),
        ("ss.method", "rc4-md5"), ("hy2.obfs.password", "..."),
        ("tls.alpn", "h3"), ("xhttp.mode", "packet-up")

    Phase 2+ parsers populate these; the identity layer hashes them as-is.
    """

    protocol: Protocol
    endpoint: Endpoint
    raw_url: str = ""
    # --- credentials / identity material ---------------------------------
    uuid: str = ""
    password: str = ""
    secret: str = ""
    # --- TLS / transport material ----------------------------------------
    sni: str = ""
    host_header: str = ""
    transport: Transport = Transport.UNKNOWN
    security: Security = Security.UNKNOWN
    path: str = ""
    service_name: str = ""
    alpn: str = ""
    fingerprint: str = ""
    allow_insecure: bool = False
    flow: str = ""
    # --- protocol-specific extensible identity material -------------------
    protocol_fields: tuple = ()
    # --- measurement / classification (updated via replace) ---------------
    tcp_connect: Optional[LatencySample] = None
    protocol_handshake: Optional[LatencySample] = None
    measured_latency: Optional[LatencySample] = None
    # Phase 9: |probe2 - probe1| over two INDEPENDENT MEASURED cycles.
    # Float (not LatencySample) deliberately: jitter is a DERIVED value
    # of two samples that already live on the node; storing a third
    # sample would duplicate the evidence it summarizes.
    jitter_ms: Optional[float] = None
    score: float = 0.0
    geo: Optional[GeoInfo] = None
    output_name: str = ""

    def __post_init__(self):
        # protocol_fields must be a sorted, de-duplicated pair-tuple so it
        # is canonical and hashable. Values are coerced to str for stable
        # hashing across parser implementations.
        pf = self.protocol_fields
        if pf is None:
            pf = ()
        try:
            items = []
            seen = set()
            for k, v in pf:
                k = str(k).strip()
                if not k:
                    raise ValueError("protocol_fields keys must be non-empty")
                if k in seen:
                    raise ValueError(f"duplicate protocol_fields key: {k}")
                seen.add(k)
                items.append((k, str(v)))
            items.sort()
            object.__setattr__(self, "protocol_fields", tuple(items))
        except TypeError:
            raise ValueError("protocol_fields must be an iterable of (key, value) pairs")
        if self.score is None:
            object.__setattr__(self, "score", 0.0)
        if not self.raw_url:
            object.__setattr__(self, "raw_url", "")

    def with_geo(self, geo: GeoInfo) -> "Node":
        """Return a copy with geo classification attached (immutable update)."""
        return replace(self, geo=geo)

    def with_tcp_connect(self, sample: LatencySample) -> "Node":
        """Return a copy with a TCP-connect latency sample attached."""
        if sample.kind is not LatencyKind.TCP_CONNECT:
            raise ValueError("with_tcp_connect requires a TCP_CONNECT sample")
        return replace(self, tcp_connect=sample)

    def with_protocol_handshake(self, sample: LatencySample) -> "Node":
        """Return a copy with a protocol-handshake latency sample attached."""
        if sample.kind is not LatencyKind.PROTOCOL_HANDSHAKE:
            raise ValueError("with_protocol_handshake requires a PROTOCOL_HANDSHAKE sample")
        return replace(self, protocol_handshake=sample)

    def with_measured(self, sample: LatencySample) -> "Node":
        """Return a copy with the scoring/output latency sample attached."""
        if sample.kind is not LatencyKind.MEASURED:
            raise ValueError("with_measured requires a MEASURED sample")
        return replace(self, measured_latency=sample)

    def with_jitter(self, jitter_ms: float) -> "Node":
        """Return a copy with a computed jitter value (Phase 9).

        Guarded: NaN/Inf and negative values are rejected so a broken
        measurement can never plant a fabricated number on the node.
        Additionally, jitter is only meaningful as |probe2 - probe1|
        over REAL MEASURED samples — attaching it to a node that has
        no measured_latency is refused (fabrication guard).
        """
        import math
        if self.measured_latency is None:
            raise ValueError(
                "with_jitter requires a MEASURED sample on the node")
        j = float(jitter_ms)
        if math.isnan(j) or math.isinf(j):
            raise ValueError("jitter must be finite")
        if j < 0:
            raise ValueError("jitter must be >= 0")
        return replace(self, jitter_ms=j)

    def with_score(self, score: float) -> "Node":
        """Return a copy with an updated score."""
        return replace(self, score=float(score))


from dataclasses import replace  # noqa: E402  (used by with_* updaters)
