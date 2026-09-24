# -*- coding: utf-8 -*-
"""DNS-aware resolution + IP classification (Phase 6).

Design:
- the OS call (``socket.getaddrinfo``) is INJECTED, so every test runs
  offline with scripted transports; production passes ``None`` to use
  the stdlib.
- results are :class:`ResolvedHost` records that split IPv4 vs IPv6 and
  keep a deterministic order (input order of the resolver, then port).
- a SMALL bounded cache (default 512 entries, TTL default 300s) maps
  (host, port) -> tuple of ips; entries expire as a whole.
- policy: a host whose resolved addresses are ALL private/special-use is
  ``blocked_private``; mixed results keep only the public addresses for
  *fetch policy* while classification reports every address. This gives
  Phase 4's fetcher a second, resolution-aware gate WITHOUT pretending
  full DNS-rebinding/TOCTOU safety (documented limitation below).

LIMITATION (explicit, no over-claiming): classic TOCTOU rebinding is not
fully preventable at this layer because the actual TCP connect later re-
resolves the name independently. Full safety would require pinning the
resolved IP into the connection step (connect-by-IP + SNI), which is a
later-phase change. This module therefore provides *classification* and
*policy verdicts*, not a complete rebinding defense.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional

__all__ = [
    "IPClass",
    "ResolveStatus",
    "ResolvedHost",
    "Resolver",
    "classify_ip",
    "ResolveError",
    "PolicyBlocked",
]

AddrInfoCallable = Callable[..., object]


class ResolveError(Exception):
    """Controlled resolution failure (never leaks raw system errors)."""


class PolicyBlocked(ResolveError):
    """Host resolved exclusively to forbidden (private/special) targets."""


@dataclass(frozen=True)
class IPClass:
    """Classification of one IP literal (frozen record)."""

    value: str
    version: int          # 4 or 6
    kind: str             # public | loopback | private | link_local | reserved | multicast | unspecified | mapping


def classify_ip(ip: str) -> IPClass:
    """Classify an IP string; raises ResolveError for garbage."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ResolveError("invalid ip literal") from None
    if addr.version == 6 and addr.ipv4_mapped:
        # ::ffff:a.b.c.d is really an IPv4 target; classify the v4 side
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        kind = "loopback"
    elif addr.is_link_local:
        kind = "link_local"
    elif addr.is_multicast:
        kind = "multicast"
    elif addr.is_unspecified:
        kind = "unspecified"
    elif addr.is_reserved:
        kind = "reserved"    # 240/4 etc. — checked BEFORE private: exact label
    elif addr.is_private:
        kind = "private"
    elif addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        kind = "private"   # CGNAT — special-use, forbidden for egress
    else:
        kind = "public"
    return IPClass(value=str(addr), version=addr.version, kind=kind)


def _is_forbidden(addr) -> bool:
    """Forbidden-for-egress classification.

    Notes (platform-independent, stdlib semantics verified):
    - CGNAT 100.64/10 is NOT ``is_private`` in stdlib (it is neither
      global nor private) => treated explicitly as forbidden here.
    - 240/4 is ``is_reserved`` AND ``is_private`` => covered by private.
    """
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_link_local or addr.is_multicast \
            or addr.is_unspecified or addr.is_private or addr.is_reserved:
        return True
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True  # CGNAT: shared address space, never egress
    return False


_FORBIDDEN_KINDS = {"loopback", "private", "link_local", "unspecified", "reserved", "multicast"}  # 'private' covers CGNAT + reserved too (see classify_ip)


@dataclass(frozen=True)
class ResolvedHost:
    """Outcome of one host resolution."""

    host: str
    status: str                     # ResolveStatus value
    ipv4: tuple = ()
    ipv6: tuple = ()
    error: str = ""                 # short code, no raw exception text

    @property
    def all_ips(self) -> tuple:
        return self.ipv4 + self.ipv6

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def public_ips(self) -> tuple:
        out = []
        for ip in self.all_ips:
            c = classify_ip(ip)
            if c.kind == "public":
                out.append(c.value)
        return tuple(out)

    @property
    def blocked_private(self) -> bool:
        """True when the host resolves ONLY to forbidden ranges."""
        ips = self.all_ips
        if not ips:
            return False
        return all(classify_ip(ip).kind in _FORBIDDEN_KINDS for ip in ips)


class ResolveStatus:
    OK = "ok"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    TEMP_FAIL = "temp_fail"
    INVALID = "invalid"


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class _TTLCache:
    """Tiny bounded TTL cache (whole-record expiry, no partial merges)."""

    def __init__(self, max_entries: int, ttl_seconds: float):
        self.max_entries = max(max_entries, 1)
        self.ttl = ttl_seconds
        self._data = {}

    def get(self, key):
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if time.monotonic() > expires:
            self._data.pop(key, None)
            return None
        return value

    def put(self, key, value):
        if len(self._data) >= self.max_entries:
            # drop the oldest inserted key (dicts keep insertion order)
            oldest = next(iter(self._data))
            self._data.pop(oldest, None)
        self._data[key] = (time.monotonic() + self.ttl, value)

    def __len__(self):
        return len(self._data)


MAX_ADDRS_PER_HOST = 64  # cap on retained addresses per resolution


class Resolver:
    """Injectable, policy-aware resolver."""

    def __init__(
        self,
        getaddrinfo: Optional[AddrInfoCallable] = None,
        *,
        timeout: float = 5.0,
        cache_entries: int = 512,
        cache_ttl: float = 300.0,
    ):
        self._getaddrinfo = getaddrinfo or socket.getaddrinfo
        self.timeout = timeout
        self._cache = _TTLCache(cache_entries, cache_ttl)

    # ------------------------------------------------------------------
    def resolve(self, host: str, port: int = 443) -> ResolvedHost:
        """Resolve one hostname; never raises for normal DNS failures."""
        host = (host or "").strip().strip(".").lower()
        if not host:
            return ResolvedHost(host="", status=ResolveStatus.INVALID, error="empty_host")
        # IP literal: classify directly, NO DNS round-trip
        if _is_literal(host):
            bare = host.strip("[]")
            try:
                c = classify_ip(bare)
            except ResolveError:
                return ResolvedHost(host=host, status=ResolveStatus.INVALID, error="bad_literal")
            key = (bare, c.version)
            rec = ResolvedHost(
                host=host, status=ResolveStatus.OK,
                ipv4=(bare,) if c.version == 4 else (),
                ipv6=(bare,) if c.version == 6 else (),
            )
            return rec
        cache_key = (host, port)
        hit = self._cache.get(cache_key)
        if hit is not None:
            return hit
        try:
            infos = self._getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            status, err = self._classify_gaierror(exc)
            rec = ResolvedHost(host=host, status=status, error=err)
            self._cache.put(cache_key, rec)   # negative caching too (bounded)
            return rec
        except TimeoutError:
            rec = ResolvedHost(host=host, status=ResolveStatus.TIMEOUT, error="timeout")
            self._cache.put(cache_key, rec)
            return rec
        except OSError:
            rec = ResolvedHost(host=host, status=ResolveStatus.TEMP_FAIL, error="os_error")
            self._cache.put(cache_key, rec)
            return rec
        except ValueError:
            return ResolvedHost(host=host, status=ResolveStatus.INVALID, error="bad_input")
        except Exception:
            # ANY other injected-transport failure is contained (contract:
            # resolver never crashes the pipeline, no raw text leakage)
            rec = ResolvedHost(host=host, status=ResolveStatus.TEMP_FAIL, error="resolver_error")
            self._cache.put(cache_key, rec)
            return rec
        ips4, ips6 = [], []
        seen = set()
        for info in infos:
            try:
                sa = info[4]
                ip = str(sa[0])
            except (IndexError, TypeError):
                continue
            if ip in seen:
                continue
            seen.add(ip)
            try:
                c = classify_ip(ip)
            except ResolveError:
                continue  # malformed resolver answer: skip, never crash
            if c.version == 4:
                ips4.append(c.value)
            else:
                ips6.append(c.value)
        if not ips4 and not ips6:
            rec = ResolvedHost(host=host, status=ResolveStatus.INVALID, error="malformed_result")
            self._cache.put(cache_key, rec)
            return rec
        # cap retained addresses (huge answers cannot balloon the record);
        # deterministic: first-seen order already, cap keeps that order
        ips4 = tuple(ips4[:MAX_ADDRS_PER_HOST])
        ips6 = tuple(ips6[:MAX_ADDRS_PER_HOST])
        rec = ResolvedHost(host=host, status=ResolveStatus.OK,
                           ipv4=ips4, ipv6=ips6)
        self._cache.put(cache_key, rec)
        return rec

    # ------------------------------------------------------------------
    def resolve_or_block(self, host: str, port: int = 443) -> ResolvedHost:
        """Like :meth:`resolve` but raises PolicyBlocked when the host
        resolves exclusively into forbidden ranges (pipeline gate)."""
        rec = self.resolve(host, port)
        if rec.blocked_private:
            raise PolicyBlocked("host resolves to forbidden range")
        return rec

    @staticmethod
    def _classify_gaierror(exc: socket.gaierror) -> tuple:
        """Portable gaierror -> status mapping via errno where available.

        Windows: 11001 WSAHOST_NOT_FOUND, 11004 WSANO_DATA (both NX-ish);
        11002/10060 try-again/timeout. POSIX: EAI_NONAME/-2, EAI_AGAIN/-3.
        The raw message text is never embedded into the record.
        """
        errno = getattr(exc, "errno", None)
        if errno in (11001, 11004, -2, 8):     # host-not-found family
            return ResolveStatus.NXDOMAIN, "nxdomain"
        if errno in (11002, 11003, -3, -4):    # try-again family
            return ResolveStatus.TEMP_FAIL, "temp_fail"
        if errno in (10060, 10061):            # windows timeout/refused
            return ResolveStatus.TIMEOUT, "timeout"
        text = str(getattr(exc, "args", ("",))[0]).lower()
        if "timed out" in text:
            return ResolveStatus.TIMEOUT, "timeout"
        if "temporary failure" in text:
            return ResolveStatus.TEMP_FAIL, "temp_fail"
        if "not known" in text or "getaddrinfo failed" in text or "nodename" in text:
            return ResolveStatus.NXDOMAIN, "nxdomain"
        return ResolveStatus.TEMP_FAIL, "resolve_error"
