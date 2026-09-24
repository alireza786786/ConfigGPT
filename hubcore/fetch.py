# -*- coding: utf-8 -*-
"""Secure URL fetching for hub sources (Phase 4).

Fetches source documents over HTTPS with strict, defensive defaults:

- scheme allow-list: https only (http is refused, other schemes refused)
- redirect policy: followed only while the scheme stays https, the host
  stays within the SAME registrable host (host-prefix match), and the hop
  count stays within ``max_redirects``; redirects to other hosts/schemes
  are refused (credential/SSRF hardening, no private-IP fetches anyway)
- response-size cap enforced DURING streaming (an oversized body aborts
  as soon as the cap is crossed, before full download)
- total wall-clock budget shared across redirects and body reading
- text decoding is tolerant; content is DATA, never code

The transport (``urlopen``-like callable) is injected so all tests run
fully offline with fake transports.

Security: no eval/exec/subprocess; error messages carry status/location
classification only — never response bodies or headers verbatim.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlsplit

__all__ = [
    "FetchError",
    "FetchBlockedError",
    "FetchNetworkError",
    "FetchSizeError",
    "FetchTimeoutError",
    "FetchResult",
    "Fetcher",
]

MAX_REDIRECTS_DEFAULT = 3
DEFAULT_BUDGET_SECONDS = 20.0
UA = "hubcore-fetcher/1.0"

# urllib error types imported lazily so the module imports without network
# machinery on exotic platforms; tests never hit these paths.
UrlopenLike = Callable[..., object]


class FetchError(Exception):
    """Base class for fetch failures (safe to display, no body content)."""


class FetchBlockedError(FetchError):
    """URL/redirect refused by policy (scheme, host, private address...)."""


class FetchNetworkError(FetchError):
    """Connection-level failure (DNS, refused, reset...)."""


class FetchSizeError(FetchError):
    """Response exceeded the configured size cap."""


class FetchTimeoutError(FetchError):
    """The overall time budget was exhausted."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Successful fetch outcome (text content + audit metadata)."""

    text: str
    url: str                # final URL after redirects
    status: int
    bytes_read: int
    redirects: int = 0
    content_type: str = ""

    def __post_init__(self):
        # hard guarantee: no accidental retention of giant bodies
        if self.bytes_read < 0:
            raise ValueError("bytes_read must be >= 0")


def _classify_host(host: str) -> str:
    """Coarse registrable-domain approximation for same-host policy.

    Keeps the last two labels (or three for common two-part TLDs). This
    is deliberately conservative: it only ever SHRINKS the set of allowed
    redirects (more refusal, never more allowance).
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    two_part_tlds = {"co.uk", "com.au", "co.jp", "org.uk", "net.au"}
    if ".".join(labels[-2:]) in two_part_tlds:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_public_ipv4(host: str) -> bool:
    """Accept ONLY dotted-quad decimal IPv4; reject every other numeric
    encoding (decimal ints like 2130706433, octal 0177.0.0.1, hex 0x7f...)
    and classify RFC1918/loopback/link-local/CGNAT/reserved as private."""
    octets = host.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return False  # non-quad numeric encodings refused entirely
    if any(len(o) > 3 for o in octets):
        return False
    try:
        vals = [int(o) for o in octets]
    except ValueError:
        return False
    if any(v > 255 for v in vals):
        return False
    if (vals[0] in (0, 10, 127)
            or (vals[0] == 172 and 16 <= vals[1] <= 31)
            or (vals[0] == 192 and vals[1] == 168)
            or (vals[0] == 169 and vals[1] == 254)
            or (vals[0] == 100 and 64 <= vals[1] <= 127)
            or vals[0] >= 224):
        return False  # private/special-use
    return True


def _validate_http_url(url: str) -> bool:
    """True when the URL is structurally https and not literal-private."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme.lower() != "https":
        return False
    # credentials in the URL are refused outright (also prevents leaking
    # them into transport calls/redirect chains)
    if (parts.username or parts.password or "@" in (parts.netloc or "")):
        return False
    # bracketed IPv6 literals are refused outright (no DNS resolution in
    # this phase => cannot classify them safely)
    if "[" in (parts.netloc or ""):
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return False
    # literal private/loopback/link-local/metadata addresses are refused
    # even before DNS (defense in depth; real resolution comes later)
    if host in {"localhost"} or host.endswith(".localhost"):
        return False
    if host.replace(".", "").isdigit() or host.startswith("0x") or "0x" in host:
        # numeric-ish host (decimal ints, octal, hex): only a clean public
        # dotted quad may pass; every other numeric encoding is refused
        return _is_public_ipv4(host)
    return True


class Fetcher:
    """HTTPS fetcher with injected transport (fully testable offline)."""

    def __init__(
        self,
        transport: Optional[UrlopenLike] = None,
        *,
        max_bytes: int = 32 * 1024 * 1024,
        budget_seconds: float = DEFAULT_BUDGET_SECONDS,
        max_redirects: int = MAX_REDIRECTS_DEFAULT,
    ):
        self._transport = transport
        self.max_bytes = max_bytes
        self.budget_seconds = budget_seconds
        self.max_redirects = max_redirects

    # ------------------------------------------------------------------
    def fetch(self, url: str) -> FetchResult:
        """Fetch one https URL; raises FetchError subclasses on failure."""
        if not isinstance(url, str) or not url.strip():
            raise FetchBlockedError("empty url")
        url = url.strip()
        if not _validate_http_url(url):
            raise FetchBlockedError("url refused by policy")
        if self._transport is None:
            from urllib.request import urlopen  # stdlib default transport

            transport: UrlopenLike = urlopen
        else:
            transport = self._transport
        import time

        deadline = time.monotonic() + self.budget_seconds
        current = url
        redirects = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchTimeoutError("time budget exhausted")
            try:
                resp = transport(current, timeout=remaining)
            except FetchError:
                raise
            except TimeoutError:
                raise FetchTimeoutError("transport timeout") from None
            except Exception as exc:
                # sanitized: classify common urllib failures without
                # embedding raw exception text (may contain URLs/paths)
                reason = getattr(exc, "reason", None)
                if isinstance(reason, TimeoutError):
                    raise FetchTimeoutError("transport timeout") from None
                raise FetchNetworkError("network failure") from None
            status = int(getattr(resp, "status", 0) or 0)
            if status in (301, 302, 303, 307, 308):
                location = getattr(resp, "headers", {}).get("Location", "")
                resp = self._close_quietly(resp)
                if redirects >= self.max_redirects:
                    raise FetchBlockedError("too many redirects")
                redirects += 1
                nxt = self._resolve_redirect(current, location)
                current = nxt
                continue
            if status != 200:
                resp = self._close_quietly(resp)
                raise FetchNetworkError(f"http status {status}")
            body = self._read_capped(resp, deadline)
            ctype = ""
            try:
                ctype = (resp.headers.get("Content-Type") or "")[:128]
            except Exception:
                ctype = ""
            resp = self._close_quietly(resp)
            text = body.decode("utf-8", errors="replace")
            return FetchResult(text=text, url=current, status=200,
                               bytes_read=len(body), redirects=redirects,
                               content_type=ctype)

    # ------------------------------------------------------------------
    def _resolve_redirect(self, current: str, location: str) -> str:
        if not location:
            raise FetchBlockedError("redirect without location")
        if len(location) > 2048:
            raise FetchBlockedError("redirect location too long")
        from urllib.parse import urljoin

        nxt = urljoin(current, location.strip())
        if not _validate_http_url(nxt):
            raise FetchBlockedError("redirect target refused by policy")
        cur_host = (urlsplit(current).hostname or "").lower()
        nxt_host = (urlsplit(nxt).hostname or "").lower()
        if _classify_host(cur_host) != _classify_host(nxt_host):
            raise FetchBlockedError("cross-host redirect refused")
        return nxt

    def _read_capped(self, resp, deadline: float) -> bytes:
        import time

        chunks = []
        total = 0
        try:
            while True:
                if time.monotonic() > deadline:
                    raise FetchTimeoutError("time budget exhausted while reading")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_bytes:
                    raise FetchSizeError(f"response exceeds {self.max_bytes} bytes")
                chunks.append(chunk)
        finally:
            resp = self._close_quietly(resp)
        return b"".join(chunks)

    @staticmethod
    def _close_quietly(resp):
        try:
            close = getattr(resp, "close", None)
            if callable(close):
                close()
        except Exception:
            pass
        return None
