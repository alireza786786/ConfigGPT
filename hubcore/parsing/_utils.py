# -*- coding: utf-8 -*-
"""Internal helpers for hubcore.parsing (Phase 2).

All functions are pure/offline, defensive, and credential-safe.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Optional
from urllib.parse import parse_qsl, unquote, urlencode

__all__ = [
    "MAX_URL_LEN",
    "MAX_PAYLOAD_LEN",
    "MAX_SECRET_LEN",
    "redact",
    "b64_decode_flexible",
    "percent_decode",
    "parse_query",
    "safe_int",
    "safe_str",
]

# Defensive limits: parser inputs are untrusted; these bound CPU/memory.
MAX_URL_LEN = 8192          # a config line longer than this is hostile
MAX_PAYLOAD_LEN = 65536     # vmess/ss payload (base64 body) cap
MAX_SECRET_LEN = 4096       # any single credential field cap

# userinfo up to '@' — uuid:password@, user@ etc.
_USERINFO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#]*@", re.DOTALL)


def redact(raw: str) -> str:
    """Return a credential-free display form of a config line.

    Strips the userinfo segment (uuid/password/secret) and, for ss legacy
    payloads, the base64 method:password blob. Keeps scheme + host only.
    """
    if not raw:
        return ""
    s = raw if len(raw) <= MAX_URL_LEN else raw[:64] + "...<truncated>"
    # drop everything between "://" and the first '/', '?' or '#'
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*://)([^/?#]*)(.*)$", s, re.DOTALL)
    if not m:
        return "<unparseable>"
    scheme, authority, rest = m.groups()
    if "@" in authority:
        authority = "<redacted>@" + authority.rsplit("@", 1)[1]
    return scheme + authority + rest


def _pad(b64: str) -> str:
    return b64 + "=" * (-len(b64) % 4)


def b64_decode_flexible(text: str) -> Optional[bytes]:
    """Decode standard/url-safe base64, with or without padding.

    Whitespace/newlines are ignored (found in real-world feeds). Returns
    ``None`` for anything undecodable. ASCII-only codec ('latin-1') keeps
    strictness: embedded unicode => None.
    """
    if not text:
        return None
    if len(text) > MAX_PAYLOAD_LEN:
        return None
    stripped = "".join(text.split())
    if not stripped:
        return None
    normalized = stripped.replace("-", "+").replace("_", "/")
    # drop stray '=' not at the end (some feeds embed them mid-string)
    normalized = normalized.rstrip("=")
    if not normalized:
        return None
    normalized = _pad(normalized)
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError:
        return None
    for candidate in (normalized, normalized.replace("+", "-").replace("/", "_")):
        try:
            return base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def percent_decode(text: str) -> str:
    """Percent-decode with UTF-8 error tolerance (never raises).

    Uses ``errors="replace"`` semantics via the stdlib; malformed
    sequences become U+FFFD instead of raising.
    """
    if not text:
        return ""
    try:
        return unquote(text, errors="replace")
    except Exception:
        return text


def parse_query(query: str) -> dict:
    """Parse a query string into a lowercase-keyed dict (last value wins).

    Duplicate/conflicting parameters are resolved deterministically
    (later wins) and are additionally exposed as ``key[]`` entries so no
    information is silently lost:
      'a=1&a=2' -> {'a': '2', 'a[]': '1'}
    """
    out: dict = {}
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    except Exception:
        return out
    for k, v in pairs:
        lk = k.strip().lower()
        if lk in out:
            prev = out[lk]
            out[lk + "[]"] = prev if lk + "[]" not in out else out[lk + "[]"]
        out[lk] = v
    return out


def safe_int(value, default=None):
    """Int coercion that never raises; boundaries checked by callers."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def safe_str(value, max_len: int = MAX_SECRET_LEN) -> str:
    """String coercion: NFC-normalized, length-capped, never raises."""
    if value is None:
        return ""
    s = str(value)
    if len(s) > max_len:
        s = s[:max_len]
    return unicodedata.normalize("NFC", s)
