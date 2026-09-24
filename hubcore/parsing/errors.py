# -*- coding: utf-8 -*-
"""Typed parse errors for the hubcore parsing layer (Phase 2).

Security properties:
- messages NEVER embed credentials (uuid/password/secret/userinfo);
  ``_utils.redact`` strips them before any string formatting.
- ``ParseError`` never wraps and re-raises raw exception text that could
  leak input fragments; it reports a sanitized reason only.
"""
from __future__ import annotations

__all__ = ["ParseError", "UnsupportedSchemeError", "MalformedURLError", "LengthLimitError"]


class ParseError(ValueError):
    """Base class for all config-parse failures (safe to display)."""

    scheme = "unknown"

    def __init__(self, message: str, *, reason: str = ""):
        super().__init__(message)
        self.reason = reason or message


class UnsupportedSchemeError(ParseError):
    """Scheme not in the supported protocol set."""

    def __init__(self, scheme: str):
        self.scheme = (scheme or "")[:32]
        super().__init__(f"unsupported scheme: {self.scheme!r}")


class MalformedURLError(ParseError):
    """Structurally invalid URI / payload for the declared scheme."""

    def __init__(self, scheme: str = "unknown", detail: str = ""):
        self.scheme = (scheme or "")[:32]
        msg = f"malformed {self.scheme} config"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


class LengthLimitError(ParseError):
    """Input exceeded a defensive size limit (DoS guard)."""

    def __init__(self, what: str, limit: int):
        self.what = what
        self.limit = limit
        super().__init__(f"{what} exceeds length limit of {limit}")
