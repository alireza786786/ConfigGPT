# -*- coding: utf-8 -*-
"""Canonical enumerations for the hub data model (Phase 1).

Small, protocol-agnostic enums that classify the node families already
present in the repository outputs (vless/vmess/ss/trojan/hysteria2/socks5)
and the transports the legacy pipeline labels. String coercion accepts
legacy aliases (``hy2`` -> HYSTERIA2, ``ss`` -> SHADOWSOCKS) so Phase 2
parsers can construct canonical nodes without a redesign. This module is
NOT a parser and performs no network or file I/O.
"""
from __future__ import annotations

from enum import Enum, unique

__all__ = ["Protocol", "Transport", "Security"]


@unique
class Protocol(Enum):
    """Wire protocol of a node. ``OTHER`` = recognized-but-unclassified."""

    VLESS = "vless"
    VMESS = "vmess"
    SHADOWSOCKS = "shadowsocks"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"
    SOCKS5 = "socks5"
    OTHER = "other"

    @classmethod
    def from_string(cls, value):
        """Coerce legacy/alias scheme strings (case-insensitive).

        Unknown/empty values collapse to ``OTHER`` instead of raising so
        the model tolerates future protocols without breaking identity or
        output generation.
        """
        if not value:
            return cls.OTHER
        v = str(value).strip().lower()
        aliases = {
            "vless": "vless",
            "vmess": "vmess",
            "ss": "shadowsocks",
            "shadowsocks": "shadowsocks",
            "trojan": "trojan",
            "hysteria2": "hysteria2",
            "hy2": "hysteria2",
            "socks": "socks5",
            "socks5": "socks5",
            "socks5h": "socks5",
        }
        canonical = aliases.get(v)
        if canonical is None:
            return cls.OTHER
        try:
            return cls[canonical.upper()]
        except KeyError:
            return cls.OTHER


@unique
class Transport(Enum):
    """Carrier/transport observed or configured for a node."""

    TCP = "tcp"
    WS = "ws"
    GRPC = "grpc"
    XHTTP = "xhttp"
    HTTP2 = "h2"
    QUIC = "quic"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value):
        """Coerce transport labels (case-insensitive, alias-tolerant)."""
        if not value:
            return cls.UNKNOWN
        v = str(value).strip().lower()
        aliases = {
            "tcp": "tcp",
            "raw": "tcp",
            "ws": "ws",
            "websocket": "ws",
            "httpupgrade": "ws",
            "grpc": "grpc",
            "gun": "grpc",
            "xhttp": "xhttp",
            "splithttp": "xhttp",
            "h2": "HTTP2",
            "http": "HTTP2",
            "quic": "quic",
        }
        canonical = aliases.get(v)
        if canonical is None:
            return cls.UNKNOWN
        try:
            return cls[canonical.upper()]
        except KeyError:
            return cls.UNKNOWN


@unique
class Security(Enum):
    """Stream security layer (TLS / REALITY / plain)."""

    TLS = "tls"
    REALITY = "reality"
    NONE = "none"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value):
        """Coerce security labels (case-insensitive, alias-tolerant)."""
        if not value:
            return cls.UNKNOWN
        v = str(value).strip().lower()
        aliases = {
            "tls": "tls",
            "none": "none",
            "reality": "reality",
        }
        canonical = aliases.get(v)
        if canonical is None:
            return cls.UNKNOWN
        try:
            return cls[canonical.upper()]
        except KeyError:
            return cls.UNKNOWN
