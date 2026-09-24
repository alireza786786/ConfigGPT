# -*- coding: utf-8 -*-
"""GeoIP layer (Phase 6): annotate resolved Nodes with geo metadata.

Design:
- ``GeoProvider`` is a swappable interface; the hubcore ships only
  OFFLINE providers (``NullGeoProvider`` -> all Unknown,
  ``TableGeoProvider`` -> caller-supplied exact-IP table for tests and
  private datasets). NO external API/dependency is added by Phase 6; a
  real provider (e.g. local mmdb reader) plugs in later behind the same
  interface.
- provider answers are length-capped and structurally validated; a bad
  or oversized answer degrades to Unknown instead of crashing.
- ``annotate_resolved`` is the pipeline wiring: given Nodes with
  ``endpoint.resolved_ip`` set (from the Resolver phase), it fills
  ``node.resolved_ip`` mirror, ``node.geo`` and ``node.output_name``
  flag/country/city using the same branding tokens as legacy output
  (flag emoji from country code, deterministic ordering preserved).

Unknown handling: country 'Unknown' / code 'XX' / flag '🌐' — explicit
sentinels, never empty strings that would break output formatting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from hubcore.model import GeoInfo, Node

from .resolver import ResolvedHost, Resolver

__all__ = [
    "GeoAnswer",
    "GeoProvider",
    "NullGeoProvider",
    "TableGeoProvider",
    "annotate_resolved",
    "MAX_PROVIDER_ANSWER",
]

MAX_PROVIDER_ANSWER = 256 * 1024   # defensive cap for one provider reply


@dataclass(frozen=True)
class GeoAnswer:
    """One provider answer (already validated)."""

    country: str
    city: str
    country_code: str
    asn: Optional[int] = None


class GeoProvider:
    """Interface: ip -> GeoAnswer. Subclass/replace for real providers."""

    def lookup(self, ip: str) -> Optional[GeoAnswer]:
        raise NotImplementedError


class NullGeoProvider(GeoProvider):
    """Always Unknown (offline default)."""

    def lookup(self, ip: str) -> Optional[GeoAnswer]:
        return None


class TableGeoProvider(GeoProvider):
    """Exact-IP mapping table (offline testing + curated datasets)."""

    def __init__(self, table: Mapping[str, Mapping[str, object]]):
        self._table = {
            str(k).strip(): v for k, v in dict(table).items()
        }

    def lookup(self, ip: str) -> Optional[GeoAnswer]:
        entry = self._table.get(str(ip).strip())
        if not isinstance(entry, Mapping):
            return None
        return _answer_from_entry(entry)


def _clamp(s: object, n: int = 128) -> str:
    """Clamp any provider value to a safe string length (never raises)."""
    try:
        text = "" if s is None else str(s)
    except Exception:
        text = ""
    return text[:n]


def _answer_from_entry(entry: Mapping) -> Optional[GeoAnswer]:
    cc = _clamp(entry.get("country_code", "XX"), 2).upper() or "XX"
    return GeoAnswer(
        country=_clamp(entry.get("country", "Unknown")) or "Unknown",
        city=_clamp(entry.get("city", "Unknown")) or "Unknown",
        country_code=cc if len(cc) == 2 else "XX",
        asn=_asn_or_none(entry.get("asn")),
    )


def _asn_or_none(value) -> Optional[int]:
    try:
        n = int(str(value).strip())
        return n if 0 < n < 2 ** 32 else None
    except (TypeError, ValueError):
        return None


def flag_from_cc(cc: str) -> str:
    """Regional-indicator flag emoji for a 2-letter code, else globe."""
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc)


def annotate_resolved(nodes, *, provider: GeoProvider,
                      resolver: Optional[Resolver] = None) -> list:
    """Annotate Nodes that carry ``endpoint.resolved_ip`` (from Resolver).

    - fills ``node.geo`` via the provider (degrades to Unknown cleanly)
    - fills ``node.output_name`` prefix flag/country/city tokens; keeps
      any existing name suffix
    - deterministic; does NOT re-resolve (Phase separation: DNS happened
      in the Resolver stage; ``resolver`` arg is accepted for API
      symmetry but unused unless resolved_ip is missing)
    """
    out = []
    for node in nodes:
        geo = None
        ip = node.endpoint.resolved_ip
        if not ip and resolver is not None and not _is_literal_host(node.endpoint.host):
            rec = resolver.resolve(node.endpoint.host, node.endpoint.port)
            if rec.ok and rec.all_ips:
                ip = rec.all_ips[0]
                node = _with_resolved(node, ip)
        if ip:
            try:
                answer = provider.lookup(ip)
            except Exception:
                answer = None  # provider failure degrades, never crashes
            geo = _geo_from_answer(answer)
        else:
            geo = GeoInfo()
        node = node.with_geo(geo)
        node = _apply_geo_name(node, geo)
        out.append(node)
    return out


def _is_literal_host(host: str) -> bool:
    from .resolver import _is_literal

    return _is_literal(host)


def _with_resolved(node: Node, ip: str) -> Node:
    from dataclasses import replace

    ep = replace(node.endpoint, resolved_ip=ip)
    return replace(node, endpoint=ep)


def _geo_from_answer(answer: Optional[GeoAnswer]) -> GeoInfo:
    if answer is None:
        return GeoInfo()
    return GeoInfo(
        country=answer.country,
        city=answer.city,
        country_code=answer.country_code,
        flag=flag_from_cc(answer.country_code),
    )


def _apply_geo_name(node: Node, geo: GeoInfo) -> Node:
    from dataclasses import replace

    base = node.output_name or ""
    prefix = f"{geo.flag}{geo.country}·{geo.city}"
    name = f"{prefix}|{base}" if base else prefix
    return replace(node, output_name=name[:256])
