# -*- coding: utf-8 -*-
"""Deterministic text output generation (Phase 12).

Turns the canonical, already-ranked records of Phases 1-11 into the exact
text artifacts the legacy pipeline published. PURE data -> text: no
network, no name resolution, no filesystem write, no process, no
environment, no clock, no entropy. Nothing here writes a file; a later
phase may persist an :class:`OutputBundle`.

----------------------------------------------------------------------
LEGACY OUTPUT CONTRACT (extracted; every rule below is evidence-backed)
----------------------------------------------------------------------
Artifacts produced by the legacy pipeline (``multi_bot/engine.py``,
``multi_bot/runner.py``, ``update_hub.py``):

    all.txt                        every kept link, one per line
    all_b64.txt                    base64 of those links
    Config/{proto}.txt             per protocol group
    transports/{trans}.txt         per transport group
    Country/{name}.txt             per country group
    Subscription/plain/guardN.txt  per source batch (same line format)
    Subscription/base64/guardN.txt base64 of one batch
    Subscription/ultra_fast.txt    ping <= 200 ms tier
    Subscription/good_ping.txt     ping <= 500 ms tier
    README.md / Config/README.md / Country/README.md / Subscription/README.md

Verified facts about the committed artifacts (byte-level inspection):

* plain text files use **CRLF** and end with exactly **one trailing
  CRLF**; an empty set still yields the 2-byte file ``b"\\r\\n"``
  (``Subscription/ultra_fast.txt`` is exactly that, because the legacy
  tier was always empty);
* base64 files contain **no line breaks at all** and the encoded payload
  is joined with **LF and has no trailing LF** (proved byte-for-byte:
  ``base64.b64decode(Subscription/base64/guard1.txt)`` equals
  ``Subscription/plain/guard1.txt`` with CRLF->LF and the trailing
  newline removed);
* a group file is a stable FILTER of the global order, never a re-sort:
  ``Config/vless.txt`` is exactly the ``vless://`` subsequence of
  ``all.txt`` in the same order;
* the displayed name is the legacy brand template
  ``👉🆔@{tag}📡{flag}®️{country}©️{city}🅿️ping:{ping:.1f}ms⚡️{arch}``
  with ``tag = "Goodbaye_filtering"``; any input fragment is DISCARDED
  and replaced by it;
* for every scheme except vmess the fragment is percent-encoded with
  ``quote(name)`` (``@`` -> ``%40``, ``:`` -> ``%3A``, emoji -> ``%F0%9F..``);
  for vmess the brand name is written RAW into the JSON field ``ps`` and
  the JSON is re-encoded to base64 (a legacy asymmetry, preserved);
* if the vmess body cannot be decoded, the ORIGINAL link is emitted
  unchanged (legacy's ``except: return raw_link``);
* a failed GeoIP lookup was branded ``📡🌐®️Unknown©️Unknown`` (legacy's
  default dict), so the explicit sentinels are part of the contract.

Deliberate separations (mandated by this phase's brief, not silent fixes):
grouping uses the canonical Phase 1 enums with an explicit legacy-name
mapping instead of legacy substring matching; country comes from Phase 6
``GeoInfo`` instead of parsing the branded name back out of the text;
ordering comes from Phase 11 instead of re-deriving it.

INPUT: the caller passes Phase 11's ranked records (a
:class:`RankingResult`, or ``RankedItem`` / ``(Node, ScoreOutcome)``
records). Output renders exactly the entries it is given - it never
re-filters, re-ranks, de-duplicates, re-measures or re-scores, because
eligibility is Phase 10/11's decision. A ``RankingResult``'s unranked
records become an audit tuple only and are never rendered as links.

NO FABRICATION: every displayed value is read from real Phase 1-11 data.
Legacy invented ``ping=150.0``/``jitter=10.0`` for VLESS/VMess and
``jitter=10.0`` when the second probe failed; those values are never
produced here. Missing ping/arch is OMITTED by default (an explicit
``"unknown"`` policy is available); missing geo falls back to the legacy
``Unknown``/``🌐`` sentinels, never to invented geography.

INJECTION SAFETY: the link body is never escaped or rewritten (the legacy
format forbids it) but a body containing a control character (CR/LF/NUL/
C0/DEL) is REFUSED with :class:`UnsafeOutputTextError` rather than being
emitted into a line-oriented file. The brand name reaches the fragment
through ``quote()`` and the vmess JSON through ``json.dumps``, so a
hostile country/city/path/``protocol_fields`` value cannot break a line
either way.

SECRET SAFETY: config links inherently carry credentials (legacy
contract), so no new exposure is created - but no credential ever reaches
an exception message: errors describe the field and the reason only.
"""
from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import quote

from hubcore.enums import Protocol, Transport
from hubcore.geo import flag_from_cc
from hubcore.latency import LatencyKind
from hubcore.model import Node
from hubcore.ranking import RankedItem, RankingResult
from hubcore.scoring import ScoreOutcome

__all__ = [
    "CRLF",
    "LF",
    "CHANNEL_TAG",
    "UNKNOWN_TEXT",
    "DEFAULT_FLAG",
    "ULTRA_FAST_MS",
    "GOOD_PING_MS",
    "UNKNOWN_COUNTRY_KEYS",
    "UNKNOWN_COUNTRY_CODE",
    "LEGACY_PROTOCOL_FILE",
    "LEGACY_TRANSPORT_FILE",
    "PATH_ALL",
    "PATH_ALL_BASE64",
    "PATH_CONFIG_DIR",
    "PATH_TRANSPORT_DIR",
    "PATH_COUNTRY_DIR",
    "PATH_ULTRA_FAST",
    "PATH_GOOD_PING",
    "OutputPolicy",
    "CountryGroup",
    "OutputBundle",
    "OutputInputError",
    "OutputPolicyError",
    "UnsafeOutputTextError",
    "build_outputs",
    "geo_flag",
    "geo_country",
    "geo_city",
    "arch_label",
    "display_ping_ms",
    "brand_name",
    "render_link",
    "render_payload",
    "render_text",
    "render_base64",
    "render_ping_tiers",
    "group_by_protocol",
    "group_by_transport",
    "group_by_country",
    "country_filename",
]

# ---- separators / sentinels (verified against the committed artifacts) ----
CRLF = "\r\n"
LF = "\n"
CHANNEL_TAG = "Goodbaye_filtering"      # legacy CHANNEL_TAG constant
UNKNOWN_TEXT = "Unknown"                # legacy GeoIP default sentinel
DEFAULT_FLAG = "🌐"                     # legacy GeoIP default sentinel
UNKNOWN_COUNTRY_CODE = "XX"             # legacy GeoIP unknown country code
DEFAULT_PING_DECIMALS = 1               # legacy f"{ping:.1f}"
ULTRA_FAST_MS = 200.0                   # legacy tier threshold (<=)
GOOD_PING_MS = 500.0                    # legacy tier threshold (<=)
VMESS_NAME_FIELD = "ps"                 # legacy rename_node field

# ---- legacy artifact layout (relative paths; this phase never writes) ----
PATH_ALL = "all.txt"
PATH_ALL_BASE64 = "all_b64.txt"
PATH_CONFIG_DIR = "Config"
PATH_TRANSPORT_DIR = "transports"
PATH_COUNTRY_DIR = "Country"
PATH_ULTRA_FAST = "Subscription/ultra_fast.txt"
PATH_GOOD_PING = "Subscription/good_ping.txt"

# ---- explicit canonical-enum -> legacy filename mappings --------------
LEGACY_PROTOCOL_FILE = {
    Protocol.VLESS: "vless",
    Protocol.VMESS: "vmess",
    Protocol.SHADOWSOCKS: "ss",       # legacy file name for shadowsocks
    Protocol.TROJAN: "trojan",
    Protocol.HYSTERIA2: "hysteria2",  # legacy wrote hy2:// links here too
    Protocol.SOCKS5: "socks",         # legacy: socks/socks5 -> "socks"
    Protocol.OTHER: "other",
}

# legacy ``extract_transport`` only ever wrote these four; everything it
# could not recognise fell into "other" and was NOT written to disk.
# Canonical HTTP2/QUIC/UNKNOWN keep that behaviour (no invented files, and
# no guessing KCP->QUIC or vice versa).
LEGACY_TRANSPORT_FILE = {
    Transport.TCP: "tcp",
    Transport.WS: "ws",
    Transport.GRPC: "grpc",
    Transport.XHTTP: "xhttp",
}

# legacy runner.py skipped country groups whose name matched these
# (case-insensitive here so both legacy filename schemes behave the same)
UNKNOWN_COUNTRY_KEYS = ("global", "other", "unknown")


# ----------------------------------------------------------------------
# errors (never carry a URL, host, uuid or credential)
# ----------------------------------------------------------------------
class OutputInputError(ValueError):
    """Malformed output input (bad entry shape, unrenderable node)."""


class OutputPolicyError(ValueError):
    """Unsupported OutputPolicy value."""


class UnsafeOutputTextError(ValueError):
    """A field would inject a control character into a line-oriented file."""


# ----------------------------------------------------------------------
# policy / records
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class OutputPolicy:
    """The approved output contract, named in exactly one place.

    Defaults reproduce the committed legacy artifacts byte-for-byte.
    ``ping_sources`` default is ``("measured",)``: only a Phase 9 MEASURED
    sample may be displayed. The legacy pipeline displayed a bare TCP
    connect time; that is reachable ONLY through the explicit
    ``("measured", "tcp_connect")`` setting, never silently.
    """

    line_separator: str = CRLF            # plain text files
    trailing_newline: bool = True         # legacy: join + one separator
    payload_separator: str = LF           # base64 payload join (no trailing)
    channel_tag: str = CHANNEL_TAG
    ping_sources: tuple = ("measured",)
    missing_ping: str = "omit"            # omit | unknown
    missing_arch: str = "omit"            # omit | unknown
    country_filename: str = "sanitized"   # sanitized | alnum_lower
    ping_decimals: int = DEFAULT_PING_DECIMALS
    vmess_name_field: str = VMESS_NAME_FIELD
    ultra_fast_ms: float = ULTRA_FAST_MS
    good_ping_ms: float = GOOD_PING_MS


@dataclass(frozen=True)
class CountryGroup:
    """One country group: legacy file name + its rendered text."""

    filename: str      # without ".txt"
    path: str          # "Country/{filename}.txt"
    country: str       # display name (raw, unsanitised)
    flag: str
    count: int
    text: str


@dataclass(frozen=True)
class OutputBundle:
    """All generated artifacts as in-memory text (nothing is written)."""

    policy: OutputPolicy
    all_text: str
    all_base64: str
    by_protocol: dict          # "Config/vless.txt" -> text
    by_transport: dict         # "transports/ws.txt" -> text
    by_country: tuple          # tuple[CountryGroup, ...]
    ping_tiers: dict           # "Subscription/ultra_fast.txt" -> text
    counts: dict
    unranked: tuple            # ((status, detail), ...) audit only — no links


@dataclass(frozen=True)
class _Entry:
    """Internal flat entry: the two objects plus optional rank metadata."""

    node: Node
    outcome: ScoreOutcome
    rank: Optional[int] = None


# ----------------------------------------------------------------------
# policy validation
# ----------------------------------------------------------------------
_ALLOWED_PING_SOURCES = ("measured", "tcp_connect")


def _validate_policy(policy: OutputPolicy) -> None:
    if not isinstance(policy, OutputPolicy):
        raise OutputPolicyError(
            f"policy must be an OutputPolicy (got {type(policy).__name__})")
    if policy.line_separator not in (CRLF, LF):
        raise OutputPolicyError("line_separator must be CRLF or LF")
    if policy.payload_separator not in (CRLF, LF):
        raise OutputPolicyError("payload_separator must be CRLF or LF")
    if policy.missing_ping not in ("omit", "unknown"):
        raise OutputPolicyError(
            f"unsupported missing_ping policy: {policy.missing_ping!r}")
    if policy.missing_arch not in ("omit", "unknown"):
        raise OutputPolicyError(
            f"unsupported missing_arch policy: {policy.missing_arch!r}")
    if policy.country_filename not in ("sanitized", "alnum_lower"):
        raise OutputPolicyError(
            f"unsupported country_filename policy: {policy.country_filename!r}")
    if not policy.ping_sources:
        raise OutputPolicyError("ping_sources must not be empty")
    for source in policy.ping_sources:
        if source not in _ALLOWED_PING_SOURCES:
            raise OutputPolicyError(f"unsupported ping source: {source!r}")
    if not isinstance(policy.ping_decimals, int) or isinstance(policy.ping_decimals, bool) \
            or not 0 <= policy.ping_decimals <= 6:
        raise OutputPolicyError("ping_decimals must be an int in 0..6")


# ----------------------------------------------------------------------
# field readers (never fabricate, never recompute a Phase 10 value)
# ----------------------------------------------------------------------
def geo_flag(node: Node) -> str:
    """Flag emoji: explicit GeoInfo flag, else derived from country code.

    The legacy Unknown sentinel is preserved: country code ``XX`` (and any
    non-2-letter / non-alphabetic code) yields the globe, NOT the regional
    indicators for X.
    """
    geo = getattr(node, "geo", None)
    if geo is None:
        return DEFAULT_FLAG
    flag = str(getattr(geo, "flag", "") or "").strip()
    if flag and flag != DEFAULT_FLAG:
        return flag
    code = str(getattr(geo, "country_code", "") or "").strip().upper()
    if len(code) == 2 and code.isalpha() and code != UNKNOWN_COUNTRY_CODE:
        return flag_from_cc(code)
    return DEFAULT_FLAG


def geo_country(node: Node) -> str:
    """Country display name from Phase 6 GeoInfo (legacy Unknown sentinel)."""
    geo = getattr(node, "geo", None)
    if geo is None:
        return UNKNOWN_TEXT
    return str(getattr(geo, "country", "") or "").strip() or UNKNOWN_TEXT


def geo_city(node: Node) -> str:
    """City display name from Phase 6 GeoInfo (legacy Unknown sentinel)."""
    geo = getattr(node, "geo", None)
    if geo is None:
        return UNKNOWN_TEXT
    return str(getattr(geo, "city", "") or "").strip() or UNKNOWN_TEXT


def arch_label(outcome: ScoreOutcome) -> Optional[str]:
    """The architecture label Phase 10 already recorded (never recomputed).

    Phase 10 stores it on ``ScoreOutcome.components["arch_label"]`` using
    the legacy label table verbatim, so output reads it instead of
    duplicating scoring logic. Missing label -> None (policy decides).
    """
    components = getattr(outcome, "components", None)
    if not isinstance(components, dict):
        return None
    label = components.get("arch_label")
    if label is None:
        return None
    text = str(label).strip()
    return text or None


def _sample_ms(node: Node, source: str) -> Optional[float]:
    """One kind-checked latency sample value, or None (kinds never mixed)."""
    if source == "measured":
        sample = node.measured_latency
        if sample is None or sample.kind is not LatencyKind.MEASURED:
            return None
    elif source == "tcp_connect":
        sample = node.tcp_connect
        if sample is None or sample.kind is not LatencyKind.TCP_CONNECT:
            return None
    else:
        return None
    value = sample.value_ms
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0:
        return None
    return number


def display_ping_ms(node: Node, policy: Optional[OutputPolicy] = None) -> Optional[float]:
    """Latency to display, by explicit precedence (None != 0).

    Precedence is the order of ``policy.ping_sources``; the default is
    MEASURED only. A PROTOCOL_HANDSHAKE sample is never displayed, and a
    value is never substituted, rounded or invented.
    """
    policy = policy or OutputPolicy()
    for source in policy.ping_sources:
        value = _sample_ms(node, source)
        if value is not None:
            return value
    return None


# ----------------------------------------------------------------------
# branding
# ----------------------------------------------------------------------
def brand_name(node: Node, outcome: ScoreOutcome,
               policy: Optional[OutputPolicy] = None) -> str:
    """The legacy brand name (markers, and missing segments omitted)."""
    policy = policy or OutputPolicy()
    parts = [
        f"👉🆔@{policy.channel_tag}",
        f"📡{geo_flag(node)}",
        f"®️{geo_country(node)}",
        f"©️{geo_city(node)}",
    ]
    ping = display_ping_ms(node, policy)
    if ping is not None:
        parts.append(f"🅿️ping:{ping:.{policy.ping_decimals}f}ms")
    elif policy.missing_ping == "unknown":
        parts.append(f"🅿️ping:{UNKNOWN_TEXT}")
    label = arch_label(outcome)
    if label:
        parts.append(f"⚡️{label}")
    elif policy.missing_arch == "unknown":
        parts.append(f"⚡️{UNKNOWN_TEXT}")
    return "".join(parts)


# ----------------------------------------------------------------------
# link rendering
# ----------------------------------------------------------------------
def _link_body(node: Node) -> str:
    """The raw URL without its fragment; refuses control characters."""
    raw = str(node.raw_url or "")
    body = raw.split("#", 1)[0]
    if not body:
        raise OutputInputError("node has no raw_url to render")
    for ch in body:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise UnsafeOutputTextError(
                "node raw_url contains a control character")
    return body


def _vmess_body_with_name(body: str, name: str, policy: OutputPolicy) -> Optional[str]:
    """Legacy vmess rename: decode JSON, set the name field, re-encode."""
    if not body:
        return None
    padding = "=" * (-len(body) % 4)
    try:
        decoded = base64.b64decode(body + padding)
        data = json.loads(decoded.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    updated = dict(data)
    updated[policy.vmess_name_field] = name
    try:
        text = json.dumps(updated, ensure_ascii=False)
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    except Exception:
        return None


def render_link(node: Node, outcome: ScoreOutcome,
                policy: Optional[OutputPolicy] = None) -> str:
    """One output line: the link with the brand name as its fragment."""
    policy = policy or OutputPolicy()
    body = _link_body(node)
    name = brand_name(node, outcome, policy)
    if node.protocol is Protocol.VMESS:
        # legacy strips the "vmess://" prefix BEFORE base64-decoding the
        # body; passing the prefixed string would always fail to decode
        # and silently fall back to the un-renamed original link
        prefix = "vmess://"
        payload = body[len(prefix):] if body[:len(prefix)].lower() == prefix else body
        encoded = _vmess_body_with_name(payload, name, policy)
        if encoded is None:
            # legacy fallback: emit the original link unchanged
            return str(node.raw_url)
        return f"{prefix}{encoded}"
    return f"{body}#{quote(name, safe='/')}"


def _entries(entries) -> list:
    """Normalise any accepted entry form into flat _Entry records."""
    if isinstance(entries, _Entry):
        return [entries]
    try:
        iterator = iter(entries)
    except TypeError:
        raise OutputInputError("entries must be an iterable of output records")
    return [_as_entry(item) for item in iterator]


def _render(entries: Iterable, policy: OutputPolicy, *, trailing: bool) -> str:
    links = [render_link(e.node, e.outcome, policy) for e in _entries(entries)]
    separator = policy.line_separator if trailing else policy.payload_separator
    joined = separator.join(links)
    if trailing and policy.trailing_newline:
        return joined + policy.line_separator
    return joined


def render_text(entries: Iterable, policy: Optional[OutputPolicy] = None) -> str:
    """The plain-text file contract: join + exactly one trailing separator."""
    policy = policy or OutputPolicy()
    return _render(entries, policy, trailing=True)


def render_payload(entries: Iterable, policy: Optional[OutputPolicy] = None) -> str:
    """The payload the base64 artifacts encode: join, NO trailing separator."""
    policy = policy or OutputPolicy()
    return _render(entries, policy, trailing=False)


def render_base64(payload: str, policy: Optional[OutputPolicy] = None) -> str:
    """Base64 of a payload string (ASCII out, no line breaks, no trailing)."""
    policy = policy or OutputPolicy()
    _validate_policy(policy)
    if not isinstance(payload, str):
        raise OutputInputError("base64 payload must be text")
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


# ----------------------------------------------------------------------
# grouping (canonical enums; legacy file names; order preserved)
# ----------------------------------------------------------------------
def group_by_protocol(entries: Iterable) -> dict:
    """Protocol groups keyed by legacy file name, first-appearance order."""
    groups: dict = {}
    for entry in _entries(entries):
        key = LEGACY_PROTOCOL_FILE.get(entry.node.protocol, "other")
        groups.setdefault(key, []).append(entry)
    return groups


def group_by_transport(entries: Iterable) -> dict:
    """Transport groups; kinds legacy never wrote (h2/quic/unknown) omitted."""
    groups: dict = {}
    for entry in _entries(entries):
        key = LEGACY_TRANSPORT_FILE.get(entry.node.transport)
        if key is None:
            continue
        groups.setdefault(key, []).append(entry)
    return groups


def country_filename(country: str, policy: Optional[OutputPolicy] = None) -> str:
    """Legacy country file name (both historical schemes are implemented).

    ``sanitized``  = ``re.sub(r"[^\\w\\s-]", "", c).strip().replace(" ", "_")``
    (runner.py; Unicode-aware, so Persian names survive)
    ``alnum_lower`` = ``"".join(ch for ch in c if ch.isalnum()).lower()``
    (update_hub.py; the scheme that actually won the last write in the repo)
    """
    policy = policy or OutputPolicy()
    text = str(country or "").strip()
    if policy.country_filename == "sanitized":
        return re.sub(r"[^\w\s-]", "", text).strip().replace(" ", "_")
    return "".join(ch for ch in text if ch.isalnum()).lower()


def group_by_country(entries: Iterable,
                     policy: Optional[OutputPolicy] = None) -> tuple:
    """Country groups from Phase 6 GeoInfo, first-appearance order.

    Groups whose name is the legacy Global/Other/Unknown sentinel are not
    emitted (legacy runner.py behaviour); an empty sanitised name is
    hardened to the Unknown sentinel instead of producing a ".txt"/hidden
    file name.
    """
    policy = policy or OutputPolicy()
    buckets: dict = {}
    for entry in _entries(entries):
        country = geo_country(entry.node)
        name = country_filename(country, policy)
        if not name:
            name = UNKNOWN_TEXT
        if name.lower() in UNKNOWN_COUNTRY_KEYS:
            continue
        bucket = buckets.get(name)
        if bucket is None:
            buckets[name] = {"country": country,
                             "flag": geo_flag(entry.node),
                             "entries": [entry]}
        else:
            bucket["entries"].append(entry)
    groups = []
    for name, bucket in buckets.items():
        links = bucket["entries"]
        groups.append(CountryGroup(
            filename=name,
            path=f"{PATH_COUNTRY_DIR}/{name}.txt",
            country=bucket["country"],
            flag=bucket["flag"],
            count=len(links),
            text=render_text(links, policy),
        ))
    return tuple(groups)


def render_ping_tiers(entries: Iterable,
                      policy: Optional[OutputPolicy] = None) -> dict:
    """Legacy ping tiers (``<=`` thresholds); nodes with no ping are absent."""
    policy = policy or OutputPolicy()
    ultra, good = [], []
    for entry in _entries(entries):
        ping = display_ping_ms(entry.node, policy)
        if ping is None:
            continue
        if ping <= policy.ultra_fast_ms:
            ultra.append(entry)
        if ping <= policy.good_ping_ms:
            good.append(entry)
    return {
        PATH_ULTRA_FAST: render_text(ultra, policy),
        PATH_GOOD_PING: render_text(good, policy),
    }


# ----------------------------------------------------------------------
# input normalisation
# ----------------------------------------------------------------------
def _as_entry(item) -> _Entry:
    if isinstance(item, _Entry):
        return item
    if isinstance(item, RankedItem):
        if not isinstance(item.node, Node) or not isinstance(item.outcome, ScoreOutcome):
            raise OutputInputError("RankedItem carries an unexpected payload")
        return _Entry(node=item.node, outcome=item.outcome, rank=item.rank)
    if isinstance(item, (tuple, list)) and len(item) == 2:
        node, outcome = item
        if not isinstance(node, Node) or not isinstance(outcome, ScoreOutcome):
            raise OutputInputError(
                "each entry must be a (Node, ScoreOutcome) pair")
        return _Entry(node=node, outcome=outcome)
    raise OutputInputError(
        "output entries must be RankedItem records or (Node, ScoreOutcome) pairs")


def _normalise(source) -> tuple:
    """Accept a RankingResult or an iterable of RankedItem/pairs."""
    if isinstance(source, RankingResult):
        entries = [_as_entry(item) for item in source.ranked]
        unranked = tuple((item.status, item.detail) for item in source.unranked)
        return entries, unranked
    try:
        iterator = iter(source)
    except TypeError:
        raise OutputInputError(
            "output input must be a RankingResult or an iterable of entries")
    entries = []
    for item in iterator:
        entries.append(_as_entry(item))
    return entries, ()


# ----------------------------------------------------------------------
# the bundle
# ----------------------------------------------------------------------
def build_outputs(source, policy: Optional[OutputPolicy] = None) -> OutputBundle:
    """Render every legacy text artifact from ranked canonical records.

    Pure and deterministic: the same input always yields byte-identical
    text. Ordering is the caller's (Phase 11's) order - nothing is
    re-sorted, re-ranked, de-duplicated, re-measured or written.
    """
    policy = policy or OutputPolicy()
    _validate_policy(policy)
    entries, unranked = _normalise(source)

    by_protocol = {
        f"{PATH_CONFIG_DIR}/{key}.txt": render_text(group, policy)
        for key, group in group_by_protocol(entries).items()
    }
    by_transport = {
        f"{PATH_TRANSPORT_DIR}/{key}.txt": render_text(group, policy)
        for key, group in group_by_transport(entries).items()
    }
    countries = group_by_country(entries, policy)
    tiers = render_ping_tiers(entries, policy)

    status_counts: dict = {}
    for status, _detail in unranked:
        status_counts[status] = status_counts.get(status, 0) + 1

    counts = {
        "nodes": len(entries),
        "protocols": {key: len(group)
                      for key, group in group_by_protocol(entries).items()},
        "transports": {key: len(group)
                       for key, group in group_by_transport(entries).items()},
        "countries": {group.filename: group.count for group in countries},
        "ultra_fast": len([1 for entry in entries
                           if _in_tier(entry.node, policy, policy.ultra_fast_ms)]),
        "good_ping": len([1 for entry in entries
                          if _in_tier(entry.node, policy, policy.good_ping_ms)]),
        "unranked": len(unranked),
        "unranked_by_status": dict(sorted(status_counts.items())),
    }

    return OutputBundle(
        policy=policy,
        all_text=render_text(entries, policy),
        all_base64=render_base64(render_payload(entries, policy), policy),
        by_protocol=by_protocol,
        by_transport=by_transport,
        by_country=countries,
        ping_tiers=tiers,
        counts=counts,
        unranked=unranked,
    )


def _in_tier(node: Node, policy: OutputPolicy, threshold: float) -> bool:
    ping = display_ping_ms(node, policy)
    return ping is not None and ping <= threshold
