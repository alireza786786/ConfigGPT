# -*- coding: utf-8 -*-
"""Source ingestion layer (Phase 3): feeds raw config text to Phase 2
parsers and attaches source metadata to every parsed Node.

Scope (per approved plan):
- source ingestion of local files / raw text (NO network fetching here;
  URL origins are metadata only)
- error containment: a malformed line never crashes the pipeline
- preservation of source metadata (origin, line number, content hash)
- key-aware views built on Phase 1 ``endpoint_key`` / ``config_key``
  (indexing only; dedup policy itself is a later phase)

Out of scope (later phases): full dedup policy, DNS, GeoIP, network
validation, latency/jitter, scoring, output redesign, Telegram, Actions.

Security: no eval/exec/subprocess; error records carry line numbers and
short reason codes, never raw credentials or full raw lines.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Iterable, Optional
from urllib.parse import urlparse

from hubcore.identity import config_key, endpoint_key
from hubcore.model import Node

from .parsing import LengthLimitError, ParseError, safe_parse_url

__all__ = [
    "SourceKind",
    "SourceOrigin",
    "IngestError",
    "IngestedNode",
    "IngestStats",
    "IngestResult",
    "SourceIngestor",
    "endpoint_index",
    "config_index",
]

MAX_FILE_BYTES = 32 * 1024 * 1024      # 32 MiB cap for one local source
MAX_LINE_CHARS = 8192                  # mirrors parsing MAX_URL_LEN
REASON_OTHER = "other"


@unique
class SourceKind(Enum):
    """Where a source came from. Network fetch is NOT in Phase 3."""

    LOCAL_FILE = "local_file"
    RAW_TEXT = "raw_text"
    URL = "url"          # metadata only in Phase 3; fetch belongs to Phase 4


@dataclass(frozen=True, slots=True)
class SourceOrigin:
    """Immutable description of one source (name/kind/location)."""

    name: str
    kind: SourceKind
    location: str = ""

    def __post_init__(self):
        object.__setattr__(self, "name", (self.name or "").strip() or "unnamed")
        object.__setattr__(self, "location", (self.location or "").strip())
        if self.kind is SourceKind.URL and self.location:
            parsed = urlparse(self.location)
            if parsed.scheme not in ("http", "https"):
                # keep the origin but mark it safe: only http(s) may be
                # fetched in later phases
                object.__setattr__(self, "location", "")
        if not isinstance(self.kind, SourceKind):
            raise ValueError("kind must be a SourceKind")

    def with_location(self, location: str) -> "SourceOrigin":
        """Return a copy with a resolved location (e.g. absolute path)."""
        return SourceOrigin(name=self.name, kind=self.kind, location=location)


@dataclass(frozen=True, slots=True)
class IngestError:
    """One rejected line. Carries NO raw line content (credential-safe)."""

    origin_name: str
    line_no: int
    reason: str          # short code: 'too_long', 'no_scheme', 'parse', ...

    def __post_init__(self):
        r = (self.reason or REASON_OTHER)[:64]
        object.__setattr__(self, "reason", r)

    def __str__(self) -> str:
        return f"[{self.origin_name}] line {self.line_no}: {self.reason}"


@dataclass(frozen=True, slots=True)
class IngestedNode:
    """A parsed Node plus where it came from."""

    node: Node
    origin: SourceOrigin
    line_no: int
    line_hash: str       # sha256 hex[:16] of the raw line (no raw text kept)

    def __post_init__(self):
        h = self.line_hash or ""
        if len(h) > 64:
            h = h[:64]
        object.__setattr__(self, "line_hash", h)


@dataclass
class IngestStats:
    """Counters for one ingestion run."""

    lines_seen: int = 0
    lines_parsed: int = 0
    lines_rejected: int = 0
    by_protocol: dict = field(default_factory=dict)

    def note_protocol(self, proto_name: str) -> None:
        self.by_protocol[proto_name] = self.by_protocol.get(proto_name, 0) + 1

    def as_dict(self) -> dict:
        return {
            "lines_seen": self.lines_seen,
            "lines_parsed": self.lines_parsed,
            "lines_rejected": self.lines_rejected,
            "by_protocol": dict(sorted(self.by_protocol.items())),
        }


@dataclass
class IngestResult:
    """Everything one source (or batch) produced: nodes + errors + stats."""

    origin: SourceOrigin
    nodes: list = field(default_factory=list)      # list[IngestedNode]
    errors: list = field(default_factory=list)     # list[IngestError]
    stats: IngestStats = field(default_factory=IngestStats)

    @property
    def node_list(self) -> list:
        """Bare Node objects, in ingestion order."""
        return [w.node for w in self.nodes]

    def merged(self, other: "IngestResult") -> "IngestResult":
        """Combine two results (batch bookkeeping)."""
        if self.origin.name != other.origin.name:
            combined = SourceOrigin(
                name=f"{self.origin.name}+{other.origin.name}",
                kind=self.origin.kind,
                location="",
            )
        else:
            combined = self.origin
        # renumber line numbers when concatenating different sources
        offset = self.stats.lines_seen
        other_nodes = [
            IngestedNode(node=w.node, origin=w.origin,
                         line_no=w.line_no + offset, line_hash=w.line_hash)
            for w in other.nodes
        ]
        other_errors = [
            IngestError(origin_name=e.origin_name, line_no=e.line_no + offset,
                        reason=e.reason)
            for e in other.errors
        ]
        st = IngestStats(
            lines_seen=self.stats.lines_seen + other.stats.lines_seen,
            lines_parsed=self.stats.lines_parsed + other.stats.lines_parsed,
            lines_rejected=self.stats.lines_rejected + other.stats.lines_rejected,
        )
        st.by_protocol = dict(self.stats.by_protocol)
        for k, v in other.stats.by_protocol.items():
            st.by_protocol[k] = st.by_protocol.get(k, 0) + v
        return IngestResult(origin=combined,
                            nodes=self.nodes + other_nodes,
                            errors=self.errors + other_errors,
                            stats=st)


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()[:16]


def _split_source_lines(text: str) -> list:
    """BOM/CRLF-tolerant line split preserving order (no stripping here)."""
    if text.startswith("﻿"):
        text = text[1:]
    return text.splitlines()


class SourceIngestor:
    """Stateless ingestion front-end for the Phase 2 parsers."""

    def __init__(self, *, max_line_chars: int = MAX_LINE_CHARS,
                 max_file_bytes: int = MAX_FILE_BYTES):
        self.max_line_chars = max_line_chars
        self.max_file_bytes = max_file_bytes

    # ------------------------------------------------------------- text
    def ingest_text(self, text: str, origin: SourceOrigin) -> IngestResult:
        """Ingest raw multi-line text. Never raises for bad lines."""
        if not isinstance(text, str):
            text = ""
        result = IngestResult(origin=origin)
        for line_no, raw in enumerate(_split_source_lines(text), start=1):
            result.stats.lines_seen += 1
            line = raw.strip()
            if not line:
                continue
            if "://" not in line:
                result.errors.append(IngestError(origin.name, line_no, "no_scheme"))
                result.stats.lines_rejected += 1
                continue
            if len(line) > self.max_line_chars:
                result.errors.append(IngestError(origin.name, line_no, "too_long"))
                result.stats.lines_rejected += 1
                continue
            node = safe_parse_url(line)
            if node is None:
                result.errors.append(IngestError(origin.name, line_no, "parse"))
                result.stats.lines_rejected += 1
                continue
            result.nodes.append(IngestedNode(
                node=node, origin=origin, line_no=line_no,
                line_hash=_hash_line(line),
            ))
            result.stats.lines_parsed += 1
            result.stats.note_protocol(node.protocol.name)
        return result

    # ------------------------------------------------------------- file
    def ingest_file(self, path: str, origin_name: Optional[str] = None) -> IngestResult:
        """Ingest a local UTF-8 text file (one config per line).

        Size-capped; oversize is an error result, never a crash and never
        a partial silent truncation of the error record.
        """
        name = origin_name or path
        origin = SourceOrigin(name=name, kind=SourceKind.LOCAL_FILE,
                              location=str(path))
        empty = IngestResult(origin=origin)
        try:
            import os

            if not os.path.isfile(path):
                empty.errors.append(IngestError(origin.name, 0, "file_missing"))
                return empty
            size = os.path.getsize(path)
            if size > self.max_file_bytes:
                empty.errors.append(IngestError(origin.name, 0, "file_too_big"))
                return empty
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(self.max_file_bytes + 1)
            if len(text) > self.max_file_bytes:
                empty.errors.append(IngestError(origin.name, 0, "file_too_big"))
                return empty
        except OSError as exc:
            # never leak path internals beyond the caller-provided path
            empty.errors.append(IngestError(origin.name, 0, "file_read_error"))
            empty.stats.lines_rejected += 1
            del exc
            return empty
        return self.ingest_text(text, origin)

    # ------------------------------------------------------------ batch
    def ingest_many(self, items: Iterable) -> IngestResult:
        """Ingest many (origin, text) pairs into one combined result."""
        combined = None
        for origin, text in items:
            res = self.ingest_text(text, origin)
            combined = res if combined is None else combined.merged(res)
        if combined is None:
            combined = IngestResult(origin=SourceOrigin(name="empty", kind=SourceKind.RAW_TEXT))
        return combined

    # ------------------------------------------------------------- url
    def ingest_url(self, url: str, *, fetcher=None, origin_name=None) -> IngestResult:
        """Fetch (https-only via :class:`hubcore.fetch.Fetcher`) and ingest.

        Network access is EXPLICIT: a fetcher instance must be provided
        (or constructed by the caller); this method never spawns one
        implicitly, so tests and offline runs stay offline by default.
        All fetch failures become IngestError records ('fetch_blocked',
        'fetch_network', 'fetch_size', 'fetch_timeout', 'fetch_error') —
        never raw exception text, never response bodies.
        """
        from .fetch import (
            FetchBlockedError,
            FetchError,
            FetchNetworkError,
            FetchSizeError,
            FetchTimeoutError,
        )

        name = origin_name or url[:120]
        origin = SourceOrigin(name=name, kind=SourceKind.URL, location=url)
        empty = IngestResult(origin=origin)
        if fetcher is None:
            empty.errors.append(IngestError(origin.name, 0, "fetch_no_fetcher"))
            return empty
        try:
            result = fetcher.fetch(url)
        except FetchBlockedError:
            empty.errors.append(IngestError(origin.name, 0, "fetch_blocked"))
            return empty
        except FetchTimeoutError:
            empty.errors.append(IngestError(origin.name, 0, "fetch_timeout"))
            return empty
        except FetchSizeError:
            empty.errors.append(IngestError(origin.name, 0, "fetch_size"))
            return empty
        except FetchNetworkError:
            empty.errors.append(IngestError(origin.name, 0, "fetch_network"))
            return empty
        except FetchError:
            empty.errors.append(IngestError(origin.name, 0, "fetch_error"))
            return empty
        except Exception:
            empty.errors.append(IngestError(origin.name, 0, "fetch_error"))
            return empty
        return self.ingest_text(result.text, origin)


# ------------------------------------------------------------------ views

def endpoint_index(nodes: Iterable) -> dict:
    """Group nodes by Phase 1 ``endpoint_key`` (view only; NOT dedup)."""
    idx = defaultdict(list)
    for w in nodes:
        node = w.node if isinstance(w, IngestedNode) else w
        idx[endpoint_key(node)].append(node)
    return dict(idx)


def config_index(nodes: Iterable) -> dict:
    """Group nodes by Phase 1 ``config_key`` (view only; NOT dedup)."""
    idx = defaultdict(list)
    for w in nodes:
        node = w.node if isinstance(w, IngestedNode) else w
        idx[config_key(node)].append(node)
    return dict(idx)


# unused-import guard: ParseError/LengthLimitError are re-exported for callers
_ = (ParseError, LengthLimitError)
