# -*- coding: utf-8 -*-
"""Deduplication policy (Phase 5) built on Phase 1 identity keys.

PRIME DIRECTIVE (per approved constraint): a node is NEVER dropped just
because another node shares its host:port / ip:port. Two configurations
may share an endpoint yet differ in uuid/password, path, serviceName,
SNI, transport, security, flow, Reality fields, or any
protocol-specific field — they are DIFFERENT configs and all survive.

What is actually a duplicate:
- identical ``config_key`` (Phase 1) after host canonicalization
  (case-folding, trailing-dot strip, bracketed/IPv6 textual normalization
  when unambiguous). DNS-based resolution identity is explicitly OUT of
  scope here (Phase 6+ resolver gate); identity stays textual.

Policy (deterministic):
- keep order = input order; among identical config_keys the FIRST
  occurrence is kept ("first wins"); later ones are reported as dropped.
- ties inside the same occurrence group (e.g. two sources ingested so
  the same line appears twice with different metadata) still keep the
  strictly-first input occurrence.
- metrics only (latency/score/geo) never influence identity, so a
  re-measured node keeps its slot.

Performance: single pass with a dict/set on the dedup key -> O(n).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from hubcore.identity import config_key, endpoint_key
from hubcore.model import Node

from .ingest import IngestedNode, IngestResult

__all__ = [
    "DedupPolicy",
    "dedup_key",
    "canonical_host",
    "DedupOutcome",
    "dedup_nodes",
    "dedup_result",
    "dedup_counts",
]


def canonical_host(host: str) -> str:
    """Textual host canonicalization (NO DNS).

    - lowercase, strip one trailing dot (FQDN form)
    - strip brackets from bracketed IPv6 text
    - lowercase IPv6 hex letters via a safe textual pass only when the
      host looks like a bare IPv6 (colons present)
    """
    h = (host or "").strip().lower()
    if not h:
        return h
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h:  # bare IPv6 text: normalize hex case, keep structure
        h = h.lower()
    if h.endswith("."):
        h = h[:-1]
    return h


def dedup_key(node: Node):
    """Phase 1 ``config_key`` with the endpoint host canonicalized.

    Everything else in the key is exactly Phase 1 semantics: protocol,
    credentials, TLS/transport material, flow, and the full
    ``protocol_fields`` payload. Measurement/naming never participate.
    """
    ep = node.endpoint
    ck = list(config_key(node))
    # config_key layout: (protocol, host, port, uuid, ...)
    ck[1] = canonical_host(ck[1])
    return tuple(ck)


@dataclass
class DedupPolicy:
    """Configuration of the dedup pass (values are the approved defaults)."""

    keep: str = "first"          # 'first' is the only policy in Phase 5


@dataclass
class DedupOutcome:
    """Result of one dedup pass: kept nodes + drop audit records."""

    kept: list = field(default_factory=list)          # list[IngestedNode]
    dropped: list = field(default_factory=list)       # list[IngestedNode]
    # key -> count of occurrences seen (kept + dropped)
    occurrences: dict = field(default_factory=dict)

    @property
    def kept_count(self) -> int:
        return len(self.kept)

    @property
    def dropped_count(self) -> int:
        return len(self.dropped)


def _wrap(item):
    """Accept IngestedNode wrappers or bare Nodes (bare => no metadata)."""
    if isinstance(item, IngestedNode):
        return item
    return IngestedNode(node=item, origin=None, line_no=-1, line_hash="")


def dedup_nodes(items: Iterable, *, policy: Optional[DedupPolicy] = None) -> DedupOutcome:
    """Single-pass, order-preserving, first-wins dedup.

    Accepts IngestedNode wrappers (metadata preserved on survivors) or
    bare Nodes. O(n) time, O(u) extra memory for unique keys.
    """
    policy = policy or DedupPolicy()
    if policy.keep != "first":  # future policies land here
        raise ValueError(f"unsupported keep policy: {policy.keep!r}")
    outcome = DedupOutcome()
    seen = set()
    for item in items:
        w = _wrap(item)
        key = dedup_key(w.node)
        outcome.occurrences[key] = outcome.occurrences.get(key, 0) + 1
        if key in seen:
            outcome.dropped.append(w)
        else:
            seen.add(key)
            outcome.kept.append(w)
    return outcome


def dedup_result(result: IngestResult, *, policy: Optional[DedupPolicy] = None) -> DedupOutcome:
    """Dedup an :class:`IngestResult` (works on Phase 3 ``merged`` too)."""
    return dedup_nodes(result.nodes, policy=policy)


def dedup_counts(outcome: DedupOutcome) -> dict:
    """Compact report: totals + top occurrence groups (audit view)."""
    multi = {k: v for k, v in outcome.occurrences.items() if v > 1}
    return {
        "kept": outcome.kept_count,
        "dropped": outcome.dropped_count,
        "unique_configs": len(outcome.occurrences),
        "groups_with_duplicates": len(multi),
        "max_occurrences": max(outcome.occurrences.values(), default=0),
    }
