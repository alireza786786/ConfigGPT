# -*- coding: utf-8 -*-
"""Deterministic ranking of scored nodes (Phase 11).

Orders Phase 10 :class:`ScoreOutcome` results into a ranked sequence and
extracts a top-N prefix. It is PURE: a total order computed only from
values already present on the input, with no I/O of any kind (no network,
no name resolution, no filesystem, no process spawning, no environment
lookup) and no nondeterministic source (no entropy draws, no system time
reads, no memory addresses, no reliance on dict/set iteration order or on
the caller's input order).

--------------------------------------------------------------------
LEGACY RANKING CONTRACT (extracted, not invented)
--------------------------------------------------------------------
``multi_bot/engine.py`` is the only legacy node-level scorer. Its
pipeline is, in order:

1. FILTER before ordering — ``test_pipeline`` returns ``None`` for any
   node whose probe failed or whose ``avg_ping >= MAX_FINAL_PING_MS``
   (500 ms); only survivors reach the list that is sorted. Eligibility is
   therefore decided BEFORE ordering, and a node with no usable
   measurement is never ranked. (Phase 10 already encodes that gate as
   ``status == "unscorable"`` / ``"insufficient_data"``.)
2. ORDER — ``tested.sort(key=lambda x: x["score"], reverse=True)``
   (engine.py line 264): **descending score, higher score first**. This
   is the legacy ordering contract and is preserved verbatim here.
3. No secondary key, no priority field, no top-N at the scored-node
   level: the only legacy ``[:N]`` is ``proxies[:3]`` in the sibling
   MTProto collector, applied to a latency-ascending list.

LEGACY_TIE_BREAKER = UNDEFINED.
Legacy sorts a list whose input order comes from
``concurrent.futures.as_completed`` — i.e. thread-completion order, which
is scheduling/network dependent. Python's sort being stable therefore
carries no defined semantic in legacy: equal scores had NO contractually
specified relative order. Nothing below is presented as legacy behaviour.

--------------------------------------------------------------------
NEW DETERMINISTIC POLICY (this phase — a declared contract, not legacy)
--------------------------------------------------------------------
Ordering is a single total order of four explicit levels:

1. ``score`` DESCENDING — the legacy contract above (higher first).
2. ``measured_ms`` ASCENDING — new policy. Rationale is contractual, not
   aesthetic: the legacy score formula is monotone decreasing in measured
   latency at fixed bonuses, and the sibling legacy pipeline orders nodes
   by ``alive.sort(key=lambda x: x.latency)`` (latency ASC, lower =
   better). Among equal scores this keeps the same "better first"
   direction both legacy signals already express. It is declared here as
   a NEW rule because legacy specified no tie order at all; an equally
   deterministic alternative (identity-first) would change no
   legacy-observable behaviour, so this is a deliberate contract choice,
   pinned by tests and changeable in exactly one place.
3. configuration identity ASC — canonical text of Phase 1
   :func:`config_key`, so different configs sharing a score AND a latency
   get a stable, reproducible order (and duplicate occurrences of one
   config stay adjacent without ever being merged).
4. full canonical node content ASC — last resort for entries that are
   identical in every ranked attribute yet differ in unranked metadata
   (geo, output name, raw url, timestamps). Only this level makes the
   result provably invariant under input shuffling.

Rendering an unrecognized object type contributes its TYPE IDENTITY
(module-qualified class name) and never ``repr()``: an object's default
repr embeds its memory address, and an address-derived key would make the
order address-dependent (explicitly forbidden). Instances of one opaque
class therefore render identically — they are indistinguishable by
content, which is the honest answer.

------------------------------------------------------------------------
INPUT CONTRACT
------------------------------------------------------------------------
Candidates are ``(Node, ScoreOutcome)`` pairs. Only
``status == "scored"`` enters the ranked set; ``unsupported``,
``insufficient_data`` and ``unscorable`` are never ranked and never
receive a fabricated score — they are returned as an explicit, canonical
``unranked`` audit list (grouped deterministically) instead.

SCORE INTEGRITY: a score is consumed, never changed. No rounding, no
recomputation, no clamping, no zero-filling of a missing score, no
conversion of non-finite values. A scored outcome that cannot supply a
finite score (or whose node has no finite, positive MEASURED latency for
level 2) is a contract violation and is refused with
:class:`ScoreIntegrityError` rather than silently ranked or dropped; a
non-scored outcome that carries a score is refused the same way.

IDENTITY: ranking never deduplicates. Two configs that share an endpoint
but differ in :func:`config_key` are two entries and both stay; identical
configs both stay as well.

TOP-N: ``n is None`` returns every ranked entry; ``n > len(ranked)``
returns all available; ``0 < n <= len(ranked)`` returns exactly ``n``.
``n <= 0`` (or a non-integer) is rejected with :class:`InvalidTopNError`.
Output ranks are 1-based positions in the FULL ranked order, so
truncation can never renumber a prefix.

MUTATION: nothing is mutated — not the input sequence, not the nodes, not
the outcomes, not any latency/jitter/identity value. Ranked items hold the
very same ``Node`` / ``ScoreOutcome`` objects they were given.
"""
from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from hubcore.identity import config_key
from hubcore.latency import LatencyKind
from hubcore.model import Node
from hubcore.scoring import ScoreOutcome

__all__ = [
    "RANK_START",
    "SCORED_STATUS",
    "UNRANKED_STATUSES",
    "ORDER_SCORE_DESC",
    "TIE_BREAK_MEASURED_MS_ASC",
    "RankingPolicy",
    "RankedItem",
    "UnrankedItem",
    "RankingResult",
    "RankingInputError",
    "InvalidTopNError",
    "ScoreIntegrityError",
    "rank_candidates",
    "ranking_counts",
]

RANK_START = 1                      # ranks are 1-based and contiguous
SCORED_STATUS = "scored"
UNRANKED_STATUSES = ("unsupported", "insufficient_data", "unscorable")
ORDER_SCORE_DESC = "score_desc"                  # the legacy contract
TIE_BREAK_MEASURED_MS_ASC = "measured_ms_asc"    # NEW policy (see above)


# ----------------------------------------------------------------------
# errors
# ----------------------------------------------------------------------
class RankingInputError(ValueError):
    """Malformed candidate stream, unknown status, or unsupported policy."""


class InvalidTopNError(ValueError):
    """``n`` was not a positive integer (``None`` means 'no limit')."""


class ScoreIntegrityError(ValueError):
    """An outcome contradicts the Phase 10 scoring contract."""


# ----------------------------------------------------------------------
# canonical rendering (total-order safe, dict/set-order proof)
# ----------------------------------------------------------------------
def _canonical_repr(value) -> str:
    """Render any model value as a stable, comparable string.

    Every branch is deterministic: enum members by NAME, floats by
    ``repr`` (exact round-trip), mapping items sorted by their rendered
    key (never by insertion order), set members sorted (never by set
    iteration order), dataclasses by their declared field order. Type
    tags keep ``1`` distinct from ``"1"`` and ``None`` distinct from
    ``"None"``.
    """
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "bool:1" if value else "bool:0"
    if isinstance(value, Enum):
        return f"enum:{type(value).__name__}.{value.name}"
    if isinstance(value, float):
        return f"float:{value!r}"
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, str):
        return f"str:{value}"
    if isinstance(value, dict):
        return "map{" + ",".join(
            f"{_canonical_repr(k)}={_canonical_repr(v)}"
            for k, v in sorted(value.items(), key=lambda kv: _canonical_repr(kv[0]))
        ) + "}"
    if isinstance(value, (set, frozenset)):
        return "set{" + ",".join(sorted(_canonical_repr(v) for v in value)) + "}"
    if isinstance(value, (tuple, list)):
        return "seq[" + ",".join(_canonical_repr(v) for v in value) + "]"
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return "rec(" + type(value).__name__ + ":" + ",".join(
            f"{f.name}={_canonical_repr(getattr(value, f.name))}"
            for f in dataclasses.fields(value)
        ) + ")"
    # Unrecognized objects: type identity only. ``repr()`` is deliberately
    # never used here because it can embed a memory address, which would
    # leak into the sort key and make the order address-derived.
    cls = value if isinstance(value, type) else type(value)
    return ("opaque:" + str(getattr(cls, "__module__", "")) + "."
            + str(getattr(cls, "__qualname__", "")))


def _identity_text(node: Node) -> str:
    """Canonical text of the Phase 1 configuration identity."""
    return _canonical_repr(config_key(node))


def _content_text(node: Node) -> str:
    """Canonical text of every field on the node (last-resort order)."""
    return _canonical_repr(node)


# ----------------------------------------------------------------------
# policy / result records
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class RankingPolicy:
    """The approved ranking contract, named in exactly one place.

    Both values are explicit: ``order`` reproduces the legacy ordering
    contract, ``tie_break`` is the new Phase 11 policy. Any other value is
    refused so a caller cannot quietly opt into an unpinned order.
    """

    order: str = ORDER_SCORE_DESC
    tie_break: str = TIE_BREAK_MEASURED_MS_ASC


@dataclass(frozen=True)
class RankedItem:
    """One ranked entry: its 1-based rank plus the original objects."""

    rank: int
    node: Node
    outcome: ScoreOutcome
    sort_key: tuple = ()

    @property
    def position(self) -> int:
        """0-based position (``rank - 1``) in the full ranked order."""
        return self.rank - RANK_START


@dataclass(frozen=True)
class UnrankedItem:
    """Audit record for a candidate that must not be ranked."""

    status: str
    detail: str
    node: Node
    outcome: ScoreOutcome


@dataclass(frozen=True)
class RankingResult:
    """Ranked prefix + unranked audit list for one candidate batch."""

    ranked: tuple = ()            # tuple[RankedItem, ...] (possibly truncated)
    unranked: tuple = ()          # tuple[UnrankedItem, ...]
    total_ranked: int = 0         # scored candidates before any Top-N cut
    requested_n: Optional[int] = None

    @property
    def is_truncated(self) -> bool:
        """True when Top-N cut scored entries away."""
        return len(self.ranked) < self.total_ranked


# ----------------------------------------------------------------------
# validation helpers
# ----------------------------------------------------------------------
def _unpack(item):
    """Accept a ``(Node, ScoreOutcome)`` pair; refuse anything else."""
    if isinstance(item, (tuple, list)) and len(item) == 2:
        node, outcome = item
    else:
        raise RankingInputError(
            "each candidate must be a (Node, ScoreOutcome) pair")
    if not isinstance(node, Node):
        raise RankingInputError("candidate node is not a hubcore Node")
    if not isinstance(outcome, ScoreOutcome):
        raise RankingInputError("candidate outcome is not a ScoreOutcome")
    return node, outcome


def _validate_top_n(n) -> Optional[int]:
    """``None`` = no limit; a positive int = exactly that many; else refuse."""
    if n is None:
        return None
    if isinstance(n, bool) or not isinstance(n, int):
        raise InvalidTopNError(
            f"top-N must be a positive integer or None, got {type(n).__name__}")
    if n <= 0:
        raise InvalidTopNError(
            f"top-N must be a positive integer or None, got {n}")
    return n


def _finite_score(node: Node, outcome: ScoreOutcome) -> float:
    """Read the score as-is; refuse anything that is not a finite number."""
    value = outcome.score
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScoreIntegrityError(
            f"scored outcome without a numeric score ({type(value).__name__})")
    number = float(value)
    if not math.isfinite(number):
        raise ScoreIntegrityError("scored outcome with a non-finite score")
    return number


def _measured_ms(node: Node) -> float:
    """Read the MEASURED latency used by tie-break level 2 (never rewritten)."""
    sample = node.measured_latency
    if sample is None:
        raise ScoreIntegrityError(
            "scored outcome whose node carries no measured latency")
    if sample.kind is not LatencyKind.MEASURED:
        raise ScoreIntegrityError(
            "scored outcome whose latency sample is not MEASURED")
    value = sample.value_ms
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScoreIntegrityError(
            "scored outcome whose measured latency is not numeric")
    number = float(value)
    if not math.isfinite(number):
        raise ScoreIntegrityError(
            "scored outcome whose measured latency is not finite")
    if number <= 0:
        raise ScoreIntegrityError(
            "scored outcome whose measured latency is not positive")
    return number


# ----------------------------------------------------------------------
# the ranking pass
# ----------------------------------------------------------------------
def rank_candidates(candidates: Iterable, *, n: Optional[int] = None,
                    policy: Optional[RankingPolicy] = None) -> RankingResult:
    """Rank scored candidates (legacy order + declared tie-break) and cut Top-N.

    Pure and deterministic: the returned sequence depends only on the
    multiset of candidates, never on their input order.
    """
    policy = policy or RankingPolicy()
    if not isinstance(policy, RankingPolicy):
        raise RankingInputError(
            "policy must be a RankingPolicy (got "
            f"{type(policy).__name__})")
    if policy.order != ORDER_SCORE_DESC:
        raise RankingInputError(
            f"unsupported ranking order: {str(policy.order)[:64]!r}")
    if policy.tie_break != TIE_BREAK_MEASURED_MS_ASC:
        raise RankingInputError(
            f"unsupported tie-break policy: {str(policy.tie_break)[:64]!r}")
    top_n = _validate_top_n(n)          # N is validated before any ranking

    try:
        stream = iter(candidates)
    except TypeError:
        raise RankingInputError(
            "candidates must be an iterable of (Node, ScoreOutcome) pairs")

    ranked_rows = []      # (sort_key, node, outcome)
    unranked_rows = []    # (sort_key, node, outcome, status, detail)

    for item in stream:
        node, outcome = _unpack(item)
        status = outcome.status

        if status == SCORED_STATUS:
            # level 1 (legacy): score DESC  |  level 2 (new): latency ASC
            sort_key = (
                -_finite_score(node, outcome),
                _measured_ms(node),
                _identity_text(node),      # level 3: config identity ASC
                _content_text(node),       # level 4: full content ASC
            )
            ranked_rows.append((sort_key, node, outcome))
        elif status in UNRANKED_STATUSES:
            if outcome.score is not None:
                raise ScoreIntegrityError(
                    f"outcome status {str(status)[:64]!r} must not carry a score")
            detail = "" if outcome.detail is None else str(outcome.detail)
            unranked_rows.append((
                (str(status), detail, _identity_text(node), _content_text(node)),
                node, outcome, str(status), detail,
            ))
        else:
            raise RankingInputError(
                f"unknown score status: {str(status)[:64]!r}")

    # explicit total orders: sorting is stable but stability is never
    # relied upon (level 4 leaves no equal keys except identical content)
    ranked_rows.sort(key=lambda row: row[0])
    unranked_rows.sort(key=lambda row: row[0])

    total_ranked = len(ranked_rows)
    ranked = tuple(
        RankedItem(rank=RANK_START + index, node=node, outcome=outcome,
                   sort_key=sort_key)
        for index, (sort_key, node, outcome) in enumerate(ranked_rows)
    )
    unranked = tuple(
        UnrankedItem(status=status, detail=detail, node=node, outcome=outcome)
        for (_key, node, outcome, status, detail) in unranked_rows
    )

    return RankingResult(
        ranked=ranked if top_n is None else ranked[:top_n],
        unranked=unranked,
        total_ranked=total_ranked,
        requested_n=top_n,
    )


def ranking_counts(result: RankingResult) -> dict:
    """Compact deterministic report of one ranking pass (audit view)."""
    by_status: dict = {}
    for item in result.unranked:
        by_status[item.status] = by_status.get(item.status, 0) + 1
    return {
        "ranked": result.total_ranked,
        "returned": len(result.ranked),
        "unranked": len(result.unranked),
        "by_status": dict(sorted(by_status.items())),
    }
