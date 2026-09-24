# -*- coding: utf-8 -*-
"""End-to-end pipeline orchestrator (Phase 14).

Wires the existing Phase 1-13 components into one auditable run:

    ingest -> dedup -> DNS -> geo -> TCP -> handshake -> measurement
           -> scoring -> ranking -> output -> writer

Every stage is the ALREADY-APPROVED Phase component; this module adds
only sequencing, a deterministic per-node audit trail, and fail-soft
semantics. It never re-implements dedup, ranking, scoring, output or
writing, never fabricates a value, and never touches the network unless
the caller explicitly provides a fetcher/resolver.

FAIL-SOFT CONTRACT (the pipeline's own policy, pinned by tests)
* One source's failure (fetch error, empty body) never stops the run:
  the failure is recorded on the source audit record and the run
  continues with the remaining sources.
* One node's failure at any live stage (DNS, TCP, handshake,
  measurement) removes only that node from the scored path and records
  a short reason; it never raises out of the pipeline.
* The run FAILS CLOSED (raises :class:`PipelineError`) only when the
  caller's own inputs are malformed (no sources, output root missing,
  ...). Missing or failed nodes are data, not errors.
* The writer is invoked with ``skip_identical=False`` so a failed
  ``os.replace`` surfaces as :class:`WriteFailedError` instead of being
  masked as an unchanged artifact; a writer failure aborts the run and
  leaves any already-published artifacts in place (Phase 13 keeps every
  artifact atomic, so partial output is still all-valid files).

INJECTED-BY-DEFAULT RULE
``fetcher``, ``resolver``, ``tcp.connect_factory``, ``handshake.*`` and
``measure.*`` are all ``None`` by default; in that state the pipeline
still runs to completion by degrading those stages honestly
(``fetch_no_fetcher``, ``dns_no_resolver``, ``no_pinned_ip`` ...), but
it will never invent a latency, a country or a score to fill the gap.

NOT IN THIS PHASE: no Telegram, no GitHub Actions, no scheduler, no
README/QR, no Config/*.txt migration, no CLI, and no change to any
Phase 1-13 module. Exceptions carry short reason codes only.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional

from .dedup import DedupOutcome, DedupPolicy, dedup_result
from .geo import GeoProvider, annotate_resolved
from .handshake import HandshakeValidator
from .ingest import (
    IngestResult,
    SourceKind,
    SourceOrigin,
    SourceIngestor,
)
from .measure import ProxyMeasurer
from .model import Node
from .output import OutputBundle, build_outputs
from .ranking import RankingPolicy, RankingResult, rank_candidates
from .resolver import Resolver
from .scoring import score_node
from .tcpval import TcpValidator
from .writer import WriterPolicy, WriteOutcome, write_outputs

__all__ = [
    "STAGE_INGEST",
    "STAGE_DEDUP",
    "STAGE_DNS",
    "STAGE_GEO",
    "STAGE_TCP",
    "STAGE_HANDSHAKE",
    "STAGE_MEASURE",
    "STAGE_SCORE",
    "STAGE_RANK",
    "STAGE_OUTPUT",
    "STAGE_WRITE",
    "LIVE_STAGES",
    "PipelineSource",
    "PipelineStage",
    "PipelineNodeReport",
    "PipelineError",
    "PipelineConfig",
    "PipelineResult",
    "run_pipeline",
]

# canonical stage names (audit labels only)
STAGE_INGEST = "ingest"
STAGE_DEDUP = "dedup"
STAGE_DNS = "dns"
STAGE_GEO = "geo"
STAGE_TCP = "tcp"
STAGE_HANDSHAKE = "handshake"
STAGE_MEASURE = "measure"
STAGE_SCORE = "score"
STAGE_RANK = "rank"
STAGE_OUTPUT = "output"
STAGE_WRITE = "write"

# stages whose failure removes a node from the scored path
LIVE_STAGES = (STAGE_DNS, STAGE_TCP, STAGE_HANDSHAKE, STAGE_MEASURE)

_REASON_TRIM = 120          # short, credential-free reason codes only


# ----------------------------------------------------------------------
# input records
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class PipelineSource:
    """One input source: raw text, a local file path, or a URL.

    ``raw_text``, ``path`` and ``url`` are mutually exclusive; the
    constructor validates the combination instead of guessing.
    """

    raw_text: Optional[str] = None
    path: Optional[str] = None
    url: Optional[str] = None
    name: str = ""

    def __post_init__(self):
        provided = sum(1 for value in (self.raw_text, self.path, self.url)
                       if value is not None)
        if provided == 0:
            raise PipelineError(
                "pipeline source must provide raw_text, path or url")
        if provided > 1:
            raise PipelineError(
                "pipeline source must provide exactly one of "
                "raw_text, path or url")
        if self.url and not str(self.url).lower().startswith(("http://",
                                                              "https://")):
            raise PipelineError(
                "pipeline source url must be http(s)")
        # raw_text="" stays legal: an empty source is data, not a mistake
        for value in (self.raw_text, self.path, self.url):
            if value is not None and not isinstance(value, str):
                raise PipelineError(
                    "pipeline source fields must be text or None")


@dataclass(frozen=True)
class PipelineStage:
    """Audit record for one pipeline stage."""

    name: str
    ok: bool
    input_count: int = 0
    output_count: int = 0
    dropped: int = 0
    detail: str = ""                    # short reason code, never content

    def as_dict(self) -> dict:
        return {
            "stage": self.name,
            "ok": self.ok,
            "input": self.input_count,
            "output": self.output_count,
            "dropped": self.dropped,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PipelineNodeReport:
    """Audit trail for one config line, from parse to final status."""

    origin: str                 # source name (unique within a run)
    line_no: int
    protocol: str               # canonical protocol name ("" if unparseable)
    endpoint: str               # host:port audit form ("" if unparseable)
    status: str                 # ok | rejected | dropped | failed | unranked
    stage: str = ""             # stage that decided the status
    reason: str = ""            # short reason code ("" on success)
    score: Optional[float] = None
    rank: Optional[int] = None
    line_hash: str = ""


# ----------------------------------------------------------------------
# errors / config / result
# ----------------------------------------------------------------------
class PipelineError(ValueError):
    """Malformed pipeline inputs (the caller's mistake, not node data)."""


@dataclass(frozen=True)
class PipelineConfig:
    """Configuration of one pipeline run (values are the defaults).

    Every component is optional; ``None`` means "run with the Phase
    default" for pure stages and "degrade honestly" for live stages.
    """

    sources: tuple = ()                 # tuple[PipelineSource, ...]
    top_n: Optional[int] = None
    fetcher: object = None              # Phase 4 Fetcher (needed for url sources)
    resolver: Optional[Resolver] = None       # Phase 6
    geo_provider: Optional[GeoProvider] = None  # Phase 6
    tcp_validator: Optional[TcpValidator] = None      # Phase 7
    handshake_validator: Optional[HandshakeValidator] = None  # Phase 8
    measurer: Optional[ProxyMeasurer] = None          # Phase 9
    ranking_policy: Optional[RankingPolicy] = None    # Phase 11
    output_policy: Optional[object] = None   # Phase 12 OutputPolicy
    writer_policy: Optional[WriterPolicy] = None      # Phase 13
    write: bool = True                  # set False for a dry run
    dedup_policy: Optional[DedupPolicy] = None        # Phase 5


@dataclass
class PipelineResult:
    """Everything one run produced, including the full audit trail."""

    stages: list = field(default_factory=list)          # list[PipelineStage]
    sources: list = field(default_factory=list)         # list[PipelineStage]
    nodes: list = field(default_factory=list)           # list[PipelineNodeReport]
    ranked: list = field(default_factory=list)          # list[RankedItem]
    unranked: list = field(default_factory=list)        # list[UnrankedItem]
    ranking: Optional[RankingResult] = None
    bundle: Optional[OutputBundle] = None
    written: Optional[WriteOutcome] = None
    root: str = ""

    # -- aggregate views -------------------------------------------------
    @property
    def ok_nodes(self) -> int:
        return sum(1 for n in self.nodes if n.status == "ok")

    @property
    def failed_nodes(self) -> int:
        return sum(1 for n in self.nodes if n.status == "failed")

    def stage(self, name: str) -> Optional[PipelineStage]:
        """The audit record of one stage (None when absent)."""
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def as_dict(self) -> dict:
        return {
            "stages": [s.as_dict() for s in self.stages],
            "sources": [s.as_dict() for s in self.sources],
            "nodes": len(self.nodes),
            "ok_nodes": self.ok_nodes,
            "failed_nodes": self.failed_nodes,
            "ranked": len(self.ranked),
            "unranked": len(self.unranked),
            "written": None if self.written is None else self.written.written,
        }


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _trim(text, limit: int = _REASON_TRIM) -> str:
    text = "" if text is None else str(text)
    return text[:limit]


def _endpoint_text(node: Node) -> str:
    """host:port audit form; brackets IPv6, never includes credentials."""
    host = node.endpoint.host or ""
    port = node.endpoint.port
    if not host:
        return ""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _origin_name(wrapper) -> str:
    origin = getattr(wrapper, "origin", None)
    return origin.name if origin is not None and origin.name else "unknown"


def _line_no(wrapper) -> int:
    return int(getattr(wrapper, "line_no", -1) or -1)


def _line_hash(wrapper) -> str:
    return str(getattr(wrapper, "line_hash", "") or "")


def _is_literal(host: str) -> bool:
    from .resolver import _is_literal

    return bool(_is_literal(host))


def _join_key(origin: str, line_no: int) -> tuple:
    """Unique per-line audit key (source names are uniquified at ingest)."""
    return (origin, line_no)


def _wrap_key(wrapper) -> tuple:
    return _join_key(_origin_name(wrapper), _line_no(wrapper))


# ----------------------------------------------------------------------
# stage 1: ingest
# ----------------------------------------------------------------------
def _run_sources(config: PipelineConfig,
                 ingestor: SourceIngestor) -> tuple:
    """Ingest every source; returns (IngestResult, source audit records).

    Source names are made unique within the run (``name``,
    ``name#2``, ``name#3``, ...) so the per-line audit join key
    ``(origin, line_no)`` is unambiguous no matter what the caller
    named its sources. Numbering is deterministic (config order).
    """
    merged: Optional[IngestResult] = None
    reports: list = []
    used_names: dict = {}
    index = 0

    for source in config.sources:
        index += 1
        label = (source.name or _source_label(source)).strip() or f"source{index}"
        count = used_names.get(label, 0) + 1
        used_names[label] = count
        origin_name = label if count == 1 else f"{label}#{count}"

        try:
            if source.url:
                result = ingestor.ingest_url(source.url, fetcher=config.fetcher,
                                             origin_name=origin_name)
            elif source.path:
                result = ingestor.ingest_file(source.path,
                                              origin_name=origin_name)
            else:
                origin = SourceOrigin(name=origin_name,
                                      kind=SourceKind.RAW_TEXT)
                result = ingestor.ingest_text(source.raw_text, origin)
        except Exception as exc:        # a broken source is data, not a crash
            reports.append(PipelineStage(
                name=origin_name, ok=False, input_count=0, output_count=0,
                dropped=0,
                detail=_trim(getattr(exc, "reason", "") or
                             type(exc).__name__)))
            continue

        reports.append(PipelineStage(
            name=origin_name,
            ok=bool(result.node_list),
            input_count=result.stats.lines_seen,
            output_count=len(result.nodes),
            dropped=result.stats.lines_rejected,
            detail=(result.errors[0].reason if result.errors else "")))
        merged = result if merged is None else merged.merged(result)

    if merged is None:                  # every source blew up before ingesting
        merged = IngestResult(origin=SourceOrigin(name="pipeline",
                                                  kind=SourceKind.RAW_TEXT))
    return merged, reports


def _source_label(source: PipelineSource) -> str:
    if source.url:
        return source.url[:120]
    if source.path:
        return source.path[:120]
    return "raw"


# ----------------------------------------------------------------------
# stage 3: DNS (Phase 6 resolver, fail-soft)
# ----------------------------------------------------------------------
def _resolve_nodes(nodes: list, config: PipelineConfig) -> tuple:
    """Pin one public IP per node; failures drop only that node."""
    resolver = config.resolver
    resolved: list = []
    reports: list = []

    for wrapper in nodes:
        node = wrapper.node
        host = node.endpoint.host or ""
        base = dict(origin=_origin_name(wrapper), line_no=_line_no(wrapper),
                    protocol=node.protocol.value, endpoint=_endpoint_text(node),
                    line_hash=_line_hash(wrapper))

        if _is_literal(host):
            # IP literals skip DNS; policy classification still happens at
            # the TCP gate (Phase 7), which refuses forbidden targets.
            ep = replace(node.endpoint, resolved_ip=host.strip("[]"))
            resolved.append(replace(wrapper, node=replace(node, endpoint=ep)))
            reports.append({**base, "status": "ok", "stage": STAGE_DNS})
            continue

        if resolver is None:
            # no resolver provided: fail soft, no fabricated destination
            reports.append({**base, "status": "failed", "stage": STAGE_DNS,
                            "reason": "dns_no_resolver"})
            continue

        try:
            rec = resolver.resolve(host, node.endpoint.port)
        except Exception:
            reports.append({**base, "status": "failed", "stage": STAGE_DNS,
                            "reason": "resolver_error"})
            continue

        if rec.ok and rec.public_ips:
            ip = rec.public_ips[0]
            ep = replace(node.endpoint, resolved_ip=ip)
            resolved.append(replace(wrapper, node=replace(node, endpoint=ep)))
            reports.append({**base, "status": "ok", "stage": STAGE_DNS})
        else:
            reports.append({**base, "status": "failed", "stage": STAGE_DNS,
                            "reason": _trim(rec.error or rec.status)})

    return resolved, reports


# ----------------------------------------------------------------------
# stage 4: geo (Phase 6 provider, fail-soft)
# ----------------------------------------------------------------------
def _geo_stage(nodes: list, config: PipelineConfig) -> tuple:
    provider = config.geo_provider
    base_reports = [dict(origin=_origin_name(w), line_no=_line_no(w),
                         protocol=w.node.protocol.value,
                         endpoint=_endpoint_text(w.node),
                         line_hash=_line_hash(w), status="ok",
                         stage=STAGE_GEO) for w in nodes]
    if provider is None:
        # no provider: nodes pass through; output later degrades to the
        # Unknown geo contract (never a fabricated country)
        return (list(nodes),
                [{**rep, "reason": "geo_provider_absent"}
                 for rep in base_reports])

    annotated = annotate_resolved([w.node for w in nodes], provider=provider)
    wrapped = [replace(wrapper, node=node)
               for wrapper, node in zip(nodes, annotated)]
    return wrapped, base_reports


# ----------------------------------------------------------------------
# stage 5: TCP (Phase 7, fail-soft)
# ----------------------------------------------------------------------
def _tcp_stage(nodes: list, config: PipelineConfig) -> tuple:
    validator = config.tcp_validator
    kept: list = []
    reports: list = []

    for wrapper in nodes:
        node = wrapper.node
        base = dict(origin=_origin_name(wrapper), line_no=_line_no(wrapper),
                    protocol=node.protocol.value, endpoint=_endpoint_text(node),
                    line_hash=_line_hash(wrapper))
        try:
            if validator is None:
                new_node, outcome = node, None
            else:
                new_node, outcome = validator.validate_and_attach(node)
        except Exception as exc:
            reports.append({**base, "status": "failed", "stage": STAGE_TCP,
                            "reason": _trim(getattr(exc, "reason", "") or
                                            type(exc).__name__)})
            continue
        if outcome is not None and not outcome.ok:
            reports.append({**base, "status": "failed", "stage": STAGE_TCP,
                            "reason": _trim(outcome.error or "tcp_failed")})
            continue
        if outcome is None:
            # validator opted out: audit the pass-through honestly
            reports.append({**base, "status": "ok", "stage": STAGE_TCP,
                            "reason": "tcp_validator_absent"})
        else:
            reports.append({**base, "status": "ok", "stage": STAGE_TCP})
        kept.append(replace(wrapper, node=new_node))

    return kept, reports


# ----------------------------------------------------------------------
# stage 6: handshake (Phase 8, fail-soft)
# ----------------------------------------------------------------------
def _handshake_stage(nodes: list, config: PipelineConfig) -> tuple:
    validator = config.handshake_validator
    kept: list = []
    reports: list = []

    for wrapper in nodes:
        node = wrapper.node
        base = dict(origin=_origin_name(wrapper), line_no=_line_no(wrapper),
                    protocol=node.protocol.value, endpoint=_endpoint_text(node),
                    line_hash=_line_hash(wrapper))
        try:
            if validator is None:
                new_node, outcome = node, None
            else:
                outcome = validator.validate(node)
                new_node = (node.with_protocol_handshake(outcome.latency)
                            if outcome.ok and outcome.latency is not None
                            else node)
        except Exception as exc:
            reports.append({**base, "status": "failed", "stage": STAGE_HANDSHAKE,
                            "reason": _trim(getattr(exc, "reason", "") or
                                            type(exc).__name__)})
            continue
        if outcome is not None and not outcome.ok:
            reports.append({**base, "status": "failed", "stage": STAGE_HANDSHAKE,
                            "reason": _trim(outcome.reason or outcome.status)})
            continue
        if outcome is None:
            reports.append({**base, "status": "ok", "stage": STAGE_HANDSHAKE,
                            "reason": "handshake_validator_absent"})
        else:
            reports.append({**base, "status": "ok", "stage": STAGE_HANDSHAKE})
        kept.append(replace(wrapper, node=new_node))

    return kept, reports


# ----------------------------------------------------------------------
# stage 7: measurement (Phase 9, fail-soft)
# ----------------------------------------------------------------------
def _measure_stage(nodes: list, config: PipelineConfig) -> tuple:
    measurer = config.measurer
    kept: list = []
    reports: list = []

    for wrapper in nodes:
        node = wrapper.node
        base = dict(origin=_origin_name(wrapper), line_no=_line_no(wrapper),
                    protocol=node.protocol.value, endpoint=_endpoint_text(node),
                    line_hash=_line_hash(wrapper))
        try:
            if measurer is None:
                new_node = node
                status, reason = "ok", "measurer_absent"
            else:
                new_node = measurer.attach(node)
                if new_node.measured_latency is None:
                    status, reason = "failed", "no_measured_sample"
                else:
                    status, reason = "ok", ""
        except Exception as exc:
            reports.append({**base, "status": "failed", "stage": STAGE_MEASURE,
                            "reason": _trim(getattr(exc, "reason", "") or
                                            type(exc).__name__)})
            continue
        reports.append({**base, "status": status, "stage": STAGE_MEASURE,
                        "reason": reason})
        if status == "failed":
            continue
        kept.append(replace(wrapper, node=new_node))

    return kept, reports


# ----------------------------------------------------------------------
# stage 8: scoring (Phase 10, pure)
# ----------------------------------------------------------------------
def _score_stage(nodes: list) -> tuple:
    """Returns (candidate_pairs, score_triples, reports).

    ``candidate_pairs`` -> EVERY (node, ScoreOutcome): Phase 11 owns the
    scored/unranked split (its contract validates status/score
    integrity and builds the unranked audit list). The pipeline never
    pre-filters, or the unranked audit would silently vanish.
    ``score_triples``   -> [(wrapper, node, ScoreOutcome), ...] for audit
    """
    pairs: list = []
    triples: list = []
    reports: list = []

    for wrapper in nodes:
        node = wrapper.node
        base = dict(origin=_origin_name(wrapper), line_no=_line_no(wrapper),
                    protocol=node.protocol.value, endpoint=_endpoint_text(node),
                    line_hash=_line_hash(wrapper))
        try:
            outcome = score_node(node)
        except Exception as exc:
            reports.append({**base, "status": "failed", "stage": STAGE_SCORE,
                            "reason": _trim(getattr(exc, "reason", "") or
                                            type(exc).__name__)})
            continue
        triples.append((wrapper, node, outcome))
        pairs.append((node, outcome))
        if outcome.status == "scored":
            reports.append({**base, "status": "ok", "stage": STAGE_SCORE,
                            "score": outcome.score})
        else:
            reports.append({**base, "status": "unranked", "stage": STAGE_SCORE,
                            "reason": _trim(outcome.detail)})

    return pairs, triples, reports


# ----------------------------------------------------------------------
# per-node audit merge
# ----------------------------------------------------------------------
def _merge_node_reports(*, ingest: IngestResult, dedup: DedupOutcome,
                        dns: list, geo: list, tcp: list, handshake: list,
                        measure: list, score: list,
                        ranking: RankingResult) -> list:
    """One :class:`PipelineNodeReport` per config line.

    Join key: ``(origin, line_no)`` — unique because source names are
    uniquified at ingest and line numbers are per-source. Ranking
    positions are joined back through the score triples (node -> wrapper).
    """
    rows: dict = {}

    def _row(key, origin="", line_no=-1, protocol="", endpoint="", line_hash=""):
        if key not in rows:
            rows[key] = {
                "origin": origin, "line_no": line_no,
                "protocol": protocol, "endpoint": endpoint,
                "status": "ok", "stage": "", "reason": "",
                "score": None, "rank": None, "line_hash": line_hash,
            }
        return rows[key]

    # rejected lines (parse errors): never became nodes
    for err in ingest.errors:
        key = _join_key(err.origin_name, err.line_no)
        if key not in rows:             # first reason per line wins
            rows[key] = {
                "origin": err.origin_name, "line_no": err.line_no,
                "protocol": "", "endpoint": "", "status": "rejected",
                "stage": STAGE_INGEST, "reason": err.reason,
                "score": None, "rank": None, "line_hash": "",
            }

    # every parsed line starts as ok
    for wrapper in ingest.nodes:
        node = wrapper.node
        _row(_wrap_key(wrapper), origin=_origin_name(wrapper),
             line_no=_line_no(wrapper), protocol=node.protocol.value,
             endpoint=_endpoint_text(node), line_hash=_line_hash(wrapper))

    # duplicates (Phase 5 first-wins)
    for wrapper in dedup.dropped:
        row = _row(_wrap_key(wrapper))
        row["status"] = "dropped"
        row["stage"] = STAGE_DEDUP
        row["reason"] = "duplicate"

    # live-stage failures; successes never overwrite a failure/drop
    for stage_reports in (dns, tcp, handshake, measure):
        for rep in stage_reports:
            key = _join_key(rep.get("origin", "unknown"),
                            rep.get("line_no", -1))
            row = rows.get(key)
            if row is None:             # synthetic node with no ingest line
                rows[key] = {
                    "origin": rep.get("origin", "unknown"),
                    "line_no": rep.get("line_no", -1),
                    "protocol": rep.get("protocol", ""),
                    "endpoint": rep.get("endpoint", ""),
                    "status": rep.get("status", "failed"),
                    "stage": rep.get("stage", ""),
                    "reason": rep.get("reason", ""),
                    "score": None, "rank": None,
                    "line_hash": rep.get("line_hash", ""),
                }
            elif rep.get("status") == "failed":
                row["status"] = "failed"
                row["stage"] = rep.get("stage", "")
                row["reason"] = rep.get("reason", "")

    # scoring: unranked outcomes surface; scored nodes keep "ok"
    for wrapper, _node, outcome in score:
        row = rows.get(_wrap_key(wrapper))
        if row is not None and outcome.status != "scored":
            row["status"] = "unranked"
            row["stage"] = STAGE_SCORE
            row["reason"] = _trim(outcome.detail)

    # rank/score join-back: scored node -> wrapper (from the same triples)
    node_to_wrapper = {node: wrapper for (wrapper, node, _outcome) in score}
    for item in ranking.ranked:
        wrapper = node_to_wrapper.get(item.node)
        if wrapper is None:
            continue
        row = rows.get(_wrap_key(wrapper))
        if row is not None:
            row["score"] = item.outcome.score
            row["rank"] = item.rank

    out = [PipelineNodeReport(**row) for row in rows.values()]
    out.sort(key=lambda r: (r.origin, r.line_no, r.line_hash))
    return out


# ----------------------------------------------------------------------
# the run
# ----------------------------------------------------------------------
def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """Run the full Phase 1-13 chain over ``config.sources``.

    Deterministic, auditable, fail-soft per source/node, fail-closed on
    malformed caller inputs. See the module docstring for the contract.
    """
    if not isinstance(config, PipelineConfig):
        raise PipelineError(
            f"config must be a PipelineConfig (got {type(config).__name__})")
    if not config.sources:
        raise PipelineError("no sources provided")
    if config.write and (config.writer_policy is None
                         or not config.writer_policy.root):
        raise PipelineError("writer policy with a root is required to write")

    result = PipelineResult(root=(config.writer_policy.root
                                  if config.writer_policy else ""))

    # -- 1. ingest ---------------------------------------------------------
    merged, source_reports = _run_sources(config, SourceIngestor())
    result.sources = source_reports
    result.stages.append(PipelineStage(
        name=STAGE_INGEST,
        ok=bool(merged.node_list),
        input_count=sum(r.input_count for r in source_reports),
        output_count=len(merged.nodes),
        dropped=sum(r.dropped for r in source_reports),
        detail=("" if merged.node_list else "no_parseable_nodes")))

    # -- 2. dedup (Phase 5, first-wins) -------------------------------------
    dedup = dedup_result(merged, policy=config.dedup_policy)
    result.stages.append(PipelineStage(
        name=STAGE_DEDUP, ok=True,
        input_count=dedup.kept_count + dedup.dropped_count,
        output_count=dedup.kept_count, dropped=dedup.dropped_count))

    # -- 3. DNS (Phase 6) -----------------------------------------------------
    resolved, dns_reports = _resolve_nodes(dedup.kept, config)
    result.stages.append(PipelineStage(
        name=STAGE_DNS, ok=bool(resolved), input_count=len(dedup.kept),
        output_count=len(resolved), dropped=len(dedup.kept) - len(resolved)))

    # -- 4. geo (Phase 6) -------------------------------------------------------
    geo_wrapped, geo_reports = _geo_stage(resolved, config)
    result.stages.append(PipelineStage(
        name=STAGE_GEO, ok=True, input_count=len(resolved),
        output_count=len(geo_wrapped)))

    # -- 5. TCP (Phase 7) ---------------------------------------------------------
    tcp_wrapped, tcp_reports = _tcp_stage(geo_wrapped, config)
    result.stages.append(PipelineStage(
        name=STAGE_TCP, ok=bool(tcp_wrapped), input_count=len(geo_wrapped),
        output_count=len(tcp_wrapped),
        dropped=len(geo_wrapped) - len(tcp_wrapped)))

    # -- 6. handshake (Phase 8) ------------------------------------------------------
    hs_wrapped, hs_reports = _handshake_stage(tcp_wrapped, config)
    result.stages.append(PipelineStage(
        name=STAGE_HANDSHAKE, ok=bool(hs_wrapped), input_count=len(tcp_wrapped),
        output_count=len(hs_wrapped),
        dropped=len(tcp_wrapped) - len(hs_wrapped)))

    # -- 7. measurement (Phase 9) ------------------------------------------------------
    measured_wrapped, measure_reports = _measure_stage(hs_wrapped, config)
    result.stages.append(PipelineStage(
        name=STAGE_MEASURE, ok=bool(measured_wrapped),
        input_count=len(hs_wrapped), output_count=len(measured_wrapped),
        dropped=len(hs_wrapped) - len(measured_wrapped)))

    # -- 8. scoring (Phase 10, pure) ------------------------------------------------------
    pairs, score_triples, score_reports = _score_stage(measured_wrapped)
    scored_count = sum(1 for _n, o in pairs if o.status == "scored")
    result.stages.append(PipelineStage(
        name=STAGE_SCORE, ok=bool(scored_count),
        input_count=len(measured_wrapped), output_count=scored_count,
        dropped=len(measured_wrapped) - scored_count))

    # -- 9. ranking (Phase 11, pure; owns the scored/unranked split) ------------------------
    ranking = rank_candidates(pairs, n=config.top_n,
                              policy=config.ranking_policy or RankingPolicy())
    result.stages.append(PipelineStage(
        name=STAGE_RANK, ok=bool(ranking.ranked), input_count=len(pairs),
        output_count=len(ranking.ranked),
        dropped=len(pairs) - len(ranking.ranked),
        detail=("top_n_truncated" if ranking.is_truncated else "")))
    result.ranking = ranking
    result.ranked = list(ranking.ranked)
    result.unranked = list(ranking.unranked)

    # -- 10. output (Phase 12, pure) ----------------------------------------------------------
    bundle = build_outputs(ranking, policy=config.output_policy)
    result.stages.append(PipelineStage(
        name=STAGE_OUTPUT, ok=bool(bundle.all_text),
        input_count=len(ranking.ranked), output_count=len(ranking.ranked)))
    result.bundle = bundle

    # -- 11. writer (Phase 13) --------------------------------------------------------------------
    if config.write:
        written = write_outputs(
            bundle, replace(config.writer_policy, skip_identical=False))
        result.written = written
        result.stages.append(PipelineStage(
            name=STAGE_WRITE, ok=written.total > 0,
            input_count=written.total, output_count=written.written,
            detail=("" if written.written == written.total
                    else "some_unchanged")))
    else:
        result.written = None

    # -- per-node audit: merge the stage reports in pipeline order ------------
    result.nodes = _merge_node_reports(
        ingest=merged, dedup=dedup, dns=dns_reports, geo=geo_reports,
        tcp=tcp_reports, handshake=hs_reports, measure=measure_reports,
        score=score_triples, ranking=ranking)

    return result
