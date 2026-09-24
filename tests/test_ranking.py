# -*- coding: utf-8 -*-
"""Phase 11 tests: deterministic ranking (fully offline, pure).

Proves the extracted legacy ordering contract (score DESC), the NEW
declared tie-break policy (measured latency ASC -> config identity ASC ->
full canonical content ASC), the ranked/unranked split over Phase 10
statuses, the explicit Top-N contract, score integrity (no rounding, no
clamping, no zero-filling, no NaN/Inf massaging), identity preservation
(never deduplicated), input immutability, purity (no I/O, no entropy, no
clock) and shuffle-invariance.
"""
import ast
import itertools
import math
import pathlib
import time
from dataclasses import replace

import pytest

import hubcore.ranking as ranking_mod
from hubcore import (
    ORDER_SCORE_DESC,
    RANK_START,
    SCORED_STATUS,
    TIE_BREAK_MEASURED_MS_ASC,
    UNRANKED_STATUSES,
    GeoInfo,
    InvalidTopNError,
    LatencyKind,
    LatencySample,
    RankingInputError,
    RankingPolicy,
    RankingResult,
    RankedItem,
    ScoreIntegrityError,
    ScoreOutcome,
    UnrankedItem,
    config_key,
    endpoint_key,
    parse_url,
    rank_candidates,
    ranking_counts,
    score_node,
)

UUID = "11111111-2222-3333-4444-555555555555"
UUID2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
IP4 = "93.184.216.34"
IP6 = "2001:db8::1"
VMESS_URL = ("vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEt"
             "MjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicHJvdG9jb2wiOiJ2bWVzcyIsInNjaWQiOiIwMCJ9")


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
OBSERVED_AT = 1_700_000_000.0   # pinned: two builds of one fixture differ
                                # nowhere, not even in stored timestamps


def node(host="a.com", port=443, uuid=UUID, ip=IP4, ms=180.0, jitter=24.0,
         path="/p1", geo=None, name="", url=None):
    """A canonical node, optionally already measured (MEASURED + jitter)."""
    n = parse_url(url or f"vless://{uuid}@{host}:{port}?security=tls&type=tcp&path={path}")
    if ip:
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip=ip))
    if ms is not None:
        n = n.with_measured(LatencySample(float(ms), LatencyKind.MEASURED,
                                          measured_at=OBSERVED_AT))
    if jitter is not None and ms is not None:
        n = n.with_jitter(float(jitter))
    if geo is not None:
        n = n.with_geo(geo)
    if name:
        n = replace(n, output_name=name)
    return n


def outcome(status=SCORED_STATUS, score=None, detail=""):
    return ScoreOutcome(status=status, score=score, detail=detail)


def cand(n):
    """A real (Node, ScoreOutcome) pair straight out of Phase 10."""
    return (n, score_node(n))


def faux(n, score):
    """A synthetic scored outcome: used to pin tie-break levels exactly."""
    return (n, outcome(SCORED_STATUS, score))


def unscored_pair(n, status, detail="reason"):
    return (n, outcome(status, None, detail))


def roster():
    """Mixed realistic batch: 2 scored + 1 unsupported + 1 unscorable +
    1 insufficient_data (statuses produced by Phase 10 itself)."""
    return [
        cand(node(path="/fast", ms=120.0, jitter=10.0)),
        cand(node(path="/slow", ms=300.0, jitter=40.0)),
        cand(node(url=VMESS_URL, ip="1.2.3.4")),                  # unsupported
        cand(node(path="/dead", ms=600.0)),                       # unscorable
        cand(node(path="/nojitter", jitter=None)),                # insufficient
    ]


def keys(result):
    return [item.sort_key for item in result.ranked]


# ==========================================================================
# determinism
# ==========================================================================
class TestDeterminism:
    def test_two_runs_are_identical(self):
        items = roster()
        r1 = rank_candidates(items)
        r2 = rank_candidates(items)
        assert keys(r1) == keys(r2)
        assert [i.rank for i in r1.ranked] == [i.rank for i in r2.ranked]
        assert [i.node for i in r1.ranked] == [i.node for i in r2.ranked]
        assert [(u.status, u.detail) for u in r1.unranked] == \
               [(u.status, u.detail) for u in r2.unranked]
        assert ranking_counts(r1) == ranking_counts(r2)

    def test_independently_built_equal_inputs_are_identical(self):
        # the fixtures are equal down to their stored observation
        # timestamps, so this compares two genuinely identical inputs
        r1 = rank_candidates(roster())
        r2 = rank_candidates(roster())
        assert keys(r1) == keys(r2)
        assert ranking_counts(r1) == ranking_counts(r2)

    def test_shuffled_input_yields_identical_result(self):
        items = roster() + [cand(node(path="/tie", ms=200.0, jitter=20.0))]
        baseline = keys(rank_candidates(items))
        for perm in itertools.permutations(items):
            assert keys(rank_candidates(list(perm))) == baseline

    def test_shuffled_input_among_identical_configs(self):
        # identical config, same score/latency, different unranked
        # metadata: only the full-content level can order these
        a = (node(path="/same", name="A"), outcome(SCORED_STATUS, 50.0))
        b = (node(path="/same", name="B"), outcome(SCORED_STATUS, 50.0))
        assert keys(rank_candidates([a, b])) == keys(rank_candidates([b, a]))
        assert [i.node.output_name for i in rank_candidates([a, b]).ranked] == \
               [i.node.output_name for i in rank_candidates([b, a]).ranked]


# ==========================================================================
# ordering: the legacy contract
# ==========================================================================
class TestOrderingLegacyContract:
    def test_higher_score_ranks_earlier(self):
        items = [cand(node(path="/a", ms=300.0)), cand(node(path="/b", ms=100.0)),
                 cand(node(path="/c", ms=200.0))]
        scores = [o.score for _, o in items]
        assert scores[1] > scores[2] > scores[0]      # sanity on the fixture
        res = rank_candidates(items)
        assert [i.outcome.score for i in res.ranked] == sorted(scores, reverse=True)
        assert [i.rank for i in res.ranked] == [1, 2, 3]

    def test_negative_scores_rank_after_positive_ones(self):
        items = [faux(node(path="/neg"), -500.0), faux(node(path="/pos"), 10.0),
                 faux(node(path="/zero"), 0.0)]
        res = rank_candidates(items)
        assert [i.outcome.score for i in res.ranked] == [10.0, 0.0, -500.0]

    def test_filtering_happens_before_ordering(self):
        # legacy placement: ineligible nodes never reach the sort
        res = rank_candidates(roster())
        assert res.total_ranked == 2
        assert all(i.outcome.status == SCORED_STATUS for i in res.ranked)
        assert len(res.unranked) == 3

    def test_fastest_measured_node_ranks_first_in_fixture(self):
        res = rank_candidates(roster())
        assert res.ranked[0].node.path == "/fast"
        assert res.ranked[1].node.path == "/slow"


# ==========================================================================
# tie-break (NEW policy, pinned level by level)
# ==========================================================================
class TestTieBreakPolicy:
    def test_level2_equal_score_orders_by_measured_ms_ascending(self):
        items = [faux(node(path="/300", ms=300.0), 100.0),
                 faux(node(path="/100", ms=100.0), 100.0),
                 faux(node(path="/200", ms=200.0), 100.0)]
        res = rank_candidates(items)
        assert [i.node.path for i in res.ranked] == ["/100", "/200", "/300"]
        assert [i.outcome.score for i in res.ranked] == [100.0, 100.0, 100.0]

    def test_level3_equal_score_and_latency_orders_by_config_identity(self):
        # same host/ip/port/uuid/latency: the first differing identity
        # component is the path, so identity ASC == path ASC here
        items = [faux(node(path="/b1"), 42.0), faux(node(path="/a2"), 42.0),
                 faux(node(path="/a1"), 42.0)]
        res = rank_candidates(items)
        assert [i.node.path for i in res.ranked] == ["/a1", "/a2", "/b1"]

    def test_level4_identical_identity_orders_by_content(self):
        a = (node(path="/same", name="A"), outcome(SCORED_STATUS, 42.0))
        b = (node(path="/same", name="B"), outcome(SCORED_STATUS, 42.0))
        assert config_key(a[0]) == config_key(b[0])       # one config...
        res = rank_candidates([a, b])
        assert res.total_ranked == 2                      # ...never deduped
        assert [i.node.output_name for i in res.ranked] == ["A", "B"]

    def test_latency_tie_break_boundary_is_exact(self):
        items = [faux(node(path="/big", ms=200.0 + 1e-9), 7.0),
                 faux(node(path="/small", ms=200.0), 7.0)]
        assert [i.node.path for i in rank_candidates(items).ranked] == \
            ["/small", "/big"]

    def test_score_boundary_is_exact_no_rounding(self):
        items = [faux(node(path="/hi"), 100.0000000002),
                 faux(node(path="/lo"), 100.0000000001)]
        res = rank_candidates(items)
        assert [i.node.path for i in res.ranked] == ["/hi", "/lo"]
        assert res.ranked[0].outcome.score == 100.0000000002

    def test_latency_level_only_applies_within_equal_scores(self):
        # a huge latency difference must NOT outrank a higher score
        items = [faux(node(path="/slowfast", ms=499.0), 1.0),
                 faux(node(path="/fastslow", ms=1.0), 2.0)]
        assert [i.node.path for i in rank_candidates(items).ranked] == \
            ["/fastslow", "/slowfast"]

    def test_all_four_levels_in_one_batch(self):
        items = [faux(node(path="/x", ms=200.0), 10.0),
                 faux(node(path="/y", ms=100.0), 10.0),
                 faux(node(path="/z1", ms=100.0), 10.0),
                 faux(node(path="/z0", ms=100.0), 10.0),
                 faux(node(path="/best", ms=100.0), 11.0)]
        res = rank_candidates(items)
        assert [i.node.path for i in res.ranked] == \
            ["/best", "/y", "/z0", "/z1", "/x"]


# ==========================================================================
# ranked / unranked policy
# ==========================================================================
class TestRankedUnranked:
    def test_empty_input(self):
        res = rank_candidates([])
        assert res.ranked == () and res.unranked == ()
        assert res.total_ranked == 0
        assert ranking_counts(res) == {"ranked": 0, "returned": 0,
                                      "unranked": 0, "by_status": {}}

    def test_singleton(self):
        res = rank_candidates([cand(node())])
        assert res.total_ranked == 1
        assert res.ranked[0].rank == RANK_START == 1
        assert res.ranked[0].position == 0

    def test_all_scored(self):
        res = rank_candidates([cand(node(path=f"/{i}", ms=100.0 + i * 10))
                               for i in range(5)])
        assert res.total_ranked == 5 and res.unranked == ()

    def test_all_unscored_never_fabricates_a_score(self):
        pairs = [
            unscored_pair(node(url=VMESS_URL, ip="1.2.3.4"), "unsupported"),
            unscored_pair(node(ms=600.0), "unscorable"),
            unscored_pair(node(jitter=None), "insufficient_data"),
        ]
        res = rank_candidates(pairs)
        assert res.ranked == () and res.total_ranked == 0
        assert len(res.unranked) == 3
        assert [u.status for u in res.unranked] == \
            ["insufficient_data", "unscorable", "unsupported"]
        assert all(u.outcome.score is None for u in res.unranked)

    def test_mixed_statuses_split(self):
        res = rank_candidates(roster())
        assert ranking_counts(res) == {
            "ranked": 2, "returned": 2, "unranked": 3,
            "by_status": {"insufficient_data": 1, "unscorable": 1,
                          "unsupported": 1},
        }

    def test_every_status_in_legacy_taxonomy_is_known(self):
        assert set(UNRANKED_STATUSES) == {"unsupported", "insufficient_data",
                                          "unscorable"}
        for status in UNRANKED_STATUSES:
            res = rank_candidates([unscored_pair(node(), status, "d")])
            assert res.ranked == ()
            assert res.unranked[0].status == status
            assert res.unranked[0].detail == "d"

    def test_unranked_order_is_canonical_not_input_order(self):
        a = unscored_pair(node(path="/a"), "unscorable", "zzz")
        b = unscored_pair(node(path="/b"), "insufficient_data", "aaa")
        out1 = [u.detail for u in rank_candidates([a, b]).unranked]
        out2 = [u.detail for u in rank_candidates([b, a]).unranked]
        assert out1 == out2 == ["aaa", "zzz"]      # status ASC dominates


# ==========================================================================
# Top-N contract
# ==========================================================================
class TestTopN:
    def items(self, k=5):
        return [cand(node(path=f"/p{i}", ms=100.0 + i * 20.0)) for i in range(k)]

    def test_none_returns_everything(self):
        res = rank_candidates(self.items(), n=None)
        assert len(res.ranked) == 5 and res.total_ranked == 5
        assert res.is_truncated is False and res.requested_n is None

    def test_exact_n(self):
        res = rank_candidates(self.items(5), n=2)
        assert len(res.ranked) == 2
        assert [i.rank for i in res.ranked] == [1, 2]
        assert res.total_ranked == 5 and res.is_truncated is True
        assert res.requested_n == 2

    def test_n_greater_than_ranked_returns_all(self):
        res = rank_candidates(self.items(3), n=99)
        assert len(res.ranked) == 3 and res.total_ranked == 3
        assert res.is_truncated is False

    def test_n_equal_to_len(self):
        res = rank_candidates(self.items(4), n=4)
        assert len(res.ranked) == 4 and res.is_truncated is False

    def test_n_one(self):
        res = rank_candidates(self.items(4), n=1)
        assert len(res.ranked) == 1
        assert res.ranked[0].node.path == "/p0"     # the fastest

    @pytest.mark.parametrize("bad", [0, -1, -99])
    def test_n_non_positive_is_rejected(self, bad):
        with pytest.raises(InvalidTopNError):
            rank_candidates(self.items(), n=bad)

    @pytest.mark.parametrize("bad", [2.0, "2", True, [2]])
    def test_n_non_integer_is_rejected(self, bad):
        with pytest.raises(InvalidTopNError):
            rank_candidates(self.items(), n=bad)

    def test_n_is_validated_before_ranking_even_when_empty(self):
        with pytest.raises(InvalidTopNError):
            rank_candidates([], n=0)

    def test_invalid_n_is_a_value_error(self):
        assert issubclass(InvalidTopNError, ValueError)

    def test_top_n_never_renumbers_a_prefix(self):
        full = rank_candidates(self.items(5))
        cut = rank_candidates(self.items(5), n=3)
        assert [i.rank for i in cut.ranked] == [i.rank for i in full.ranked[:3]]
        assert keys(cut)[:3] == keys(full)[:3]

    def test_top_n_does_not_touch_unranked(self):
        res = rank_candidates(roster(), n=1)
        assert len(res.ranked) == 1 and len(res.unranked) == 3

    def test_ranking_counts_reports_returned_vs_ranked(self):
        c = ranking_counts(rank_candidates(self.items(5), n=2))
        assert c["ranked"] == 5 and c["returned"] == 2


# ==========================================================================
# identity preservation (no dedup, ever)
# ==========================================================================
class TestIdentityPreservation:
    def test_identical_configs_are_both_ranked(self):
        a = (node(path="/dup"), outcome(SCORED_STATUS, 5.0))
        b = (node(path="/dup"), outcome(SCORED_STATUS, 5.0))
        assert config_key(a[0]) == config_key(b[0])
        res = rank_candidates([a, b])
        assert res.total_ranked == 2 and len(res.ranked) == 2

    def test_same_endpoint_different_config_both_kept(self):
        u1 = node(path="/cfg1", uuid=UUID)
        u2 = node(path="/cfg2", uuid=UUID)
        u3 = node(path="/cfg1", uuid=UUID2)
        assert endpoint_key(u1) == endpoint_key(u2) == endpoint_key(u3)
        assert config_key(u1) != config_key(u2) != config_key(u3)
        res = rank_candidates([cand(u1), cand(u2), cand(u3)])
        assert res.total_ranked == 3

    def test_ipv4_and_ipv6_entries_stay_distinct(self):
        v4 = node(ip=IP4)
        v6 = node(ip=IP6)
        assert endpoint_key(v4) != endpoint_key(v6)
        res = rank_candidates([cand(v4), cand(v6)])
        assert res.total_ranked == 2
        assert {i.node.endpoint.identity_host for i in res.ranked} == {IP4, IP6}

    def test_original_objects_are_passed_through_untouched(self):
        pair = cand(node())
        res = rank_candidates([pair])
        item = res.ranked[0]
        assert item.node is pair[0] and item.outcome is pair[1]

    def test_renamed_node_keeps_its_own_slot(self):
        a = (node(path="/same", name="NameA"), outcome(SCORED_STATUS, 3.0))
        b = (node(path="/same", name="NameB"), outcome(SCORED_STATUS, 3.0))
        res = rank_candidates([a, b])
        assert {i.node.output_name for i in res.ranked} == {"NameA", "NameB"}


# ==========================================================================
# score integrity
# ==========================================================================
class TestScoreIntegrity:
    def test_scored_without_score_is_refused_never_zeroed(self):
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome(SCORED_STATUS, None))])

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_nonfinite_score_is_refused(self, bad):
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome(SCORED_STATUS, bad))])

    @pytest.mark.parametrize("bad", [True, False, "100", None, [1.0]])
    def test_non_numeric_score_is_refused(self, bad):
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome(SCORED_STATUS, bad))])

    @pytest.mark.parametrize("status", list(UNRANKED_STATUSES))
    def test_unranked_status_carrying_a_score_is_refused(self, status):
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome(status, 1.0, "why"))])

    def test_score_is_consumed_verbatim_not_rounded(self):
        pair = (node(), outcome(SCORED_STATUS, 123.456789))
        res = rank_candidates([pair])
        assert res.ranked[0].outcome.score == 123.456789
        assert res.ranked[0].outcome is pair[1]

    def test_integer_score_is_accepted_as_is(self):
        pair = (node(), outcome(SCORED_STATUS, 42))
        res = rank_candidates([pair])
        assert res.ranked[0].outcome.score == 42

    def test_scored_outcome_without_measured_latency_is_refused(self):
        bare = node(ms=None, jitter=None)
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(bare, outcome(SCORED_STATUS, 1.0))])

    def test_scored_outcome_with_non_measured_kind_is_refused(self):
        bare = node(ms=None, jitter=None).with_tcp_connect(
            LatencySample(80.0, LatencyKind.TCP_CONNECT))
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(bare, outcome(SCORED_STATUS, 1.0))])

    def test_scored_outcome_with_planted_nan_latency_is_refused(self):
        n = node()
        bad = replace(n.measured_latency, value_ms=float("nan"))
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(replace(n, measured_latency=bad),
                              outcome(SCORED_STATUS, 1.0))])

    def test_scored_outcome_with_planted_zero_latency_is_refused(self):
        n = node()
        bad = replace(n.measured_latency, value_ms=0.0)
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(replace(n, measured_latency=bad),
                              outcome(SCORED_STATUS, 1.0))])

    def test_huge_but_finite_score_is_ranked_not_clamped(self):
        pair = (node(), outcome(SCORED_STATUS, 1e12))
        res = rank_candidates([pair])
        assert res.ranked[0].outcome.score == 1e12

    def test_negative_score_ranked_not_clamped(self):
        res = rank_candidates([(node(), outcome(SCORED_STATUS, -1e9))])
        assert res.ranked[0].outcome.score == -1e9


# ==========================================================================
# input validation / policy guard
# ==========================================================================
class TestInputValidation:
    def test_bare_node_is_refused(self):
        with pytest.raises(RankingInputError):
            rank_candidates([node()])

    def test_three_tuple_is_refused(self):
        with pytest.raises(RankingInputError):
            rank_candidates([(node(), outcome(SCORED_STATUS, 1.0), "extra")])

    def test_wrong_outcome_type_is_refused(self):
        with pytest.raises(RankingInputError):
            rank_candidates([(node(), "scored")])

    def test_unknown_status_is_refused(self):
        with pytest.raises(RankingInputError):
            rank_candidates([(node(), outcome("excellent", 1.0))])

    @pytest.mark.parametrize("order", ["score_asc", "random", "", "RANK"])
    def test_unsupported_order_is_refused(self, order):
        with pytest.raises(RankingInputError):
            rank_candidates([cand(node())], policy=RankingPolicy(order=order))

    @pytest.mark.parametrize("tb", ["measured_ms_desc", "id", "", "shuffle"])
    def test_unsupported_tie_break_is_refused(self, tb):
        with pytest.raises(RankingInputError):
            rank_candidates([cand(node())], policy=RankingPolicy(tie_break=tb))

    def test_default_policy_is_the_declared_contract(self):
        p = RankingPolicy()
        assert p.order == ORDER_SCORE_DESC == "score_desc"
        assert p.tie_break == TIE_BREAK_MEASURED_MS_ASC == "measured_ms_asc"

    def test_errors_are_value_errors(self):
        for exc in (RankingInputError, InvalidTopNError, ScoreIntegrityError):
            assert issubclass(exc, ValueError)

    def test_error_messages_leak_no_credentials(self):
        secret_pw = "SUPERSECRETPASSWORD"
        n = node(url=f"trojan://{secret_pw}@a.com:443?security=tls&type=tcp")
        for bad in (outcome(SCORED_STATUS, float("nan")), outcome("nope", None)):
            with pytest.raises(ValueError) as ei:
                rank_candidates([(n, bad)])
            msg = str(ei.value)
            assert secret_pw not in msg and UUID not in msg
            assert "a.com" not in msg


# ==========================================================================
# mutation / immutability
# ==========================================================================
class TestMutation:
    def snapshot(self, items):
        return (
            [id(x) for x in items],
            list(items),
            [(n.measured_latency, n.jitter_ms, n.score, n.geo, n.output_name,
              n.raw_url, n.endpoint, n.protocol_fields, n.tcp_connect,
              n.protocol_handshake) for n, _ in items],
            [(o.status, o.score, o.detail, dict(o.components)) for _, o in items],
        )

    def test_nothing_is_mutated(self):
        items = roster()
        before = self.snapshot(items)
        rank_candidates(items, n=2)
        assert self.snapshot(items) == before

    def test_node_score_field_is_never_written(self):
        items = roster()
        before = [n.score for n, _ in items]
        rank_candidates(items)
        assert [n.score for n, _ in items] == before
        assert all(s == 0.0 for s in before)

    def test_result_is_immutable_and_independent_of_the_input_list(self):
        items = roster()
        res = rank_candidates(items, n=2)
        assert isinstance(res, RankingResult)
        assert isinstance(res.ranked, tuple) and isinstance(res.unranked, tuple)
        items.clear()
        assert len(res.ranked) == 2 and len(res.unranked) == 3

    def test_ranked_item_records_are_frozen(self):
        item = rank_candidates([cand(node())]).ranked[0]
        assert isinstance(item, RankedItem) and isinstance(item.sort_key, tuple)
        with pytest.raises(Exception):
            item.rank = 99

    def test_unranked_item_records_are_frozen(self):
        u = rank_candidates([unscored_pair(node(), "unscorable")]).unranked[0]
        assert isinstance(u, UnrankedItem) and u.outcome.score is None
        with pytest.raises(Exception):
            u.status = "scored"

    def test_generator_input_is_accepted_without_materialising(self):
        gen = (p for p in roster())
        res = rank_candidates(gen)
        assert res.total_ranked == 2


# ==========================================================================
# purity / security
# ==========================================================================
ALLOWED_MODULES = {
    "__future__", "dataclasses", "math", "typing", "enum",
    "hubcore.identity", "hubcore.latency", "hubcore.model", "hubcore.scoring",
}
BANNED_TOKENS = (
    "socket", "subprocess", "urllib", "requests", "http.client", "ssl.",
    "os.environ", "import os", "from time", "import time", "random",
    "eval(", "exec(", "open(",
)
BANNED_CALLS = {
    "eval", "exec", "compile", "open", "system", "popen", "getenv",
    "urandom", "randint", "randrange", "choice", "shuffle", "id",
    "time", "monotonic", "perf_counter", "gethostbyname", "getaddrinfo",
    "create_connection", "urlopen",
}


def ranking_source():
    return pathlib.Path(ranking_mod.__file__).read_text(encoding="utf-8")


def called_names(tree):
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            func = n.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


class TestPurity:
    def test_imports_are_whitelisted(self):
        tree = ast.parse(ranking_source())
        modules = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                modules.update(a.name for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                modules.add(n.module or "")
        assert modules <= ALLOWED_MODULES, modules - ALLOWED_MODULES

    def test_no_banned_source_tokens(self):
        src = ranking_source()
        for token in BANNED_TOKENS:
            assert token not in src, f"ranking must not reference {token}"

    def test_no_banned_calls(self):
        names = called_names(ast.parse(ranking_source()))
        assert not (names & BANNED_CALLS), names & BANNED_CALLS

    def test_result_carries_no_score_side_channels(self):
        res = rank_candidates(roster())
        assert not hasattr(res, "output") and not hasattr(res, "write")

    def test_no_module_level_io_objects_are_reachable(self):
        # no socket/clock/env/subprocess handle is even imported into the
        # module namespace, so no call path can reach one
        for name in ("socket", "ssl", "os", "sys", "time", "random",
                     "subprocess", "urllib", "requests"):
            assert not hasattr(ranking_mod, name), name

    def test_ranking_never_reaches_stdout(self, capsys):
        rank_candidates(roster())
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""


# ==========================================================================
# canonical rendering (dict/set order proof)
# ==========================================================================
class TestCanonicalRendering:
    def test_dict_rendering_is_insertion_order_proof(self):
        r = ranking_mod._canonical_repr
        assert r({"b": 1, "a": 2}) == r({"a": 2, "b": 1})

    def test_set_rendering_is_iteration_order_proof(self):
        r = ranking_mod._canonical_repr
        assert r({3, 1, 2}) == r({2, 3, 1}) == r(frozenset({1, 2, 3}))

    def test_type_tags_distinguish_ambiguous_values(self):
        r = ranking_mod._canonical_repr
        assert r(1) != r("1") and r(None) != r("None") and r(True) != r(1)

    def test_enum_and_float_rendering_is_stable(self):
        r = ranking_mod._canonical_repr
        assert r(LatencyKind.MEASURED) == "enum:LatencyKind.MEASURED"
        assert r(0.1) == "float:0.1"

    def test_nan_rendering_does_not_crash(self):
        assert "nan" in ranking_mod._canonical_repr(float("nan"))


# ==========================================================================
# adversarial invariants
# ==========================================================================
class TestAdversarialInvariants:
    def test_equal_scores_full_tie_is_stable(self):
        items = [faux(node(path=f"/p{i}"), 9.0) for i in range(8)]
        first = [i.node.path for i in rank_candidates(items).ranked]
        shuffled = list(reversed(items))
        assert [i.node.path for i in rank_candidates(shuffled).ranked] == first

    def test_near_equal_scores_never_merge(self):
        items = [faux(node(path=f"/p{i}"), 1.0 + i * 1e-15) for i in range(5)]
        res = rank_candidates(items)
        assert [i.outcome.score for i in res.ranked] == \
            sorted([o.score for _, o in items], reverse=True)

    def test_status_score_mismatch_attacked(self):
        for status in UNRANKED_STATUSES + ("", "SCORED", "Scored"):
            pair = (node(), outcome(status, 0.0))
            with pytest.raises((ScoreIntegrityError, RankingInputError)):
                rank_candidates([pair])

    def test_nan_inf_negative_score_matrix(self):
        for bad in (float("nan"), float("inf"), float("-inf"), None, "x"):
            with pytest.raises(ScoreIntegrityError):
                rank_candidates([(node(), outcome(SCORED_STATUS, bad))])
        # negative is legal data, not corruption
        assert rank_candidates([(node(), outcome(SCORED_STATUS, -3.5))]).ranked[0] \
            .outcome.score == -3.5

    def test_identity_loss_attack_duplicate_configs(self):
        pairs = [cand(node(path="/same", ms=150.0, jitter=15.0)) for _ in range(6)]
        res = rank_candidates(pairs, n=3)
        assert res.total_ranked == 6 and len(res.ranked) == 3

    def test_mutation_attack_through_dataclasses_replace(self):
        n = node()
        planted = replace(n, jitter_ms=float("nan"))
        items = [(planted, outcome(SCORED_STATUS, 5.0))]
        before = (planted.jitter_ms, planted.score, planted.raw_url)
        res = rank_candidates(items)
        assert (planted.jitter_ms, planted.score, planted.raw_url) == before
        assert res.total_ranked == 1        # order still deterministic

    def test_top_n_boundary_sweep(self):
        items = [cand(node(path=f"/p{i}", ms=100.0 + i)) for i in range(6)]
        for n in range(1, 8):
            res = rank_candidates(items, n=n)
            assert len(res.ranked) == min(n, 6)
            assert [i.rank for i in res.ranked] == list(range(1, min(n, 6) + 1))

    def test_empty_and_all_unscored_then_scored_mix(self):
        assert rank_candidates([]).total_ranked == 0
        assert rank_candidates([unscored_pair(node(), "unsupported")]).total_ranked == 0
        assert rank_candidates([cand(node())]).total_ranked == 1


# ==========================================================================
# regressions found in this phase's hunt
# ==========================================================================
class TestRegressionAdversarial:
    """Regressions for the three real defects the Phase 11 hunt
    reproduced against the first revision of this module."""

    def test_regression_non_iterable_candidate_stream(self):
        """BUG (reproduced): ``rank_candidates(None)`` / ``(42)`` escaped as
        a bare ``TypeError: 'NoneType' object is not iterable`` instead of
        the module's documented input error, so a wiring mistake surfaced
        as an unrelated crash. FIX: the stream is materialised through an
        explicit ``iter()`` guard."""
        for bad in (None, 42, object(), 3.14):
            with pytest.raises(RankingInputError):
                rank_candidates(bad)

    def test_regression_policy_of_the_wrong_type(self):
        """BUG (reproduced): a policy-like mapping raised
        ``AttributeError: 'dict' object has no attribute 'order'``. FIX:
        the policy is type-checked and refused as RankingInputError."""
        with pytest.raises(RankingInputError):
            rank_candidates([], policy={"order": ORDER_SCORE_DESC})
        with pytest.raises(RankingInputError):
            rank_candidates([], policy="score_desc")
        with pytest.raises(RankingInputError):
            rank_candidates([], policy=object())

    def test_regression_opaque_field_cannot_inject_a_memory_address(self):
        """BUG (reproduced): a non-model object planted on a node field was
        rendered with ``repr()``, so a memory address
        (``<Opaque object at 0x...>``) entered the sort key and the order
        became address-derived — banned outright. FIX: unrecognized types
        contribute module-qualified type identity only, never repr()."""
        class OpaqueType:
            pass

        n = node(path="/planted")
        object.__setattr__(n, "path", OpaqueType())      # frozen+slots plant
        res = rank_candidates([(n, outcome(SCORED_STATUS, 5.0))])
        text = "|".join(str(part) for part in res.ranked[0].sort_key)
        assert "0x" not in text and "object at" not in text
        # type identity is still part of the key (two classes stay distinct)
        assert "OpaqueType" in text
        # ...and the same input ranks identically on a rebuild
        assert keys(rank_candidates([(replace(n), outcome(SCORED_STATUS, 5.0))])) \
            == keys(res)

    def test_regression_identical_configs_ordered_by_content_not_input(self):
        """ATTACK (repelled, invariant pinned): two entries of the SAME
        config identity with equal score and equal latency but different
        metadata (geo / output name). A three-level key (score, latency,
        identity) leaves them equal and the stable sort silently falls
        back to input order, so shuffling the input reorders the output.
        The shipped level 4 (full canonical node content) makes the order
        a pure function of the input multiset — verified here, and by the
        500-batch shuffle fuzz run recorded in the phase report."""
        geo_de = GeoInfo(country="Germany", city="Berlin", country_code="DE")
        geo_nl = GeoInfo(country="Netherlands", city="Amsterdam", country_code="NL")
        a = (node(path="/same", geo=geo_de, name="DE"), outcome(SCORED_STATUS, 5.0))
        b = (node(path="/same", geo=geo_nl, name="NL"), outcome(SCORED_STATUS, 5.0))
        assert config_key(a[0]) == config_key(b[0])
        assert keys(rank_candidates([a, b])) == keys(rank_candidates([b, a]))
        assert [i.node.output_name for i in rank_candidates([a, b]).ranked] == \
               [i.node.output_name for i in rank_candidates([b, a]).ranked]

    def test_regression_bool_score_cannot_masquerade_as_a_number(self):
        """ATTACK (repelled, invariant pinned): ``True`` passes
        ``isinstance(x, int)``, so a boolean planted as a score is ranked
        as 1.0 and sorts above real scores. The validator refuses
        booleans for both score and Top-N."""
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome(SCORED_STATUS, True))])
        with pytest.raises(InvalidTopNError):
            rank_candidates([cand(node())], n=True)

    def test_regression_unranked_status_with_score_cannot_enter_the_audit(self):
        """ATTACK (repelled, invariant pinned): a plant of
        ``status="unscorable", score=999`` would be reported as unranked
        while secretly carrying a score, making a fabricated value visible
        to any later output stage. Refused."""
        with pytest.raises(ScoreIntegrityError):
            rank_candidates([(node(), outcome("unscorable", 999.0, "x"))])


# ==========================================================================
# performance
# ==========================================================================
class TestPerformance:
    def test_large_batch_is_linear_logarithmic_and_deterministic(self):
        base = node(path="/perf")
        items = []
        for i in range(20_000):
            nb = replace(base, measured_latency=LatencySample(
                float(i % 500) + 1.0, LatencyKind.MEASURED,
                measured_at=OBSERVED_AT))
            nb = replace(nb, jitter_ms=float(i % 20))
            items.append((nb, outcome(SCORED_STATUS, ((i * 7919) % 100_000) / 10.0)))
        for _ in range(5_000):
            items.append(unscored_pair(base, "unscorable", "latency_over_threshold"))

        t0 = time.monotonic()
        res = rank_candidates(items)
        dt = time.monotonic() - t0
        assert res.total_ranked == 20_000 and len(res.unranked) == 5_000
        scores = [i.outcome.score for i in res.ranked]
        assert scores == sorted(scores, reverse=True)
        assert dt < 5.0, f"ranking too slow: {dt:.2f}s"

    def test_repeated_runs_at_scale_agree(self):
        items = [cand(node(path=f"/p{i}", ms=100.0 + (i % 7)))
                 for i in range(500)]
        assert keys(rank_candidates(items)) == keys(rank_candidates(items))
