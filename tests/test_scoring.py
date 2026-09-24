# -*- coding: utf-8 -*-
"""Phase 10 tests: deterministic scoring (fully offline, pure).

Proves: same input -> same score; boundaries 499/500/501 and 74/75/76;
the missing-data matrix; numeric safety (NaN/Inf/None/negative/huge);
integrity (no network, no new measurement, no mutation, kind-checked
inputs); explainability (components consistent with the final score);
unsupported protocols never scored.
"""
import math
from dataclasses import replace

import pytest

from hubcore import (
    GOLDEN_PORTS,
    JITTER_PENALTY_WEIGHT,
    LATENCY_GATE_MS,
    LatencyKind,
    LatencySample,
    Protocol,
    Security,
    Transport,
    parse_url,
    score_node,
)

UUID = "11111111-2222-3333-4444-555555555555"


def measured_node(ip="93.184.216.34", port=443, ms=180.0, jitter=24.0,
                  protocol_url=None):
    n = parse_url(protocol_url
                  or f"vless://{UUID}@example.com:{port}?security=tls&type=tcp")
    n = replace(n, endpoint=replace(n.endpoint, resolved_ip=ip))
    n = n.with_measured(LatencySample(ms, LatencyKind.MEASURED))
    if jitter is not None:
        n = n.with_jitter(jitter)
    return n


class TestDeterminism:
    def test_same_input_same_score(self):
        n = measured_node()
        s1, s2, s3 = score_node(n), score_node(n), score_node(n)
        assert s1.score == s2.score == s3.score
        assert s1.components == s2.components == s3.components

    def test_score_is_pure_function_of_fields_not_identity(self):
        a = measured_node(ms=180.0, jitter=24.0)
        b = measured_node(ms=180.0, jitter=24.0)
        assert a is not b
        assert score_node(a).score == score_node(b).score


class TestBoundary:
    def test_latency_boundary_499_500_501(self):
        # legacy gate: ms >= 500 -> unscorable; < 500 -> scored
        assert score_node(measured_node(ms=499.0)).status == "scored"
        assert score_node(measured_node(ms=500.0)).status == "unscorable"
        assert score_node(measured_node(ms=500.0)).detail == "latency_over_threshold"
        assert score_node(measured_node(ms=501.0)).status == "unscorable"
        # and 499.999 (just under) scores:
        assert score_node(measured_node(ms=499.999)).status == "scored"

    def test_jitter_boundary_74_75_76_smooth_not_gated(self):
        # contract: jitter is NOT gated; it enters the penalty term
        s74 = score_node(measured_node(jitter=74.0))
        s75 = score_node(measured_node(jitter=75.0))
        s76 = score_node(measured_node(jitter=76.0))
        assert all(s.status == "scored" for s in (s74, s75, s76))
        # each +1ms of jitter costs exactly 1.5 points
        assert s74.score - s75.score == pytest.approx(1.5)
        assert s75.score - s76.score == pytest.approx(1.5)
        # raw flag flips at 75 (documented; no ambiguity about </<=)
        assert s74.components["jitter_within_threshold"] is True
        assert s75.components["jitter_within_threshold"] is False
        assert s76.components["jitter_within_threshold"] is False

    def test_port_bonus_boundary(self):
        golden = measured_node(port=443)
        off = measured_node(port=8443)
        assert score_node(golden).components["port_bonus"] == 100
        assert score_node(off).components["port_bonus"] == 100
        non = measured_node(port=1234)
        assert score_node(non).components["port_bonus"] == 0


class TestMissingDataMatrix:
    def test_case_A_no_measured_sample(self):
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls&type=tcp")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        out = score_node(n)
        assert out.status == "insufficient_data"
        assert out.detail == "no_measured_sample"
        assert out.score is None

    def test_case_B_measured_without_jitter(self):
        n = measured_node(jitter=None)
        out = score_node(n)
        assert out.status == "insufficient_data"
        assert out.detail == "jitter_missing"
        assert out.score is None
        # the latency term is still explained (auditability)
        assert out.components["latency_term"] == pytest.approx(1000.0 / 180.0, rel=1e-3)

    def test_case_C_full_data_scores(self):
        out = score_node(measured_node(ms=180.0, jitter=24.0))
        assert out.status == "scored"
        # legacy formula verbatim, rounded to 2 decimals (legacy contract)
        expected = round(1000.0/180.0 - 1.5*24.0 + 300 + 100, 2)
        assert out.score == pytest.approx(expected)

    def test_case_E_tcp_failure_reflected_in_missing_samples(self):
        # a TCP-failed node never acquired MEASURED/jitter in Phase 9;
        # scorer must see exactly that -> insufficient, NOT a guessed score
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls&type=tcp")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        out = score_node(n)
        assert out.status == "insufficient_data" and out.score is None

    def test_failed_observation_value_none_is_unscorable(self):
        n = measured_node()
        n = n.with_measured(LatencySample(None, LatencyKind.MEASURED))
        out = score_node(n)
        assert out.status == "unscorable" and out.detail == "measured_failed_null"


class TestIntegrity:
    def test_tcp_sample_never_consumed_as_measured(self):
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls&type=tcp")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        n = n.with_tcp_connect(LatencySample(80.0, LatencyKind.TCP_CONNECT))
        out = score_node(n)
        assert out.status == "insufficient_data"   # no MEASURED -> no score
        assert out.score is None
        # even WITH a kind-invalid field planted on measured_latency:
        bad = replace(n, measured_latency=n.tcp_connect)
        out2 = score_node(bad)
        assert out2.status == "unscorable"
        assert out2.detail == "measured_kind_invalid"

    def test_handshake_sample_never_consumed_as_measured(self):
        n = measured_node()
        n = replace(n, measured_latency=n.protocol_handshake
                    or LatencySample(130.0, LatencyKind.PROTOCOL_HANDSHAKE))
        out = score_node(n)
        assert out.status == "unscorable"
        assert out.detail == "measured_kind_invalid"

    def test_scorer_does_not_mutate_node(self):
        n = measured_node()
        before = (n.measured_latency, n.jitter_ms, n.score, n.tcp_connect,
                  n.protocol_handshake)
        score_node(n)
        after = (n.measured_latency, n.jitter_ms, n.score, n.tcp_connect,
                 n.protocol_handshake)
        assert before == after

    def test_scorer_is_offline_no_network_imports(self):
        import hubcore.scoring as mod
        import inspect
        src = inspect.getsource(mod)
        for banned in ("socket", "requests", "urllib", "http.client",
                       "subprocess", "ssl."):
            assert banned not in src.replace("socket-like", "").replace(
                "sockets", ""), f"scoring must not reference {banned}"

    def test_unsupported_protocol_never_scored_even_with_samples(self):
        # plant a full valid measurement on an unmeasurable protocol
        n = parse_url("vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicHJvdG9jb2wiOiJ2bWVzcyIsInNjaWQiOiIwMCJ9")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="1.2.3.4"))
        n = n.with_measured(LatencySample(100.0, LatencyKind.MEASURED))
        n = n.with_jitter(5.0)
        out = score_node(n)
        assert out.status == "unsupported"
        assert out.score is None
        assert out.components["unsupported_reason"] == \
            "vmess_aead_envelope_not_implemented"


class TestNumericSafety:
    def test_nan_latency_refused(self):
        n = measured_node()
        n = replace(n, measured_latency=LatencySample(
            None, LatencyKind.MEASURED))
        # plant NaN directly via replace (LatencySample guard blocks it
        # in the constructor path, so use object-level construction):
        import dataclasses as dc
        bad = dc.replace(n.measured_latency, value_ms=float("nan"))
        n = dc.replace(n, measured_latency=bad)
        out = score_node(n)
        assert out.status == "unscorable" and out.detail == "nonfinite_latency"

    def test_inf_latency_refused(self):
        import dataclasses as dc
        n = measured_node()
        bad = dc.replace(n.measured_latency, value_ms=float("inf"))
        n = dc.replace(n, measured_latency=bad)
        out = score_node(n)
        assert out.status == "unscorable"

    def test_nonpositive_latency_refused(self):
        out = score_node(measured_node(ms=0.0))
        assert out.status == "unscorable" and out.detail == "latency_nonpositive"

    def test_negative_latency_blocked_at_both_layers(self):
        # layer 1: LatencySample refuses negative values at construction
        with pytest.raises(ValueError):
            LatencySample(-5.0, LatencyKind.MEASURED)
        # layer 2 (verified property): dataclasses.replace RE-RUNS
        # __post_init__, so even corrupting a sample via replace raises
        # — a negative value can never reach the scorer through the
        # model. (scorer's nonpositive guard remains as depth-3.)
        import dataclasses as dc
        n = measured_node()
        with pytest.raises(ValueError):
            dc.replace(n.measured_latency, value_ms=-5.0)

    def test_huge_but_finite_jitter_penalized_not_crash(self):
        out = score_node(measured_node(jitter=1e9))
        assert out.status == "scored"          # formula handles it
        assert out.score < 0                   # big penalty, documented
        assert math.isfinite(out.score)

    def test_huge_latency_over_gate(self):
        out = score_node(measured_node(ms=1e9))
        assert out.status == "unscorable"      # >= 500 gate


class TestExplainability:
    def test_components_consistent_with_score(self):
        out = score_node(measured_node(ms=180.0, jitter=24.0))
        c = out.components
        recomputed = (c["latency_term"] - c["jitter_penalty"]
                      + c["arch_bonus"] + c["port_bonus"])
        assert out.score == pytest.approx(round(recomputed, 2))

    def test_arch_labels_follow_legacy_table(self):
        cases = [
            (f"vless://{UUID}@example.com:443?security=tls&type=tcp", "VLESS-TLS", 300),
            (f"trojan://pw@example.com:443?security=tls&type=tcp", "Trojan-TLS", 260),
        ]
        for url, label, bonus in cases:
            n = parse_url(url)
            n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
            n = n.with_measured(LatencySample(180.0, LatencyKind.MEASURED))
            n = n.with_jitter(24.0)
            out = score_node(n)
            assert out.components["arch_label"] == label
            assert out.components["arch_bonus"] == bonus

    def test_reality_vision_padding_bonus(self):
        n = parse_url(
            f"vless://{UUID}@example.com:443?security=reality&flow=xtls-rprx-vision&type=tcp&pbk=x")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        n = n.with_measured(LatencySample(180.0, LatencyKind.MEASURED))
        n = n.with_jitter(24.0)
        out = score_node(n)
        # NOTE: reality nodes are gate-unsupported for probing; scoring
        # must STILL refuse them (unsupported beats bonus arithmetic)
        assert out.status == "unsupported"


class TestRegressionAdversarial:
    """Regressions from the Phase 10 adversarial bug-hunt."""

    def test_regression_orphan_jitter_cannot_manufacture_score(self):
        """ATTACK: plant jitter_ms via dataclasses.replace (bypassing
        the with_jitter guard) on a node with NO measured sample.
        RESULT: insufficient_data — measured is checked first; orphan
        jitter alone can never produce a score."""
        import dataclasses as dc
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls&type=tcp")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        n = dc.replace(n, jitter_ms=10.0)
        out = score_node(n)
        assert out.status == "insufficient_data"
        assert out.detail == "no_measured_sample"
        assert out.score is None

    def test_regression_nan_inf_jitter_planted(self):
        """ATTACK: NaN/Inf jitter via replace. RESULT: unscorable,
        never a number."""
        import dataclasses as dc
        n = measured_node()
        for bad in (float("nan"), float("inf"), float("-inf")):
            out = score_node(dc.replace(n, jitter_ms=bad))
            assert out.status == "unscorable"
            assert out.detail == "invalid_jitter"
            assert out.score is None

    def test_regression_extreme_small_latency_huge_finite_score(self):
        # 0.001ms -> 1000/0.001 = 1,000,000 base: inherited legacy
        # behaviour (finite but large), documented not hidden
        out = score_node(measured_node(ms=0.001, jitter=0.0))
        assert out.status == "scored"
        assert math.isfinite(out.score)
        assert out.score == pytest.approx(1000000.0 + 300 + 100)

    def test_regression_legacy_arch_order_vless_beats_cleanip(self):
        """PIN legacy ordering: protocol bonuses match BEFORE the CF
        fallbacks — vless on an IP host scores VLESS-TLS (300), not
        CF-CleanIP (200); CF-CleanIP applies to fall-through protocols."""
        n = parse_url(
            f"vless://{UUID}@1.2.3.4:443?security=tls&type=tcp")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="1.2.3.4"))
        n = n.with_measured(LatencySample(180.0, LatencyKind.MEASURED))
        n = n.with_jitter(24.0)
        out = score_node(n)
        assert out.components["arch_label"] == "VLESS-TLS"
        # fall-through protocols never reach CF branches here: every
        # measurable protocol hits its protocol label first; ss on an
        # IP host is probe-unsupported (ss_target_relay_required) so
        # the gate wins before any bonus arithmetic
        ss = parse_url("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443")
        ss = replace(ss, endpoint=replace(ss.endpoint, resolved_ip="1.2.3.4"))
        ss = ss.with_measured(LatencySample(180.0, LatencyKind.MEASURED))
        ss = ss.with_jitter(24.0)
        out_ss = score_node(ss)
        assert out_ss.status == "unsupported"
        assert out_ss.components["unsupported_reason"] == \
            "ss_target_relay_required"


class TestGeoPolicy:
    def test_geo_metadata_never_moves_score(self):
        from hubcore import GeoInfo
        n_plain = measured_node()
        n_geo = n_plain.with_geo(GeoInfo(country="Germany", city="Berlin",
                                         country_code="DE", flag="\U0001F1E9\U0001F1EA"))
        assert score_node(n_plain).score == score_node(n_geo).score
        assert "geo" not in score_node(n_geo).components


class TestConstants:
    def test_thresholds_unchanged_from_phase9(self):
        from hubcore import LATENCY_THRESHOLD_MS, JITTER_THRESHOLD_MS
        assert LATENCY_GATE_MS == LATENCY_THRESHOLD_MS == 500.0
        assert JITTER_PENALTY_WEIGHT == 1.5
        assert GOLDEN_PORTS == frozenset(
            {443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880})
