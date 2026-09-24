# -*- coding: utf-8 -*-
"""Phase 9 tests: MEASURED latency + jitter (fully offline).

Injected fake transports, clock and sleeper make every scenario
deterministic: no real waiting, no network, no DNS. The tests prove
two probes are INDEPENDENT (fresh dials), jitter is |p2-p1| over two
valid probes only, and TCP/handshake/MEASURED never overwrite each
other.
"""
import math
import socket
import ssl
from dataclasses import replace

import pytest

from hubcore import (
    JITTER_THRESHOLD_MS,
    LATENCY_THRESHOLD_MS,
    LatencyKind,
    MeasureOutcome,
    ProxyMeasurer,
    parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"


def vless_tls_node(host="example.com", ip="93.184.216.34", port=443):
    n = parse_url(f"vless://{UUID}@{host}:{port}?security=tls&type=tcp")
    return replace(n, endpoint=replace(n.endpoint, resolved_ip=ip))


class FakeTLSSock:
    """Scripted TLS socket; records sends, closes, and read count."""

    def __init__(self, script):
        self._script = script       # callable() -> bytes | Exception
        self.sent = b""
        self.closed = False
        self.reads = 0

    def sendall(self, data):
        self.sent = data

    def recv(self, cap):
        self.reads += 1
        item = self._script()
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


class Harness:
    """Captures dials/SNI/closes; scripts per-probe responses and ms."""

    def __init__(self, response_script=lambda: b"\x00\x2a\x00\x00",
                 tcp_error=None, tls_error=None, probe_ms=(120.0, 133.0)):
        self.dials = []
        self.snis = []
        self.tls_socks = []
        self.closes = 0
        self.response_script = response_script
        self.tcp_error = tcp_error
        self.tls_error = tls_error
        self.probe_ms = list(probe_ms)
        self.now = 1000.0
        self._calls = 0
        self.slept = []
        self.factory = self._factory
        self.tls_wrap = self._tls_wrap
        self.clock = self._clock
        self.sleeper = self._sleeper

    # -- fake transport ------------------------------------------------
    def _factory(self, family, socktype, target, port, timeout):
        self.dials.append((target, port, family))

        class Raw:
            def connect(self, addr):
                if self._owner.tcp_error is not None:
                    raise self._owner.tcp_error
            def close(self):
                self._owner.closes += 1
        Raw._owner = self
        return Raw()

    def _tls_wrap(self, raw, sni):
        self.snis.append(sni)
        if self.tls_error is not None:
            raise self.tls_error
        fake = FakeTLSSock(self.response_script)
        self.tls_socks.append(fake)
        return fake

    # -- fake clock/sleep ----------------------------------------------
    def _clock(self):
        # Paired-call model: odd calls are t0 (return NOW, no advance);
        # even calls are t1 (advance NOW by the next scripted probe ms).
        self._calls += 1
        if self._calls % 2 == 0 and self.probe_ms:
            self.now += self.probe_ms.pop(0) / 1000.0
        return self.now

    def _sleeper(self, seconds):
        self.slept.append(seconds)


class TestSuccess:
    def test_two_independent_probes_produce_measured_samples(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.ok and out.status == "success"
        assert out.latency.kind is LatencyKind.MEASURED
        assert out.latency2.kind is LatencyKind.MEASURED
        assert out.latency.value_ms == pytest.approx(120.0)
        assert out.latency2.value_ms == pytest.approx(133.0)
        # two INDEPENDENT dial cycles (fresh socket each probe)
        assert len(h.dials) == 2
        assert out.jitter_ms == pytest.approx(13.0)   # |133 - 120|

    def test_gap_is_injected_not_slept(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        m.measure(vless_tls_node())
        assert h.slept == [m.probe_gap_seconds]
        assert 0.12 <= m.probe_gap_seconds <= 0.15   # contract 120–150ms

    def test_attach_writes_measured_and_jitter(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        n1 = m.attach(vless_tls_node())
        assert n1.measured_latency.kind is LatencyKind.MEASURED
        assert n1.jitter_ms == pytest.approx(13.0)
        assert n1.tcp_connect is None       # untouched by this phase
        assert n1.protocol_handshake is None

    def test_dial_and_sni_each_probe(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node(host="real.example",
                                       ip="93.184.216.34"))
        assert h.dials == [("93.184.216.34", 443, socket.AF_INET)] * 2
        assert h.snis == ["real.example", "real.example"]
        assert out.dial_target == "93.184.216.34"
        assert out.identity_hostname == "real.example"

    def test_six_probe_bytes_were_sent_each_cycle(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        m.measure(vless_tls_node())
        assert len(h.tls_socks) == 2
        assert all(len(s.sent) == 56 for s in h.tls_socks)


class TestFailurePolicy:
    def test_tcp_failure_no_latency(self):
        h = Harness(tcp_error=socket.timeout())
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert not out.ok and out.status == "timeout"
        assert out.latency is None and out.jitter_ms is None
        assert h.slept == []            # probe2 never attempted

    def test_probe1_failure_means_no_jitter_and_no_probe2(self):
        h = Harness(tls_error=ssl.SSLError("no tls"))
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert not out.ok and out.status == "tls_error"
        assert out.latency is None and out.latency2 is None
        assert out.jitter_ms is None

    def test_probe2_failure_is_partial_probe1_survives(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        # probe1 ok; make probe2 fail by exhausting scripted successes
        calls = {"n": 0}
        def flaky():
            calls["n"] += 1
            if calls["n"] > 1:      # second probe cycle's TLS read
                raise OSError(104, "reset detail")
            return b"\x00OK"
        h2 = Harness(response_script=flaky)
        m2 = ProxyMeasurer(connect_factory=h2.factory, tls_wrap=h2.tls_wrap,
                           accept_injected_tls=True, clock=h2.clock,
                           sleeper=h2.sleeper)
        out = m2.measure(vless_tls_node())
        assert out.status == "partial"
        assert out.latency is not None and out.latency2 is None
        assert out.jitter_ms is None      # NEVER fabricated from one probe

    def test_unexpected_response_no_number(self):
        h = Harness(response_script=lambda: b"HTTP/1.1 404 not vless")
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert out.reason == "unexpected_response"
        assert out.latency is None

    def test_empty_response_no_number(self):
        h = Harness(response_script=lambda: b"")
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert not out.ok and out.reason == "closed_without_response"
        assert out.latency is None

    def test_no_credentials_in_reports(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        n = parse_url(f"trojan://secretpw@93.184.216.34:443?security=tls")
        n = replace(n, endpoint=replace(n.endpoint, resolved_ip="93.184.216.34"))
        out = m.measure(n)
        assert out.status == "unsupported"    # credential probe off
        assert "secretpw" not in repr(out)


class TestUnsupportedAndTaxonomy:
    def test_vmess_unsupported_no_fake_latency(self):
        n = parse_url("vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicHJvdG9jb2wiOiJ2bWVzcyIsInNjaWQiOiIwMCJ9")
        m = ProxyMeasurer(connect_factory=Harness().factory)
        out = m.measure(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "vmess_aead_envelope_not_implemented"
        assert out.latency is None and out.jitter_ms is None

    def test_hysteria2_never_measured_over_tcp(self):
        n = parse_url("hysteria2://pass@93.184.216.34:443")
        m = ProxyMeasurer(connect_factory=Harness().factory)
        out = m.measure(n)
        assert not out.ok and out.unsupported_reason == "hy2_quic_out_of_scope"

    def test_taxonomy_kinds_never_conflated(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        n0 = vless_tls_node()
        # pre-attach TCP and handshake samples (simulating phases 7/8)
        from hubcore.latency import LatencySample
        n0 = n0.with_tcp_connect(LatencySample(80.0, LatencyKind.TCP_CONNECT))
        n0 = n0.with_protocol_handshake(
            LatencySample(130.0, LatencyKind.PROTOCOL_HANDSHAKE))
        n1 = m.attach(n0)
        assert n1.tcp_connect.kind is LatencyKind.TCP_CONNECT
        assert n1.tcp_connect.value_ms == 80.0      # NOT overwritten
        assert n1.protocol_handshake.kind is LatencyKind.PROTOCOL_HANDSHAKE
        assert n1.protocol_handshake.value_ms == 130.0
        assert n1.measured_latency.kind is LatencyKind.MEASURED
        assert n1.measured_latency.value_ms not in (80.0, 130.0)
        # explicit kind-mismatch guards on the model
        with pytest.raises(ValueError):
            n0.with_measured(n0.tcp_connect)         # TCP sample rejected
        with pytest.raises(ValueError):
            n0.with_tcp_connect(n1.measured_latency)  # MEASURED rejected

    def test_no_retroactive_rewrite(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        n1 = m.attach(vless_tls_node())
        n2 = m.attach(n1)
        # second measure cycle replaces only MEASURED; nothing else moves
        assert n2.tcp_connect is None and n2.protocol_handshake is None
        assert n2.measured_latency.kind is LatencyKind.MEASURED


class TestPinning:
    def test_no_pinned_ip_fails_closed(self):
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls")
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(n)
        assert out.status == "no_pinned_ip" and h.dials == []

    def test_private_target_never_dialed(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node(ip="10.9.9.9"))
        assert h.dials == []
        assert out.unsupported_reason.startswith("forbidden_target:")

    def test_never_resolves_hostname_again(self):
        # two probes -> exactly two dials, both to the SAME pinned IP;
        # no dial to the hostname ever
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        m.measure(vless_tls_node(host="example.com", ip="93.184.216.34"))
        assert [d[0] for d in h.dials] == ["93.184.216.34", "93.184.216.34"]


class TestNumericGuards:
    def test_with_jitter_rejects_nan_inf_negative(self):
        n = vless_tls_node()
        with pytest.raises(ValueError):
            n.with_jitter(float("nan"))
        with pytest.raises(ValueError):
            n.with_jitter(float("inf"))
        with pytest.raises(ValueError):
            n.with_jitter(-0.01)

    def test_regression_with_jitter_requires_measured_sample(self):
        """BUG: with_jitter accepted a value on a node with NO MEASURED
        sample — allowing fabricated jitter on unmeasured nodes.
        Fix: refuse unless measured_latency exists."""
        n = vless_tls_node()          # no measured_latency attached
        with pytest.raises(ValueError):
            n.with_jitter(24.0)
        # and after a real (faked-transport) measurement it works:
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        n2 = m.attach(n)
        assert n2.jitter_ms is not None

    def test_nonfinite_clock_refused(self):
        h = Harness()
        # clock that returns NaN at the t1 read
        seq = [1000.0, float("nan"), 1000.0, 1000.0]
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True,
                          clock=lambda: seq.pop(0) if seq else 1000.0,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.status == "internal_error"
        assert out.reason == "nonfinite_latency"
        assert out.latency is None

    def test_negative_elapsed_refused(self):
        seq = {"i": 0}
        vals = [1000.0, 999.999]     # clock goes BACKWARDS -> negative ms
        def clock():
            v = vals[min(seq["i"], len(vals) - 1)]
            seq["i"] += 1
            return v
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.status == "internal_error"
        assert out.reason == "nonfinite_latency"

    def test_huge_latency_is_reported_not_scored(self):
        h = Harness(probe_ms=(900.0, 900.0))
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.ok
        assert out.latency.value_ms == pytest.approx(900.0)
        assert out.within_threshold is False      # raw classification only
        assert not hasattr(out, "score")           # NO scoring in Phase 9


class TestThresholds:
    def test_constants_documented(self):
        assert LATENCY_THRESHOLD_MS == 500.0
        assert JITTER_THRESHOLD_MS == 75.0

    def test_within_threshold_classification(self):
        h = Harness(probe_ms=(183.0, 207.0))
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.within_threshold is True
        assert out.jitter_within_threshold is True   # |207-183| = 24 < 75
        assert not hasattr(out, "rank")

    def test_jitter_over_threshold_flagged_only(self):
        h = Harness(probe_ms=(100.0, 300.0))
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        out = m.measure(vless_tls_node())
        assert out.ok
        assert out.jitter_ms == pytest.approx(200.0)
        assert out.jitter_within_threshold is False
        assert out.latency.value_ms == pytest.approx(100.0)


class TestContainment:
    def test_factory_explosion_contained(self):
        def evil(family, socktype, target, port, timeout):
            raise RuntimeError("factory fire")
        m = ProxyMeasurer(connect_factory=evil)
        out = m.measure(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert "fire" not in repr(out)

    def test_sockets_closed_both_probes(self):
        h = Harness()
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=h.sleeper)
        m.measure(vless_tls_node())
        assert h.closes == 2              # both raw sockets closed
        assert all(s.closed for s in h.tls_socks)

    def test_determinism(self):
        a, b = Harness(), Harness()
        o1 = ProxyMeasurer(connect_factory=a.factory, tls_wrap=a.tls_wrap,
                           accept_injected_tls=True, clock=a.clock,
                           sleeper=a.sleeper).measure(vless_tls_node())
        o2 = ProxyMeasurer(connect_factory=b.factory, tls_wrap=b.tls_wrap,
                           accept_injected_tls=True, clock=b.clock,
                           sleeper=b.sleeper).measure(vless_tls_node())
        strip = lambda o: (o.ok, o.status, o.reason, o.jitter_ms,
                           o.within_threshold, o.jitter_within_threshold)
        assert strip(o1) == strip(o2)

    def test_sleeper_explosion_contained(self):
        h = Harness()
        def boom(_s):
            raise RuntimeError("sleep interrupted")
        m = ProxyMeasurer(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                          accept_injected_tls=True, clock=h.clock,
                          sleeper=boom)
        out = m.measure(vless_tls_node())
        assert out.ok                      # gap failure must not kill probes
        assert "sleep_interrupted" in out.notes
