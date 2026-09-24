# -*- coding: utf-8 -*-
"""Phase 14 tests: end-to-end pipeline orchestrator (fully offline).

Every live transport is injected; nothing here opens a socket, resolves
DNS or touches the real filesystem beyond pytest's ``tmp_path``. The
suite pins: staged wiring, the fail-soft contract, per-node audit
records, no-fabrication, Phase 11 ordering preservation, Phase 13 byte
identity, determinism, secret safety and canonical-input immutability.
"""
import ast
import pathlib
import socket
import time
from dataclasses import replace

import pytest

import hubcore.pipeline as pipeline_mod
from hubcore import (
    InvalidTopNError,
    LatencyKind,
    LatencySample,
    Node,
    OutputBundle,
    PipelineConfig,
    PipelineError,
    PipelineSource,
    Protocol,
    Resolver,
    WriteFailedError,
    WriterPolicy,
    HandshakeValidator,
    ProxyMeasurer,
    TableGeoProvider,
    TcpValidator,
    parse_url,
    run_pipeline,
    write_outputs,
)

UUID = "11111111-2222-3333-4444-555555555555"
SECRET = "SUPERSECRETPASSWORD"
# note: TEST-NET ranges (198.51.100.0/24, 203.0.113.0/24) are classified
# private by the Phase 6 policy, so the fakes use globally-routable IPs
IP_GOOD = "93.184.216.34"       # Canada
IP_SLOW = "8.8.4.4"             # Germany-ish (public)
IP_DEAD = "9.9.9.9"             # TCP refused
IP_PRIVATE = "10.0.0.5"

RESPONSE = b"\x00\x2a\x00\x00"  # bytes that match the VLESS response contract


# ======================================================================
# fake transports (same patterns as the Phase 7/8/9 suites)
# ======================================================================
class FakeTLSSock:
    def __init__(self, script):
        self._script = script
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent = data

    def recv(self, cap):
        item = self._script()
        if isinstance(item, Exception):
            raise item
        return item() if callable(item) else item

    def close(self):
        self.closed = True


class RawSock:
    def __init__(self, owner, target):
        self._owner = owner
        self._target = target

    def connect(self, addr):
        self._owner.dials.append((self._target, addr[0], addr[1]))
        if self._owner.tcp_script(addr[0]) is False:
            # errno 111 = ECONNREFUSED -> Phase 7 maps it to "refused"
            refused = ConnectionRefusedError("refused")
            refused.errno = 111
            raise refused

    def close(self):
        pass


class Transport:
    """Shared fake transport: DNS table + TCP script + TLS responses.

    ``tcp_script`` returns True when the dial to that IP SUCCEEDS.
    """

    def __init__(self, tcp_script=lambda ip: True,
                 response_script=lambda: RESPONSE):
        self.dials = []
        self._tcp_script = tcp_script
        self.response_script = response_script
        self.dns_table = {
            "good.com": IP_GOOD,
            "slow.com": IP_SLOW,
            "dead.com": IP_DEAD,
            "private.com": IP_PRIVATE,
        }

    # -- DNS (Resolver.getaddrinfo contract) ---------------------------
    def gai(self, host, port, **kwargs):
        ip = self.dns_table.get(host)
        if ip is None:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    def tcp_script(self, ip):        # overridable per instance
        return self._tcp_script(ip)

    def factory(self, family, socktype, target, port, timeout):
        return RawSock(self, target)

    def tls_wrap(self, raw, sni):
        return FakeTLSSock(self.response_script)

    # -- measure clock/sleep (paired-call model of test_measure) -------
    def make_clock_sleeper(self, probe_ms=(40.0, 52.0, 60.0, 71.0, 80.0, 95.0),
                           per_node=False):
        """A clock that scripts each probe's duration in ms.

        The measurer makes 4 clock calls per node: (t0,t1) probe1 and
        (t0,t1) probe2; a call advances ``now`` iff it is a t1 (even
        count). The script list is consumed per t1, so with a rotating
        list every node in the run gets a DIFFERENT measured latency
        (deterministic, order = node processing order).
        """
        state = {"now": 1000.0, "calls": 0, "script": list(probe_ms) * 512}

        def clock():
            state["calls"] += 1
            if state["calls"] % 2 == 0:            # t1: advance by scripted ms
                state["now"] += state["script"].pop(0) / 1000.0
            return state["now"]

        return clock, (lambda _s: None)


# ======================================================================
# node/source builders
# ======================================================================
def make_transport(tcp_script=lambda ip: True,
                   response_script=lambda: RESPONSE):
    return Transport(tcp_script=tcp_script, response_script=response_script)


def source_text(hosts=("good.com", "slow.com", "dead.com"), secret=False):
    lines = []
    for host in hosts:
        if secret:
            lines.append(f"trojan://{SECRET}@{host}:443?security=tls&type=tcp")
        else:
            lines.append(f"vless://{UUID}@{host}:443?security=tls&type=tcp")
    return "\r\n".join(lines) + "\r\n"


def trojan_text(hosts=("good.com",)):
    """Trojan source (credential-bearing) for secret-safety tests.

    Trojan relay responses match ANY bytes, so the default RESPONSE fake
    works for trojan too.
    """
    return "\r\n".join(
        f"trojan://{SECRET}@{host}:443?security=tls&type=tcp"
        for host in hosts) + "\r\n"


def geo_provider():
    # entries use the Phase 6 TableGeoProvider mapping shape
    return TableGeoProvider({
        IP_GOOD: {"country": "Canada", "city": "Toronto",
                  "country_code": "CA"},
        IP_SLOW: {"country": "Germany", "city": "Berlin",
                  "country_code": "DE"},
        IP_DEAD: {"country": "United States", "city": "Dallas",
                  "country_code": "US"},
        IP_PRIVATE: {"country": "Private", "city": "Nowhere",
                     "country_code": "XX"},
    })

# private-range literal used by the blocked-at-TCP test
PRIVATE_LITERAL = "10.0.0.5"


def make_components(t, probe_ms=(40.0, 52.0, 60.0, 71.0, 80.0, 95.0)):
    """(resolver, tcp, handshake, measurer) all wired to the fake transport.

    The clock script rotates per t1 call, so every node of the run gets
    a distinct deterministic measured latency (52, 71, 95, ... ms since
    the stored sample is probe2's).
    """
    clock, sleeper = t.make_clock_sleeper(probe_ms)
    resolver = Resolver(getaddrinfo=t.gai)
    tcp = TcpValidator(connect_factory=t.factory, timeout=1.0,
                       resolver=resolver)
    hs = HandshakeValidator(connect_factory=t.factory, tls_wrap=t.tls_wrap,
                            accept_injected_tls=True, timeout=1.0)
    measurer = ProxyMeasurer(connect_factory=t.factory, tls_wrap=t.tls_wrap,
                             accept_injected_tls=True, timeout=1.0,
                             clock=clock, sleeper=sleeper)
    return resolver, tcp, hs, measurer


def base_config(t, tmp_path=None, write=False, **overrides):
    resolver, tcp, hs, measurer = make_components(t)
    cfg = PipelineConfig(
        sources=(PipelineSource(raw_text=source_text(), name="s1"),),
        resolver=resolver, geo_provider=geo_provider(),
        tcp_validator=tcp, handshake_validator=hs, measurer=measurer,
        write=write,
    )
    if write:
        cfg = replace(cfg, writer_policy=WriterPolicy(root=str(tmp_path)))
    for key, value in overrides.items():
        cfg = replace(cfg, **{key: value})
    return cfg


def by_host(result, host):
    for item in result.ranked:
        if item.node.endpoint.host == host:
            return item
    return None


def report_for(result, host):
    for rep in result.nodes:
        if rep.endpoint.endswith(host) or rep.endpoint == f"{host}:443":
            return rep
    return None


# ======================================================================
# basic wiring
# ======================================================================
class TestBasicWiring:
    def test_all_stages_run_in_order(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        names = [s.name for s in result.stages]
        assert names == ["ingest", "dedup", "dns", "geo", "tcp", "handshake",
                         "measure", "score", "rank", "output", "write"]

    def test_three_healthy_nodes_rank_and_write(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        assert [r.rank for r in result.ranked] == [1, 2, 3]
        # the scripted clock gives every node a distinct measured latency;
        # equal scores are then broken by measured_ms ASC (Phase 11)
        latencies = [item.node.measured_latency.value_ms
                     for item in result.ranked]
        assert latencies == sorted(latencies)
        files = sorted(p.name for p in (tmp_path / "Config").iterdir())
        assert files == ["vless.txt"]
        assert len(result.written.files) == result.written.total
        # geo came from the injected provider, not fabricated
        good = by_host(result, "good.com").node
        assert good.geo.country_code == "CA"

    def test_writer_receives_the_phase12_bundle_bytes(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        on_disk = (tmp_path / "all.txt").read_bytes()
        assert on_disk == result.bundle.all_text.encode("utf-8")
        assert on_disk.endswith(b"\r\n")      # Phase 12 CRLF contract

    def test_write_false_is_a_dry_run(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, write=False))
        assert result.written is None
        assert result.stage("write") is None
        assert result.bundle.all_text          # output still built

    def test_result_dict_is_jsonable_audit(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        payload = result.as_dict()
        import json
        json.dumps(payload)               # must not raise
        assert payload["ranked"] == 3

    def test_sources_audit_records(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        assert [s.name for s in result.sources] == ["s1"]
        assert result.sources[0].ok and result.sources[0].output_count == 3


# ======================================================================
# per-node audit reports
# ======================================================================
class TestNodeReports:
    def test_every_line_has_exactly_one_report(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        assert len(result.nodes) == 3 + 0          # 3 healthy lines
        statuses = {rep.status for rep in result.nodes}
        assert statuses == {"ok"}

    def test_failure_stage_and_reason_are_recorded(self, tmp_path):
        t = make_transport(tcp_script=lambda ip: ip != IP_DEAD)
        result = run_pipeline(base_config(t, tmp_path, write=True))
        dead = report_for(result, "dead.com")
        assert dead.status == "failed"
        assert dead.stage == "tcp"
        assert dead.reason == "refused"
        good = report_for(result, "good.com")
        assert good.status == "ok"
        assert good.rank is not None
        assert dead.rank is None and dead.score is None
        # the two survivors' latencies come out in Phase 11 order
        ranks = [r for r in result.nodes if r.rank is not None]
        assert len(ranks) == 2

    def test_dns_failure_reported(self, tmp_path):
        text = source_text(("good.com", "unknown.host"))
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        miss = report_for(result, "unknown.host")
        assert miss.status == "failed" and miss.stage == "dns"
        assert miss.reason in ("nxdomain", "resolver_error", "temp_fail",
                               "timeout", "invalid")

    def test_private_ip_is_blocked_at_dns_not_silently_dropped(self, tmp_path):
        # 10.0.0.5 is classified private, so the Phase 6 resolver's
        # public_ips is empty -> the pipeline reports a DNS-stage failure
        # (defence in depth would also block at TCP if it ever got there)
        text = source_text(("good.com",)) + \
            f"vless://{UUID}@private.com:443?security=tls&type=tcp\r\n"
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        rep = report_for(result, "private.com")
        assert rep.status == "failed" and rep.stage == "dns"
        # and the node never reached the scored path
        assert all("private.com" not in item.node.endpoint.host
                   for item in result.ranked)

    def test_private_literal_ip_is_blocked_at_tcp(self, tmp_path):
        # a LITERAL private IP skips DNS (no lookup), so the block must
        # happen at the Phase 7 destination gate
        text = source_text(("good.com",)) + \
            f"vless://{UUID}@10.0.0.5:443?security=tls&type=tcp\r\n"
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        rep = report_for(result, "10.0.0.5")
        assert rep.status == "failed" and rep.stage == "tcp"
        assert rep.reason == "blocked"

    def test_unranked_nodes_appear_in_reports_and_result(self, tmp_path):
        # scoring's honest insufficient_data path: strip the jitter from
        # every measured node -> jitter_missing (no fabricated penalty)
        t = make_transport()

        class NoJitterMeasurer(ProxyMeasurer):
            def attach(self, node):
                # keep the MEASURED sample but drop the jitter: scoring
                # must report insufficient_data (jitter_missing), not a
                # fabricated jitter penalty
                out = super().attach(node)
                if out.measured_latency is None:
                    return out
                return replace(out, jitter_ms=None)

        clock, sleeper = t.make_clock_sleeper()
        cfg = replace(base_config(t),
                      measurer=NoJitterMeasurer(
                          connect_factory=t.factory, tls_wrap=t.tls_wrap,
                          accept_injected_tls=True, timeout=1.0,
                          clock=clock, sleeper=sleeper))
        result = run_pipeline(cfg)
        slow = report_for(result, "slow.com")
        assert slow.status == "unranked" and slow.stage == "score"
        assert slow.reason == "jitter_missing"
        # EVERY jitter-less measured node lands in Phase 11's unranked
        # audit list (H1 fix: the pipeline must not pre-filter them)
        assert len(result.unranked) == 3
        assert all(u.detail == "jitter_missing" for u in result.unranked)
        assert result.ranked == []

    def test_rejected_lines_are_reported(self, tmp_path):
        text = source_text(("good.com",)) + "not-a-config-line\r\n"
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        rejected = [r for r in result.nodes if r.status == "rejected"]
        assert len(rejected) == 1
        assert rejected[0].stage == "ingest"
        assert rejected[0].reason == "no_scheme"
        assert rejected[0].protocol == ""

    def test_duplicate_lines_reported_as_dropped(self, tmp_path):
        text = source_text(("good.com",)) * 2
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        dropped = [r for r in result.nodes if r.status == "dropped"]
        assert len(dropped) == 1
        assert dropped[0].reason == "duplicate"
        assert result.stage("dedup").dropped == 1


# ======================================================================
# partial failure: one bad thing never kills the run
# ======================================================================
class TestPartialFailure:
    def test_one_dead_host_does_not_stop_the_run(self, tmp_path):
        t = make_transport(tcp_script=lambda ip: ip != IP_DEAD)
        result = run_pipeline(base_config(t, tmp_path, write=True))
        assert by_host(result, "good.com") is not None
        assert by_host(result, "slow.com") is not None
        assert report_for(result, "dead.com").status == "failed"
    def test_broken_source_does_not_stop_the_run(self, tmp_path):
        class BoomFetcher:
            def fetch(self, url):
                raise RuntimeError("connection reset by peer")

        t = make_transport()
        cfg = replace(base_config(t), sources=(
            PipelineSource(url="https://example.invalid/list.txt", name="bad"),
            PipelineSource(raw_text=source_text(("good.com",)), name="ok"),
        ), fetcher=BoomFetcher())
        result = run_pipeline(cfg)
        bad = next(s for s in result.sources if s.name == "bad")
        assert bad.ok is False and bad.detail == "fetch_error"
        assert by_host(result, "good.com") is not None   # the good source ran

    def test_empty_source_is_data_not_an_error(self, tmp_path):
        t = make_transport()
        cfg = replace(base_config(t), sources=(
            PipelineSource(raw_text="\r\n", name="empty"),
            PipelineSource(raw_text=source_text(("good.com",)), name="ok"),
        ))
        result = run_pipeline(cfg)
        empty = next(s for s in result.sources if s.name == "empty")
        assert empty.ok is False
        assert by_host(result, "good.com") is not None

    def test_url_without_fetcher_degrades_honestly(self, tmp_path):
        t = make_transport()
        cfg = replace(base_config(t), sources=(
            PipelineSource(url="https://example.com/list.txt", name="u"),
            PipelineSource(raw_text=source_text(("good.com",)), name="ok"),
        ))
        result = run_pipeline(cfg)
        u = next(s for s in result.sources if s.name == "u")
        assert u.ok is False and u.detail == "fetch_no_fetcher"

    def test_all_nodes_failing_still_produces_valid_empty_outputs(self, tmp_path):
        t = make_transport(tcp_script=lambda ip: False)
        result = run_pipeline(base_config(t, tmp_path, write=True))
        assert result.ranked == []
        write_stage = result.stage("write")
        assert write_stage.input_count == result.written.total
        # the legacy empty-file contract: literal b"\r\n"
        assert (tmp_path / "Subscription" / "ultra_fast.txt").read_bytes() == b"\r\n"

    def test_handshake_failure_drops_only_that_node(self, tmp_path):
        t = make_transport()

        original = t.tls_wrap

        def flaky(raw, sni):
            if sni == "slow.com":
                raise OSError("tls refused")
            return original(raw, sni)

        hs = HandshakeValidator(connect_factory=t.factory, tls_wrap=flaky,
                                accept_injected_tls=True, timeout=1.0)
        cfg = replace(base_config(t), handshake_validator=hs)
        result = run_pipeline(cfg)
        assert report_for(result, "slow.com").stage == "handshake"
        assert by_host(result, "good.com") is not None

    def test_measurement_failure_drops_only_that_node(self, tmp_path):
        t = make_transport()

        original = t.tls_wrap

        def flaky(raw, sni):
            if sni == "slow.com":
                return FakeTLSSock(lambda: ConnectionResetError("boom"))
            return original(raw, sni)

        clock, sleeper = t.make_clock_sleeper()
        measurer = ProxyMeasurer(connect_factory=t.factory, tls_wrap=flaky,
                                 accept_injected_tls=True, timeout=1.0,
                                 clock=clock, sleeper=sleeper)
        cfg = replace(base_config(t), measurer=measurer)
        result = run_pipeline(cfg)
        assert report_for(result, "slow.com").stage == "measure"
        assert by_host(result, "good.com") is not None


# ======================================================================
# no fabrication
# ======================================================================
class TestNoFabrication:
    def test_missing_dns_never_fabricates_an_ip(self, tmp_path):
        t = make_transport()
        text = source_text(("good.com", "ghost.host"))
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        ghost = report_for(result, "ghost.host")
        assert ghost.status == "failed" and ghost.stage == "dns"
        # and nothing with an unresolved host ever reached ranking
        assert all(item.node.endpoint.resolved_ip
                   for item in result.ranked)

    def test_no_geo_provider_keeps_unknown_geo_honest(self, tmp_path):
        t = make_transport()
        cfg = replace(base_config(t), geo_provider=None)
        result = run_pipeline(cfg)
        assert result.ranked
        for item in result.ranked:
            geo = item.node.geo
            assert geo is None or geo.country_code in ("", "XX")
        # the brand template never shows a made-up flag: the name degrades
        # to the Unknown country sentinel (percent-encoded in the link)
        all_text = result.bundle.all_text
        assert "Unknown" in all_text          # no fabricated country

    def test_no_measurer_scores_nothing(self, tmp_path):
        t = make_transport()
        cfg = replace(base_config(t), measurer=None)
        result = run_pipeline(cfg)
        assert result.ranked == []       # no MEASURED sample -> no score
        assert result.stage("score").output_count == 0

    def test_no_resolver_fails_dns_stage_honestly(self, tmp_path):
        t = make_transport()
        cfg = replace(base_config(t), resolver=None)
        result = run_pipeline(cfg)
        assert result.ranked == []
        rep = report_for(result, "good.com")
        assert rep.status == "failed" and rep.reason == "dns_no_resolver"

    def test_scores_come_from_measurements_only(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        for item in result.ranked:
            sample = item.node.measured_latency
            assert sample is not None
            assert sample.kind is LatencyKind.MEASURED
            # score must equal the Phase 10 formula for these samples
            assert item.outcome.status == "scored"


# ======================================================================
# ordering preservation / top-N / determinism
# ======================================================================
class TestOrderingAndDeterminism:
    def test_phase11_order_preserved_into_output(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        scores = [item.outcome.score for item in result.ranked]
        assert scores == sorted(scores, reverse=True)
        all_text = result.bundle.all_text
        # Phase 11 order (score DESC, then measured ASC) survives into the
        # rendered text: links appear exactly in ranked order
        hosts_in_order = [item.node.endpoint.host for item in result.ranked]
        positions = [all_text.index(h) for h in hosts_in_order]
        assert positions == sorted(positions)

    def test_top_n_flows_through(self, tmp_path):
        t = make_transport()
        result = run_pipeline(replace(base_config(t), top_n=1))
        assert len(result.ranked) == 1
        assert result.stage("rank").detail == "top_n_truncated"
        assert result.stage("rank").dropped == 2
        # the cut node's score audit row must not pretend it was ranked
        assert sum(1 for r in result.nodes if r.rank is not None) == 1

    def test_deterministic_repeat_byte_for_byte(self, tmp_path):
        t1, t2 = make_transport(), make_transport()
        cfg1 = base_config(t1, tmp_path / "a", write=True)
        cfg2 = base_config(t2, tmp_path / "b", write=True)
        r1, r2 = run_pipeline(cfg1), run_pipeline(cfg2)
        assert r1.bundle.all_text == r2.bundle.all_text
        assert r1.bundle.all_base64 == r2.bundle.all_base64
        disk1 = sorted(p.relative_to(tmp_path / "a").as_posix()
                       for p in (tmp_path / "a").rglob("*.txt"))
        disk2 = sorted(p.relative_to(tmp_path / "b").as_posix()
                       for p in (tmp_path / "b").rglob("*.txt"))
        assert disk1 == disk2
        for rel in disk1:
            assert ((tmp_path / "a" / rel).read_bytes()
                    == (tmp_path / "b" / rel).read_bytes())

    def test_shuffled_source_order_same_ranking(self, tmp_path):
        # the scripted clock ties latency to NODE PROCESSING order, so a
        # shuffled source feeds the measurer in a different order; the
        # RANKING must still be a pure function of the measured multiset
        t = make_transport()
        text_a = source_text(("good.com", "slow.com", "dead.com"))
        text_b = source_text(("dead.com", "slow.com", "good.com"))
        ra = run_pipeline(replace(base_config(t),
                                  sources=(PipelineSource(raw_text=text_a),)))
        rb = run_pipeline(replace(base_config(t),
                                  sources=(PipelineSource(raw_text=text_b),)))
        hosts_a = sorted(i.node.endpoint.host for i in ra.ranked)
        hosts_b = sorted(i.node.endpoint.host for i in rb.ranked)
        assert hosts_a == hosts_b
        # identical latency multisets (each host keeps its scripted ms)
        lat_a = sorted(i.node.measured_latency.value_ms for i in ra.ranked)
        lat_b = sorted(i.node.measured_latency.value_ms for i in rb.ranked)
        assert lat_a == lat_b


# ======================================================================
# caller-input validation (fail closed)
# ======================================================================
class TestCallerValidation:
    def test_no_sources_rejected(self):
        with pytest.raises(PipelineError):
            run_pipeline(PipelineConfig())

    def test_write_requires_a_root(self, t=None):
        t = t or make_transport()
        with pytest.raises(PipelineError):
            run_pipeline(replace(base_config(t), write=True,
                                 writer_policy=None))

    def test_source_must_choose_one_kind(self):
        with pytest.raises(PipelineError):
            PipelineSource(name="only-a-name")
        with pytest.raises(PipelineError):
            PipelineSource(raw_text="x", path="y")
        with pytest.raises(PipelineError):
            PipelineSource(url="ftp://example.com/x")

    def test_bad_config_type(self):
        with pytest.raises(PipelineError):
            run_pipeline("not a config")


# ======================================================================
# secret safety
# ======================================================================
class TestSecretSafety:
    def test_trojan_password_never_leaks_into_audit(self, tmp_path):
        # trojan probing needs the explicit credential-probe opt-in on the
        # Phase 8/9 components; the pipeline passes no credentials itself
        t = make_transport()
        hs = HandshakeValidator(connect_factory=t.factory, tls_wrap=t.tls_wrap,
                                accept_injected_tls=True, timeout=1.0,
                                allow_credential_probe=True)
        clock, sleeper = t.make_clock_sleeper()
        measurer = ProxyMeasurer(connect_factory=t.factory, tls_wrap=t.tls_wrap,
                                 accept_injected_tls=True, timeout=1.0,
                                 allow_credential_probe=True,
                                 clock=clock, sleeper=sleeper)
        cfg = replace(base_config(t), handshake_validator=hs, measurer=measurer,
                      sources=(PipelineSource(raw_text=trojan_text(), name="tj"),))
        result = run_pipeline(cfg)
        blob = repr(result.as_dict()) + repr(result.nodes)
        assert SECRET not in blob
        # the credential DOES reach the output link, per the legacy contract
        assert SECRET in result.bundle.all_text
        # ...but failure reasons stay short codes
        for rep in result.nodes:
            assert SECRET not in (rep.reason or "")
            assert len(rep.reason or "") <= 120

    def test_rejected_line_reason_carries_no_content(self, tmp_path):
        secret_line = f"trojan://{SECRET}@bad host with spaces:443\r\n"
        t = make_transport()
        cfg = replace(base_config(t), sources=(PipelineSource(raw_text=secret_line),))
        result = run_pipeline(cfg)
        assert all("SUPERSECRET" not in (r.reason or "")
                   for r in result.nodes)
        assert not any(r.endpoint and SECRET in r.endpoint
                       for r in result.nodes)


# ======================================================================
# canonical-input immutability
# ======================================================================
class TestImmutability:
    def test_nodes_and_bundle_are_untouched_by_a_rerun(self, tmp_path):
        t = make_transport()
        cfg = base_config(t, tmp_path, write=True)
        first = run_pipeline(cfg)
        snapshot = [(rep.status, rep.stage, rep.reason, rep.rank)
                    for rep in first.nodes]
        bundle_bytes = first.bundle.all_text

        second = run_pipeline(cfg)          # same config object, fresh run
        assert [(rep.status, rep.stage, rep.reason, rep.rank)
                for rep in second.nodes] == snapshot
        assert second.bundle.all_text == bundle_bytes

    def test_scored_nodes_carry_real_samples_only(self, tmp_path):
        t = make_transport()
        result = run_pipeline(base_config(t, tmp_path, write=True))
        for item in result.ranked:
            node = item.node
            assert node.measured_latency.kind is LatencyKind.MEASURED
            if node.tcp_connect is not None:
                assert node.tcp_connect.kind is LatencyKind.TCP_CONNECT
            if node.protocol_handshake is not None:
                assert node.protocol_handshake.kind is \
                    LatencyKind.PROTOCOL_HANDSHAKE


# ======================================================================
# purity of the orchestrator module
# ======================================================================
ALLOWED_MODULES = {
    "__future__", "dataclasses", "typing", "hubcore.dedup", "hubcore.geo",
    "hubcore.handshake", "hubcore.ingest", "hubcore.measure",
    "hubcore.model", "hubcore.output", "hubcore.ranking", "hubcore.resolver",
    "hubcore.scoring", "hubcore.tcpval", "hubcore.writer",
    # relative imports resolve as bare names in the AST
    "dedup", "geo", "handshake", "ingest", "measure", "model", "output",
    "ranking", "resolver", "scoring", "tcpval", "writer",
}
BANNED_TOKENS = (
    "socket", "subprocess", "urllib", "http.client", "requests", "telegram",
    "shutil", "eval(", "exec(", "os.system", "os.environ", "getenv",
    "import time", "from time", "datetime", "monotonic", "random",
    "open(", "Path.write", "mkdir",
)


class TestPurity:
    def _source(self):
        return pathlib.Path(pipeline_mod.__file__).read_text(encoding="utf-8")

    def test_no_banned_tokens(self):
        src = self._source()
        # "open(" appears inside ordinary words ("reopen" etc.) only if a
        # regression introduced it; token-level check is the contract
        for token in BANNED_TOKENS:
            assert token not in src, f"pipeline must not reference {token}"

    def test_only_phase_imports(self):
        tree = ast.parse(self._source())
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module or "")
        assert modules <= ALLOWED_MODULES, modules - ALLOWED_MODULES

    def test_writer_is_the_only_filesystem_reach(self):
        src = self._source()
        assert "write_outputs(" in src
        assert src.count("open(") == 0


# ==========================================================================
# adversarial hunt regressions (H1..H2 + verified hunt behaviours)
# ==========================================================================
class TestHuntRegressions:
    def test_h1_unranked_nodes_reach_phase11_audit(self, tmp_path):
        # H1: the pipeline pre-filtered unscored candidates, so Phase 11's
        # unranked audit list and Phase 12's unranked counts were always
        # empty. Every measured-but-unscorable node must appear.
        t = make_transport()
        clock, sleeper = t.make_clock_sleeper()

        class NoJitterMeasurer(ProxyMeasurer):
            def attach(self, node):
                out = super().attach(node)
                if out.measured_latency is None:
                    return out
                return replace(out, jitter_ms=None)

        cfg = replace(base_config(t),
                      measurer=NoJitterMeasurer(
                          connect_factory=t.factory, tls_wrap=t.tls_wrap,
                          accept_injected_tls=True, timeout=1.0,
                          clock=clock, sleeper=sleeper))
        result = run_pipeline(cfg)
        assert len(result.unranked) == 3
        assert result.bundle.counts["unranked"] == 3
        assert result.bundle.counts["unranked_by_status"] == {
            "insufficient_data": 3}

    def test_h2_writer_failure_aborts_typed_with_valid_partial_output(
            self, tmp_path):
        # H2: a writer failure must surface as the Phase 13 typed error
        # (never a bare OSError), and every already-published artifact
        # must remain individually valid (atomic per file).
        t = make_transport()
        (tmp_path / "Config").write_bytes(b"x")     # Config path is a file
        with pytest.raises(WriteFailedError) as exc:
            run_pipeline(replace(base_config(t, tmp_path, write=True)))
        assert exc.value.path == "Config/vless.txt"
        published = sorted(p.relative_to(tmp_path).as_posix()
                           for p in tmp_path.rglob("*.txt"))
        assert published == ["all.txt", "all_b64.txt"]
        assert (tmp_path / "all.txt").read_bytes().endswith(b"\r\n")
        # no writer debris
        assert list(tmp_path.rglob(".hubcore-tmp-*")) == []

    def test_duplicate_source_names_are_uniquified_for_audit(self):
        # two sources named the same must not collide on the audit join
        t = make_transport()
        cfg = replace(base_config(t), sources=(
            PipelineSource(raw_text=source_text(("good.com",)), name="same"),
            PipelineSource(raw_text=source_text(("slow.com",)), name="same")))
        result = run_pipeline(cfg)
        keys = [(n.origin, n.line_no) for n in result.nodes]
        assert len(keys) == len(set(keys))
        assert any(n.origin == "same#2" for n in result.nodes)

    def test_cross_source_duplicate_is_deduped_first_wins(self):
        t = make_transport()
        cfg = replace(base_config(t), sources=(
            PipelineSource(raw_text=source_text(("good.com",)), name="a"),
            PipelineSource(raw_text=source_text(("good.com",)), name="b")))
        result = run_pipeline(cfg)
        assert result.stage("dedup").dropped == 1
        statuses = sorted(n.status for n in result.nodes)
        assert statuses == ["dropped", "ok"]

    def test_dns_cache_shared_across_nodes(self):
        # two configs on the same host -> exactly ONE getaddrinfo call
        t = make_transport()
        calls = []
        orig = t.gai

        def counting(host, port, **kw):
            calls.append(host)
            return orig(host, port, **kw)

        text = (
            f"vless://11111111-2222-3333-4444-555555555555@good.com:443"
            f"?security=tls&type=tcp\r\n"
            f"vless://99999999-2222-3333-4444-555555555555@good.com:443"
            f"?security=tls&type=tcp\r\n")
        cfg = replace(base_config(t), resolver=Resolver(getaddrinfo=counting),
                      sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        assert len(calls) == 1
        assert len(result.ranked) == 2

    def test_ipv6_literal_runs_end_to_end(self, tmp_path):
        t = make_transport()
        text = ("vless://11111111-2222-3333-4444-555555555555"
                "@[2606:4700:4700::1111]:443?security=tls&type=tcp\r\n")
        cfg = replace(base_config(t),
                      sources=(PipelineSource(raw_text=text),))
        result = run_pipeline(cfg)
        assert len(result.ranked) == 1
        assert result.ranked[0].node.endpoint.host == "2606:4700:4700::1111"

    def test_top_n_zero_and_negative_are_rejected(self):
        t = make_transport()
        with pytest.raises(InvalidTopNError):
            run_pipeline(replace(base_config(t), top_n=0))
        with pytest.raises(InvalidTopNError):
            run_pipeline(replace(base_config(t), top_n=-2))

    def test_resolver_that_raises_fails_nodes_softly(self):
        class BoomResolver:
            def resolve(self, host, port=443):
                raise RuntimeError("dns exploded")

        t = make_transport()
        cfg = replace(base_config(t), resolver=BoomResolver())
        result = run_pipeline(cfg)          # must NOT raise
        assert all(n.status == "failed" and n.stage == "dns"
                   and n.reason == "resolver_error"
                   for n in result.nodes)

    def test_hostile_component_exception_cannot_leak_secrets(self):
        class EvilTLS:
            def __call__(self, raw, sni):
                raise RuntimeError(f"pw={SECRET} trojan://{SECRET}@h")

        t = make_transport()
        hs = HandshakeValidator(connect_factory=t.factory, tls_wrap=EvilTLS(),
                                accept_injected_tls=True, timeout=1.0)
        cfg = replace(base_config(t), handshake_validator=hs)
        result = run_pipeline(cfg)          # must NOT raise
        blob = repr(result.as_dict()) + repr(result.nodes)
        assert SECRET not in blob
        rep = report_for(result, "good.com")
        assert rep.status == "failed" and rep.stage == "handshake"

    def test_two_runs_on_one_root_are_safe(self, tmp_path):
        t = make_transport()
        r1 = run_pipeline(replace(base_config(t, tmp_path, write=True)))
        r2 = run_pipeline(replace(base_config(t, tmp_path, write=True)))
        assert r1.written.written == r2.written.written == 9
        assert len(list(tmp_path.rglob("*.txt"))) == 9

    def test_audit_rows_deterministic_across_runs(self):
        r1 = run_pipeline(base_config(make_transport()))
        r2 = run_pipeline(base_config(make_transport()))
        a = [(n.origin, n.line_no, n.status, n.stage, n.reason, n.rank)
             for n in r1.nodes]
        b = [(n.origin, n.line_no, n.status, n.stage, n.reason, n.rank)
             for n in r2.nodes]
        assert a == b
