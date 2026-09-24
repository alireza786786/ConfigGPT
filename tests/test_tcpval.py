# -*- coding: utf-8 -*-
"""Phase 7 tests: pinned TCP validation (fully offline, injected factory)."""
from dataclasses import replace

import pytest

from hubcore import (
    AttemptReport,
    LatencyKind,
    Node,
    Protocol,
    TcpValidator,
    parse_url,
)
from hubcore.tcpval import _short_error
import socket

UUID = "11111111-2222-3333-4444-555555555555"


def node(host="example.com", ip=None, port=443):
    n = parse_url(f"vless://{UUID}@{host}:{port}")
    if ip:
        ep = replace(n.endpoint, resolved_ip=ip)
        n = replace(n, endpoint=ep)
    return n


class FakeSock:
    def __init__(self, behavior):
        self._behavior = behavior   # None=ok, Exception=raise
        self.closed = False
        self.settimeout_called = None

    def settimeout(self, t):
        self.settimeout_called = t

    def connect(self, addr):
        if isinstance(self._behavior, Exception):
            raise self._behavior

    def close(self):
        self.closed = True


def factory_script(script: dict, calls: list):
    """script: (ip) -> behavior(None or Exception); records every call."""
    def factory(family, socktype, target, port, timeout):
        calls.append((family, target, port, timeout))
        return FakeSock(script.get(target))
    return factory


class TestPinning:
    def test_connects_to_resolved_ip_not_hostname(self):
        calls = []
        f = factory_script({"93.184.216.34": None}, calls)
        v = TcpValidator(connect_factory=f, timeout=1.5)
        out = v.validate(node(host="example.com", ip="93.184.216.34"))
        assert out.ok
        # the OS was asked to connect to the PINNED IP, never the hostname
        assert calls[0][1] == "93.184.216.34"
        assert out.pinned_ip == "93.184.216.34"
        # identity hostname preserved for SNI/Host in later phases
        assert out.identity_hostname == "example.com"

    def test_no_silent_hostname_fallback(self):
        # no resolved_ip and literal host: fail closed, no connect at all
        calls = []
        f = factory_script({}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="example.com", ip=None))
        assert not out.ok
        assert out.error == "no_pinned_ip"
        assert calls == []          # nothing dialed

    def test_explicit_hostname_optin(self):
        calls = []
        f = factory_script({"example.com": None}, calls)
        v = TcpValidator(connect_factory=f, allow_direct_hostname=True)
        out = v.validate(node(host="example.com", ip=None))
        assert out.ok
        assert calls[0][1] == "example.com"
        assert out.error == ""

    def test_literal_host_is_its_own_pin(self):
        calls = []
        f = factory_script({"8.8.8.8": None}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="8.8.8.8", ip=None))
        assert out.ok and out.pinned_ip == "8.8.8.8"
        assert calls[0][1] == "8.8.8.8"

    def test_validate_and_attach_pins_working_ip(self):
        f = factory_script({"1.2.3.4": None}, [])
        v = TcpValidator(connect_factory=f)
        n0 = node(host="example.com", ip="1.2.3.4")
        n1, out = v.validate_and_attach(n0)
        assert out.ok
        assert n1.endpoint.resolved_ip == "1.2.3.4"
        assert n1.tcp_connect is not None
        assert n1.tcp_connect.kind is LatencyKind.TCP_CONNECT
        assert n1.endpoint.host == "example.com"   # SNI identity intact


class TestFamilies:
    def test_ipv6_pinned(self):
        calls = []
        f = factory_script({"2001:4860:4860::8888": None}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="v6.example.com", ip="2001:4860:4860::8888"))
        assert out.ok
        assert calls[0][0] == socket.AF_INET6
        assert calls[0][1] == "2001:4860:4860::8888"

    def test_mixed_endpoint_v4_first_then_v6(self):
        # resolved list not directly supported by model (single resolved_ip),
        # but the internal ordering helper is pinned by test
        ordered = TcpValidator._order_for_dialing(
            ["2001:db8::1", "1.2.3.4", "2606:4700::10", "9.9.9.9"])
        assert [t for t, _ in ordered] == ["1.2.3.4", "9.9.9.9",
                                           "2001:db8::1", "2606:4700::10"]

    def test_partial_failure_then_success(self):
        # policy first: a private ULA address is BLOCKED without dialing
        # (regression for the blocked-not-refused contract)
        calls = []
        f = factory_script({"fd00::5": socket.error(10061, "refused")}, calls)
        v = TcpValidator(connect_factory=f, allow_direct_hostname=False)
        out = v.validate(node(host="h", ip="fd00::5"))
        assert not out.ok and out.attempts[0].error == "blocked"
        assert calls == []                     # never dialed
        # a public v6 address still validates (independent per-address)
        out_ok = v.validate(node(host="h", ip="2606:4700::10"))
        assert out_ok.ok


class TestPolicyAndErrors:
    def test_private_targets_blocked_not_dialed(self):
        calls = []
        f = factory_script({}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="x", ip="10.1.2.3"))
        assert not out.ok
        assert out.attempts[0].error == "blocked"
        assert out.any_attempt_blocked
        assert calls == []                       # never dialed

    def test_loopback_blocked(self):
        v = TcpValidator(connect_factory=factory_script({}, []))
        out = v.validate(node(host="x", ip="127.0.0.1"))
        assert out.attempts[0].error == "blocked"

    @pytest.mark.parametrize("ip,err", [
        ("1.2.3.4", "timeout"), ("5.6.7.8", "refused"), ("7.7.7.7", "unreachable"),
    ])
    def test_error_mapping(self, ip, err):
        script = {ip: {"timeout": TimeoutError(),
                       "refused": socket.error(10061, "refused"),
                       "unreachable": socket.error(10051, "unreachable")}[err]}
        v = TcpValidator(connect_factory=factory_script(script, []))
        out = v.validate(node(host="x", ip=ip))
        assert not out.ok and out.attempts[0].error == err

    def test_aggregate_verdict(self):
        script = {"1.2.3.4": socket.error(10061, "refused")}
        v = TcpValidator(connect_factory=factory_script(script, []))
        out = v.validate(node(host="x", ip="1.2.3.4"))
        assert not out.ok and out.error == "refused"
        # deterministic: same inputs -> same verdict
        out2 = v.validate(node(host="x", ip="1.2.3.4"))
        assert out2.error == out.error

    def test_short_error_never_leaks_os_text(self):
        exc = socket.error(10061, "super internal winsock detail SECRET")
        assert _short_error(exc) == "refused"
        # and the report keeps only the code:
        v = TcpValidator(connect_factory=factory_script(
            {"1.2.3.4": exc}, []))
        out = v.validate(node(ip="1.2.3.4"))
        blob = repr(out.attempts)
        assert "SECRET" not in blob and "winsock" not in blob


class TestResources:
    def test_socket_closed_on_success(self):
        holder = {}
        def factory(family, socktype, target, port, timeout):
            s = FakeSock(None)
            holder["sock"] = s
            return s
        v = TcpValidator(connect_factory=factory)
        out = v.validate(node(ip="1.2.3.4"))
        assert out.ok and holder["sock"].closed

    def test_socket_closed_on_failure(self):
        holder = {}
        def factory(family, socktype, target, port, timeout):
            s = FakeSock(socket.error(10061, "refused"))
            holder["sock"] = s
            return s
        v = TcpValidator(connect_factory=factory)
        out = v.validate(node(ip="1.2.3.4"))
        assert not out.ok and holder["sock"].closed

    def test_close_raising_still_contained(self):
        class Evil(FakeSock):
            def close(self):
                raise RuntimeError("close blew up")
        def factory(family, socktype, target, port, timeout):
            return Evil(None)
        v = TcpValidator(connect_factory=factory)
        out = v.validate(node(ip="1.2.3.4"))
        assert out.ok          # close() explosion must not flip the verdict

    def test_timeout_value_passed_to_socket(self):
        calls = []
        f = factory_script({"1.2.3.4": None}, calls)
        v = TcpValidator(connect_factory=f, timeout=2.25)
        v.validate(node(ip="1.2.3.4"))
        assert calls[0][3] == 2.25


class TestContract:
    def test_latency_kind_is_tcp_connect_not_proxy(self):
        v = TcpValidator(connect_factory=factory_script({"1.2.3.4": None}, []))
        _, out = TcpValidator(connect_factory=factory_script({"1.2.3.4": None}, [])
                              ).validate_and_attach(node(ip="1.2.3.4"))
        assert out.latency.kind is LatencyKind.TCP_CONNECT
        assert out.latency.kind is not LatencyKind.PROTOCOL_HANDSHAKE

    def test_rebinding_guard(self):
        # endpoint resolved_ip pinned -> hostname NEVER dialed even though
        # DNS could say otherwise; identity stays for SNI
        calls = []
        f = factory_script({"93.184.216.34": None}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="rebindable.example.com", ip="93.184.216.34"))
        assert out.ok
        assert [c[1] for c in calls] == ["93.184.216.34"]
        assert out.identity_hostname == "rebindable.example.com"

    def test_deterministic_reports(self):
        v = TcpValidator(connect_factory=factory_script({"1.2.3.4": None}, []))
        a = v.validate(node(ip="1.2.3.4"))
        b = v.validate(node(ip="1.2.3.4"))
        assert [(x.target_ip, x.ok, x.error) for x in a.attempts] == \
               [(x.target_ip, x.ok, x.error) for x in b.attempts]

    def test_missing_everything(self):
        v = TcpValidator(connect_factory=factory_script({}, []))
        n = parse_url(f"vless://{UUID}@h:443")
        out = v.validate(n)
        assert not out.ok and out.error == "no_pinned_ip"


class TestRegressionAdversarial:
    """Regressions for real bugs found during Phase 7 adversarial bug-hunt."""

    def test_regression_factory_connect_was_never_called(self):
        """BUG: _attempt only created the socket and reported ok=True
        without ever dialing — injected fakes observed zero connects and
        every validation "succeeded". Fix: validator performs connect()
        itself and times exactly that call."""
        calls = []
        script = {"9.9.9.9": socket.error(10061, "refused")}
        f = factory_script(script, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="x", ip="9.9.9.9"))
        assert calls, "factory must be invoked"
        assert not out.ok and out.attempts[0].error == "refused"

    def test_regression_unknown_ip_never_dialed(self):
        """BUG: non-IP strings (e.g. octal '0177.0.0.1' that the OS could
        interpret as 127.0.0.1) were handed to the dial path. Fix:
        unparseable targets fail with 'invalid_ip', never dialed."""
        calls = []
        f = factory_script({}, calls)
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="x", ip="0177.0.0.1"))
        assert not out.ok and out.attempts[0].error == "invalid_ip"
        assert calls == []

    def test_regression_hostname_dial_not_pinned_into_resolved_ip(self):
        """BUG: hostname opt-in success wrote the hostname into
        resolved_ip via validate_and_attach. Fix: only genuine IP
        literals pin resolved_ip."""
        f = factory_script({"example.com": None}, [])
        v = TcpValidator(connect_factory=f, allow_direct_hostname=True)
        n0 = node(host="example.com", ip=None)
        n1, out = v.validate_and_attach(n0)
        assert out.ok and out.used_hostname_dial
        assert n1.endpoint.resolved_ip is None   # not polluted
        assert n1.tcp_connect is not None        # sample still recorded

    def test_regression_exotic_exception_mapped_no_leak(self):
        """BUG-adjacent hardening: a non-OSError from the injected factory
        maps to a short code; OS/vendored text must never surface and the
        run must not crash."""
        import os as _os
        f = factory_script({"6.6.6.6": _os.error(10022, "C:\\vendored\\detail")}, [])
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="x", ip="6.6.6.6"))
        assert not out.ok and out.attempts[0].error == "os_error"
        assert "10022" not in repr(out.attempts) and "vendored" not in repr(out.attempts)

    def test_regression_gaierror_mapped_resolve(self):
        f = factory_script({"4.4.4.4": socket.gaierror(8, "lookup detail")}, [])
        v = TcpValidator(connect_factory=f)
        out = v.validate(node(host="x", ip="4.4.4.4"))
        assert not out.ok and out.attempts[0].error == "resolve"
        assert "lookup detail" not in repr(out.attempts)

    def test_aggregate_policy_pins_priority(self):
        # POLICY: a specific error (refused > blocked > unreachable) beats
        # the generic timeout; timeout wins only when ALL attempts timed
        # out; no errors at all -> "unknown"
        attempts = [
            AttemptReport(target_ip="1.1.1.1", version=4, ok=False, error="unreachable"),
            AttemptReport(target_ip="2.2.2.2", version=4, ok=False, error="refused"),
            AttemptReport(target_ip="3.3.3.3", version=4, ok=False, error="blocked"),
            AttemptReport(target_ip="4.4.4.4", version=4, ok=False, error="timeout"),
        ]
        assert TcpValidator._aggregate_error(attempts) == "refused"
        assert TcpValidator._aggregate_error(attempts[:3]) == "refused"
        assert TcpValidator._aggregate_error(attempts[2:]) == "blocked"
        assert TcpValidator._aggregate_error(attempts[:1]) == "unreachable"
        assert TcpValidator._aggregate_error(attempts[3:]) == "timeout"
        assert TcpValidator._aggregate_error(
            [AttemptReport(target_ip="1.1.1.1", version=4, ok=True)]) == "unknown"

    def test_factory_raising_is_contained(self):
        # a factory that explodes must produce a failed attempt, not crash
        def evil_factory(family, socktype, target, port, timeout):
            raise RuntimeError("factory on fire")
        v = TcpValidator(connect_factory=evil_factory)
        out = v.validate(node(ip="1.2.3.4"))
        assert not out.ok and out.attempts[0].error == "os_error"
        assert "fire" not in repr(out.attempts)

    def test_latency_window_covers_connect_not_socket_creation(self):
        # the timed window starts at connect(); a slow factory must not
        # inflate the latency sample (contract: sample == TCP_CONNECT)
        import time as _time
        def slow_factory(family, socktype, target, port, timeout):
            _time.sleep(0.05)     # 50ms of CREATION cost
            return FakeSock(None)
        v = TcpValidator(connect_factory=slow_factory)
        out = v.validate(node(ip="1.2.3.4"))
        assert out.ok and out.latency.value_ms < 50.0
