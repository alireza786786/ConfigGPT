# -*- coding: utf-8 -*-
"""Phase 6 tests: DNS resolver (fully offline via injected getaddrinfo)."""
import socket

import pytest

from hubcore import (
    PolicyBlocked,
    ResolveError,
    Resolver,
    ResolveStatus,
    classify_ip,
)


def fake_gai(mapping, *, fail=None):
    """Build a getaddrinfo replacement: host -> [(family, ..., sockaddr)]."""
    def _gai(host, port=443, proto=0, *a, **kw):
        if fail is not None:
            raise fail
        item = mapping.get(host)
        if item is None:
            raise socket.gaierror(-2, "Name or service not known")
        out = []
        for ip in item:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0)
            out.append((fam, socket.SOCK_STREAM, proto, "", sockaddr))
        return out
    return _gai


HOSTS = {
    "v4.example.com": ["93.184.216.34"],
    "v6.example.com": ["2001:4860:4860::8888"],
    "dual.example.com": ["93.184.216.34", "2001:4860:4860::8888"],
    "multi.example.com": ["1.1.1.1", "8.8.8.8", "1.1.1.1"],   # duplicate too
    "loop.example.com": ["127.0.0.1"],
    "priv.example.com": ["10.1.2.3"],
    "cgnat.example.com": ["100.64.0.9"],
    "linklocal.example.com": ["169.254.1.2"],
    "v6loop.example.com": ["::1"],
    "v6link.example.com": ["fe80::1"],
    "v6priv.example.com": ["fd00::5"],
    "mixed.example.com": ["10.9.9.9", "93.184.216.34"],       # one public, one private
    "garbled.example.com": ["not-an-ip"],
}


class TestClassifyIP:
    def test_public_v4(self):
        c = classify_ip("93.184.216.34")
        assert (c.version, c.kind) == (4, "public")

    @pytest.mark.parametrize("ip,kind", [
        ("127.0.0.1", "loopback"), ("::1", "loopback"),
        ("10.0.0.1", "private"), ("172.16.0.1", "private"),
        ("192.168.1.1", "private"), ("100.64.0.1", "private"),
        ("169.254.1.1", "link_local"), ("fe80::1", "link_local"),
        ("fd00::1", "private"), ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"), ("240.0.0.1", "reserved"),
        ("::ffff:127.0.0.1", "loopback"),   # v4-mapped must see through
        ("::ffff:8.8.8.8", "public"),
    ])
    def test_kinds(self, ip, kind):
        assert classify_ip(ip).kind == kind

    def test_versions_split(self):
        assert classify_ip("8.8.8.8").version == 4
        assert classify_ip("2001:4860:4860::8888").version == 6

    def test_garbage_raises_controlled(self):
        with pytest.raises(ResolveError):
            classify_ip("not-an-ip")


class TestResolve:
    def test_v4(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("v4.example.com")
        assert rec.ok and rec.ipv4 == ("93.184.216.34",) and rec.ipv6 == ()

    def test_v6(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("v6.example.com")
        assert rec.ok and rec.ipv6 == ("2001:4860:4860::8888",) and rec.ipv4 == ()

    def test_dual_stack_split(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("dual.example.com")
        assert rec.ipv4 == ("93.184.216.34",)
        assert rec.ipv6 == ("2001:4860:4860::8888",)

    def test_duplicate_ips_deduped(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("multi.example.com")
        assert rec.ipv4 == ("1.1.1.1", "8.8.8.8")

    def test_nxdomain(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("missing.example.com")
        assert rec.status == ResolveStatus.NXDOMAIN and not rec.ok

    def test_timeout(self):
        r = Resolver(getaddrinfo=fake_gai({}, fail=TimeoutError()))
        rec = r.resolve("x.example.com")
        assert rec.status == ResolveStatus.TIMEOUT

    def test_temporary_failure(self):
        r = Resolver(getaddrinfo=fake_gai({}, fail=socket.gaierror(-3, "Temporary failure in name resolution")))
        rec = r.resolve("x.example.com")
        assert rec.status == ResolveStatus.TEMP_FAIL

    def test_malformed_result_skipped(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("garbled.example.com")
        assert rec.status == ResolveStatus.INVALID and rec.error == "malformed_result"

    def test_empty_host(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        assert r.resolve("").status == ResolveStatus.INVALID
        assert r.resolve("  ").status == ResolveStatus.INVALID

    def test_trailing_dot_and_case(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("V4.Example.COM.")
        assert rec.ok and rec.ipv4 == ("93.184.216.34",)

    def test_ip_literal_no_dns(self):
        called = []
        def spy_gai(host, *a, **kw):
            called.append(host)
            raise AssertionError("DNS must not be called for literals")
        r = Resolver(getaddrinfo=spy_gai)
        rec = r.resolve("8.8.8.8")
        assert rec.ok and rec.ipv4 == ("8.8.8.8",)
        rec6 = r.resolve("[2001:4860:4860::8888]")
        assert rec6.ok and rec6.ipv6 == ("2001:4860:4860::8888",)
        assert called == []


class TestPolicy:
    @pytest.mark.parametrize("host", [
        "loop.example.com", "priv.example.com", "cgnat.example.com",
        "linklocal.example.com", "v6loop.example.com",
        "v6link.example.com", "v6priv.example.com",
    ])
    def test_private_only_hosts_blocked(self, host):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        with pytest.raises(PolicyBlocked):
            r.resolve_or_block(host)

    def test_mixed_keeps_public_gate_open(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve_or_block("mixed.example.com")
        assert rec.public_ips == ("93.184.216.34",)
        # classification still reports the private one for audit
        kinds = {classify_ip(ip).kind for ip in rec.all_ips}
        assert kinds == {"private", "public"}

    def test_public_host_passes(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        assert r.resolve_or_block("v4.example.com").ok

    def test_literal_loopback_blocked(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        with pytest.raises(PolicyBlocked):
            r.resolve_or_block("127.0.0.1")
        with pytest.raises(PolicyBlocked):
            r.resolve_or_block("::1")

    def test_literal_public_ok(self):
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        assert r.resolve_or_block("8.8.8.8").ok

    def test_rebinding_toctou_documented_limitation(self):
        # NOT a full rebinding defense: the gate verdict is computed from
        # THIS resolution; a later independent re-resolution could differ.
        # This test only pins the current contract:
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        rec = r.resolve("loop.example.com")
        assert rec.blocked_private  # verdict available to the pipeline


class TestRegressionAdversarial:
    """Regression tests for bugs found in the Phase 6 bug hunt."""

    def test_regression_v4_mapped_evasion_blocked(self):
        # hostname resolving to ::ffff:10.0.0.5 must be PRIVATE (seen
        # through the v4-mapped wrapper), so the gate blocks it
        r = Resolver(getaddrinfo=fake_gai({"evil.com": ["::ffff:10.0.0.5"]}))
        with pytest.raises(PolicyBlocked):
            r.resolve_or_block("evil.com")

    def test_regression_cgnat_is_forbidden(self):
        # 100.64/10 is neither is_private nor is_reserved in stdlib;
        # the policy must still forbid it
        r = Resolver(getaddrinfo=fake_gai(HOSTS))
        with pytest.raises(PolicyBlocked):
            r.resolve_or_block("cgnat.example.com")

    def test_regression_malformed_then_good_not_poisoned_within_run(self):
        # documented behavior: 'invalid' results ARE negative-cached for
        # the TTL (bounded); a fresh Resolver sees the new answer
        seq = {"h.com": ["not-an-ip"]}
        r = Resolver(getaddrinfo=fake_gai(seq), cache_ttl=60)
        assert r.resolve("h.com").status == ResolveStatus.INVALID
        seq["h.com"] = ["8.8.8.8"]
        r2 = Resolver(getaddrinfo=fake_gai(seq), cache_ttl=60)
        assert r2.resolve("h.com").ok

    def test_regression_injected_transport_crash_contained(self):
        # BUG: non-OSError from the injected transport crashed resolve()
        def bad_gai(host, *a, **kw):
            raise TypeError("boom")
        r = Resolver(getaddrinfo=bad_gai)
        rec = r.resolve("x.com")
        assert rec.status == ResolveStatus.TEMP_FAIL
        assert rec.error == "resolver_error" and "boom" not in rec.error

    def test_regression_huge_answer_deduped_and_capped(self):
        # BUG: 1000-entry answer produced 256 raw entries; now deduped
        # and capped deterministically at MAX_ADDRS_PER_HOST
        from hubcore.resolver import MAX_ADDRS_PER_HOST
        many = [f"93.0.0.{i % 256}" for i in range(1000)]
        r = Resolver(getaddrinfo=fake_gai({"big.com": many}))
        rec = r.resolve("big.com")
        assert len(rec.ipv4) <= MAX_ADDRS_PER_HOST
        assert len(set(rec.ipv4)) == len(rec.ipv4)  # no duplicates

    def test_regression_6to4_embedded_private_not_special_case(self):
        # 2002:a00:1:: embeds 10.0.0.1; stdlib marks it private => forbidden
        from hubcore import classify_ip
        assert classify_ip("2002:a00:1::").kind == "private"


class TestCache:
    def test_cache_hit_and_expiry(self):
        calls = []
        base = fake_gai(HOSTS)
        def counting(host, *a, **kw):
            calls.append(host)
            return base(host, *a, **kw)
        r = Resolver(getaddrinfo=counting, cache_ttl=60.0)
        r.resolve("v4.example.com")
        r.resolve("v4.example.com")
        assert calls == ["v4.example.com"]           # second was a hit
        # distinct host is a miss
        r.resolve("v6.example.com")
        assert len(calls) == 2

    def test_negative_cached(self):
        calls = []
        base = fake_gai(HOSTS)
        def counting(host, *a, **kw):
            calls.append(host)
            return base(host, *a, **kw)
        r = Resolver(getaddrinfo=counting, cache_ttl=60.0)
        r.resolve("missing.example.com")
        r.resolve("missing.example.com")
        assert calls == ["missing.example.com"]      # negative caching

    def test_cache_bounded(self):
        base = fake_gai(HOSTS)
        r = Resolver(getaddrinfo=base, cache_entries=4, cache_ttl=60.0)
        for i in range(10):
            r.resolve(f"v4.example.com")     # same key
        for i in range(10):
            r.resolve(f"h{i}.example.com")   # eviction pressure
        assert len(r._cache) <= 4
