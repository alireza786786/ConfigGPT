# -*- coding: utf-8 -*-
"""Offline tests for the canonical data model (Phase 1). No network I/O."""
import dataclasses

import pytest

from hubcore import (
    Endpoint,
    GeoInfo,
    LatencyKind,
    LatencySample,
    Node,
    Protocol,
    Security,
    Transport,
)


def make_node(**overrides):
    defaults = dict(
        protocol=Protocol.VLESS,
        endpoint=Endpoint(host="Example.COM", port="443"),
        uuid="u1",
        sni="a.example.com",
        transport=Transport.WS,
        security=Security.TLS,
        path="/p",
    )
    defaults.update(overrides)
    return Node(**defaults)


class TestEndpoint:
    def test_normalizes_host_and_port(self):
        ep = Endpoint(host="Example.COM", port="443")
        assert ep.host == "example.com"
        assert ep.port == 443

    def test_rejects_bad_port(self):
        with pytest.raises(ValueError):
            Endpoint(host="h", port=0)
        with pytest.raises(ValueError):
            Endpoint(host="h", port=70000)
        with pytest.raises(ValueError):
            Endpoint(host="h", port="abc")

    def test_rejects_empty_host(self):
        with pytest.raises(ValueError):
            Endpoint(host="  ", port=80)

    def test_identity_host_prefers_resolved_ip(self):
        ep = Endpoint(host="example.com", port=443, resolved_ip="1.2.3.4")
        assert ep.identity_host == "1.2.3.4"
        assert Endpoint(host="example.com", port=443).identity_host == "example.com"

    def test_frozen(self):
        ep = Endpoint(host="h", port=80)
        with pytest.raises(Exception):
            ep.host = "other"


class TestEnums:
    def test_legacy_aliases(self):
        assert Protocol.from_string("hy2") is Protocol.HYSTERIA2
        assert Protocol.from_string("ss") is Protocol.SHADOWSOCKS
        assert Protocol.from_string("socks") is Protocol.SOCKS5
        assert Protocol.from_string("VLESS") is Protocol.VLESS
        assert Protocol.from_string("weird://") is Protocol.OTHER
        assert Protocol.from_string(None) is Protocol.OTHER

        assert Transport.from_string("websocket") is Transport.WS
        assert Transport.from_string("splithttp") is Transport.XHTTP
        assert Transport.from_string("gun") is Transport.GRPC
        assert Transport.from_string("http") is Transport.HTTP2
        assert Transport.from_string(None) is Transport.UNKNOWN

        assert Security.from_string("tls") is Security.TLS
        assert Security.from_string("reality") is Security.REALITY
        assert Security.from_string("none") is Security.NONE
        assert Security.from_string("") is Security.UNKNOWN

    def test_unique_values(self):
        assert len({p.value for p in Protocol}) == len(list(Protocol))
        assert len({t.value for t in Transport}) == len(list(Transport))


class TestLatencySample:
    def test_kinds_distinct(self):
        assert LatencyKind.TCP_CONNECT is not LatencyKind.PROTOCOL_HANDSHAKE
        assert LatencyKind.PROTOCOL_HANDSHAKE is not LatencyKind.MEASURED

    def test_failed_measurement_allowed_and_flagged(self):
        s = LatencySample(value_ms=None, kind=LatencyKind.TCP_CONNECT)
        assert s.ok is False

    def test_rejects_negative(self):
        with pytest.raises(ValueError):
            LatencySample(value_ms=-1.0, kind=LatencyKind.MEASURED)

    def test_rejects_zero_attempts(self):
        with pytest.raises(ValueError):
            LatencySample(value_ms=10.0, kind=LatencyKind.MEASURED, attempts=0)

    def test_frozen(self):
        s = LatencySample(value_ms=5.0, kind=LatencyKind.TCP_CONNECT)
        with pytest.raises(Exception):
            s.value_ms = 9.0


class TestNode:
    def test_frozen(self):
        n = make_node()
        with pytest.raises(Exception):
            n.score = 99.0

    def test_replace_updates_without_mutation(self):
        n1 = make_node()
        n2 = dataclasses.replace(n1, score=42.0)
        assert n1.score == 0.0
        assert n2.score == 42.0
        assert n1 is not n2

    def test_with_geo(self):
        n = make_node()
        g = GeoInfo(country="Germany", city="Berlin", country_code="de", flag="x")
        n2 = n.with_geo(g)
        assert n.geo is None
        assert n2.geo.country == "Germany"
        assert n2.geo.country_code == "DE"  # normalized

    def test_with_tcp_connect_only_accepts_tcp_kind(self):
        n = make_node()
        good = LatencySample(value_ms=12.5, kind=LatencyKind.TCP_CONNECT)
        bad = LatencySample(value_ms=12.5, kind=LatencyKind.MEASURED)
        n2 = n.with_tcp_connect(good)
        assert n2.tcp_connect.value_ms == 12.5
        assert n.tcp_connect is None  # original untouched
        with pytest.raises(ValueError):
            n.with_tcp_connect(bad)

    def test_with_measured_only_accepts_measured_kind(self):
        n = make_node()
        with pytest.raises(ValueError):
            n.with_measured(LatencySample(value_ms=5, kind=LatencyKind.TCP_CONNECT))
        n2 = n.with_measured(LatencySample(value_ms=5, kind=LatencyKind.MEASURED))
        assert n2.measured_latency.value_ms == 5

    def test_with_score(self):
        n2 = make_node().with_score(123.4)
        assert n2.score == 123.4

    def test_protocol_fields_normalized_sorted(self):
        n = make_node(protocol_fields=[("b", 2), ("a", "1")])
        # sorted and string-coerced
        assert n.protocol_fields == (("a", "1"), ("b", "2"))

    def test_duplicate_protocol_field_key_rejected(self):
        with pytest.raises(ValueError):
            make_node(protocol_fields=[("a", "1"), ("a", "2")])

    def test_three_latency_slots_independent(self):
        n = make_node(
            tcp_connect=LatencySample(20.0, LatencyKind.TCP_CONNECT),
            protocol_handshake=LatencySample(80.0, LatencyKind.PROTOCOL_HANDSHAKE),
            measured_latency=LatencySample(75.0, LatencyKind.MEASURED),
        )
        assert n.tcp_connect.kind is LatencyKind.TCP_CONNECT
        assert n.protocol_handshake.kind is LatencyKind.PROTOCOL_HANDSHAKE
        assert n.measured_latency.kind is LatencyKind.MEASURED

    def test_hashable_for_dedup_sets(self):
        s = {make_node(), make_node()}
        assert len(s) == 1  # identical field values -> equal -> same hash
