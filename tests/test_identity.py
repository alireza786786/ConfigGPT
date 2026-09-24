# -*- coding: utf-8 -*-
"""Offline identity tests: endpoint identity vs configuration identity.

Core guarantee under test (approved constraint 2): nodes that share a
host:port but differ in credentials/paths/SNI/transport/security/any
protocol field are DIFFERENT configurations and their config_key differs.
"""
import pytest

from hubcore import (
    Endpoint,
    Node,
    Protocol,
    Security,
    Transport,
    config_key,
    endpoint_key,
    same_config,
    same_endpoint,
)


def make_node(**overrides):
    defaults = dict(
        protocol=Protocol.VLESS,
        endpoint=Endpoint(host="example.com", port=443),
        uuid="u1",
        sni="a.example.com",
        transport=Transport.WS,
        security=Security.TLS,
        path="/p",
    )
    defaults.update(overrides)
    return Node(**defaults)


class TestEndpointKey:
    def test_same_host_port_same_key(self):
        a = make_node(uuid="u1", path="/p1")
        b = make_node(uuid="u2", path="/p2")
        assert endpoint_key(a) == endpoint_key(b)
        assert same_endpoint(a, b)

    def test_resolved_ip_changes_endpoint_key(self):
        a = make_node()
        b = make_node(endpoint=Endpoint(host="example.com", port=443, resolved_ip="1.2.3.4"))
        assert endpoint_key(a) != endpoint_key(b)

    def test_different_port_differs(self):
        assert endpoint_key(make_node()) != endpoint_key(
            make_node(endpoint=Endpoint(host="example.com", port=8443))
        )


class TestConfigKey:
    def test_identical_fields_identical_key(self):
        assert config_key(make_node()) == config_key(make_node())

    def test_renaming_fragment_does_not_change_identity(self):
        # raw_url/name cosmetics must not affect config identity
        a = make_node(raw_url="vless://...#nameA")
        b = make_node(raw_url="vless://...#nameB")
        assert config_key(a) == config_key(b)

    def test_uuid_difference_matters(self):
        assert config_key(make_node(uuid="u1")) != config_key(make_node(uuid="u2"))

    def test_password_difference_matters(self):
        a = make_node(protocol=Protocol.TROJAN, password="pw1", uuid="")
        b = make_node(protocol=Protocol.TROJAN, password="pw2", uuid="")
        assert config_key(a) != config_key(b)

    def test_path_difference_matters(self):
        assert config_key(make_node(path="/p1")) != config_key(make_node(path="/p2"))

    def test_sni_difference_matters(self):
        assert config_key(make_node(sni="a.x")) != config_key(make_node(sni="b.x"))

    def test_transport_difference_matters(self):
        assert config_key(make_node(transport=Transport.WS)) != config_key(
            make_node(transport=Transport.GRPC)
        )

    def test_security_difference_matters(self):
        assert config_key(make_node(security=Security.TLS)) != config_key(
            make_node(security=Security.REALITY)
        )

    def test_protocol_difference_matters(self):
        assert config_key(make_node(protocol=Protocol.VLESS)) != config_key(
            make_node(protocol=Protocol.VMESS)
        )

    def test_allow_insecure_matters(self):
        assert config_key(make_node(allow_insecure=True)) != config_key(
            make_node(allow_insecure=False)
        )

    def test_flow_difference_matters(self):
        assert config_key(make_node(flow="xtls-rprx-vision")) != config_key(
            make_node(flow="")
        )

    def test_protocol_field_difference_matters(self):
        a = make_node(protocol_fields=[("vless.reality.pubkey", "K1")])
        b = make_node(protocol_fields=[("vless.reality.pubkey", "K2")])
        c = make_node(protocol_fields=[("vless.reality.pubkey", "K1")])
        assert config_key(a) != config_key(b)
        assert config_key(a) == config_key(c)

    def test_each_protocol_field_namespace_changes_identity(self):
        variants = [
            dict(protocol_fields=[("vmess.encryption", "auto")]),
            dict(protocol_fields=[("ss.method", "rc4-md5")]),
            dict(protocol_fields=[("ss.plugin", "obfs-local")]),
            dict(protocol_fields=[("hy2.obfs.password", "x")]),
            dict(protocol_fields=[("tls.alpn", "h3")]),
            dict(protocol_fields=[("tls.fingerprint", "chrome")]),
            dict(protocol_fields=[("xhttp.mode", "packet-up")]),
            dict(protocol_fields=[("vless.reality.shortid", "01")]),
        ]
        base = config_key(make_node())
        for kw in variants:
            assert config_key(make_node(**kw)) != base, kw

    def test_key_order_irrelevant(self):
        a = make_node(protocol_fields=[("a", "1"), ("b", "2")])
        b = make_node(protocol_fields=[("b", "2"), ("a", "1")])
        assert config_key(a) == config_key(b)

    def test_measurement_does_not_change_identity(self):
        from hubcore import LatencyKind, LatencySample
        a = make_node()
        b = make_node().with_tcp_connect(LatencySample(12.0, LatencyKind.TCP_CONNECT))
        b = b.with_score(77.0)
        assert config_key(a) == config_key(b)

    def test_hashable_and_stable(self):
        a, b = make_node(), make_node()
        assert hash(config_key(a)) == hash(config_key(b))
        assert {a, b}.__len__() == 1  # equal nodes collapse in a set
        assert len({config_key(a), config_key(b)}) == 1

    def test_same_config_true_false(self):
        assert same_config(make_node(), make_node())
        assert not same_config(make_node(uuid="u1"), make_node(uuid="u2"))
