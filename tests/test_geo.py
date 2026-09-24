# -*- coding: utf-8 -*-
"""Phase 6 tests: GeoIP annotation (offline, injectable provider)."""
from dataclasses import replace

import pytest

from hubcore import (
    Endpoint,
    GeoAnswer,
    GeoProvider,
    Node,
    NullGeoProvider,
    Protocol,
    Resolver,
    ResolveStatus,
    TableGeoProvider,
    annotate_resolved,
    flag_from_cc,
    parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"

TABLE = {
    "93.184.216.34": {"country": "United States", "city": "Los Angeles",
                      "country_code": "us", "asn": 15169},
    "8.8.8.8": {"country": "United States", "city": "Mountain View",
                "country_code": "US"},
    "1.1.1.1": {"country": "Australia", "city": "Sydney", "country_code": "AU",
                "asn": "not-a-number"},   # malformed asn degrades to None
}


def node_at(host="example.com", ip=None, port=443):
    n = parse_url(f"vless://{UUID}@{host}:{port}")
    if ip:
        ep = replace(n.endpoint, resolved_ip=ip)
        n = replace(n, endpoint=ep)
    return n


class TestProviders:
    def test_null_provider_unknown(self):
        a = NullGeoProvider().lookup("8.8.8.8")
        assert a is None

    def test_table_lookup(self):
        a = TableGeoProvider(TABLE).lookup("93.184.216.34")
        assert a.country == "United States"
        assert a.country_code == "US"      # normalized upper
        assert a.asn == 15169

    def test_table_malformed_asn(self):
        a = TableGeoProvider(TABLE).lookup("1.1.1.1")
        assert a.asn is None

    def test_unknown_ip(self):
        assert TableGeoProvider(TABLE).lookup("9.9.9.9") is None

    def test_non_mapping_entry_degrades(self):
        p = TableGeoProvider({"1.2.3.4": "junk-not-a-mapping"})
        assert p.lookup("1.2.3.4") is None

    def test_provider_exception_contained(self):
        class Boom(GeoProvider):
            def lookup(self, ip):
                raise RuntimeError("provider exploded")
        nodes = annotate_resolved([node_at(ip="8.8.8.8")], provider=Boom())
        g = nodes[0].geo
        assert g.country == "Unknown"       # degraded, not crashed

    def test_oversized_answer_clamped(self):
        class Huge(GeoProvider):
            def lookup(self, ip):
                return GeoAnswer(country="C" * 5000, city="y" * 5000,
                                 country_code="us")
        nodes = annotate_resolved([node_at(ip="8.8.8.8")], provider=Huge())
        g = nodes[0].geo
        assert len(g.country) <= 128 and len(g.city) <= 128


class TestFlagEmoji:
    def test_known(self):
        assert flag_from_cc("de") == "🇩🇪"
        assert flag_from_cc("US") == "🇺🇸"

    def test_invalid_globe(self):
        assert flag_from_cc("") == "🌐"
        assert flag_from_cc("D") == "🌐"
        assert flag_from_cc("DEU") == "🌐"
        assert flag_from_cc("1D") == "🌐"


class TestAnnotate:
    def test_resolved_ip_annotated(self):
        nodes = annotate_resolved([node_at(ip="93.184.216.34")],
                                  provider=TableGeoProvider(TABLE))
        n = nodes[0]
        assert n.geo.country == "United States"
        assert n.geo.flag == "🇺🇸"
        assert "United States" in n.output_name
        assert "Los Angeles" in n.output_name

    def test_unresolved_node_gets_unknown(self):
        nodes = annotate_resolved([node_at()], provider=TableGeoProvider(TABLE))
        g = nodes[0].geo
        assert (g.country, g.city, g.country_code) == ("Unknown", "Unknown", "XX")
        assert g.flag == "🌐"

    def test_lazy_resolution_when_allowed(self):
        # no resolved_ip yet: annotate may use the resolver explicitly
        import socket
        def gai(host, port=443, proto=0, *a, **kw):
            return [(socket.AF_INET, 1, proto, "", ("93.184.216.34", port))]
        r = Resolver(getaddrinfo=gai)
        nodes = annotate_resolved([node_at()], provider=TableGeoProvider(TABLE),
                                  resolver=r)
        assert nodes[0].endpoint.resolved_ip == "93.184.216.34"
        assert nodes[0].geo.country == "United States"

    def test_lazy_resolution_nxdomain_stays_unknown(self):
        def gai(host, *a, **kw):
            import socket as s
            raise s.gaierror(-2, "Name or service not known")
        r = Resolver(getaddrinfo=gai)
        nodes = annotate_resolved([node_at()], provider=TableGeoProvider(TABLE),
                                  resolver=r)
        assert nodes[0].geo.country == "Unknown"
        assert nodes[0].endpoint.resolved_ip is None

    def test_private_ip_still_annotates_if_provider_knows(self):
        # classification is the resolver's job; geo is a pure lookup
        table = dict(TABLE)
        table["10.1.2.3"] = {"country": "PrivateLand", "city": "Nowhere",
                             "country_code": "PR"}
        nodes = annotate_resolved([node_at(ip="10.1.2.3")],
                                  provider=TableGeoProvider(table))
        assert nodes[0].geo.country == "PrivateLand"

    def test_deterministic_order(self):
        ns = [node_at(ip="8.8.8.8"), node_at(ip="1.1.1.1")]
        a = annotate_resolved(ns, provider=TableGeoProvider(TABLE))
        b = annotate_resolved([node_at(ip="8.8.8.8"), node_at(ip="1.1.1.1")],
                              provider=TableGeoProvider(TABLE))
        assert [n.output_name for n in a] == [n.output_name for n in b]


class TestWiring:
    def test_resolver_to_annotation_pipeline(self):
        # resolve -> pick first public ip -> annotate, all offline
        HOSTS = {"g.example.com": ["93.184.216.34"]}
        def gai(host, port=443, proto=0, *a, **kw):
            return [(2, 1, proto, "", ("93.184.216.34", port))]
        r = Resolver(getaddrinfo=gai)
        rec = r.resolve_or_block("g.example.com")
        assert rec.public_ips == ("93.184.216.34",)
        n = node_at(host="g.example.com")
        ep = replace(n.endpoint, resolved_ip=rec.public_ips[0])
        n = replace(n, endpoint=ep)
        (annotated,) = annotate_resolved([n], provider=TableGeoProvider(TABLE))
        assert annotated.geo.country_code == "US"

    def test_name_suffix_preserved(self):
        n = parse_url(f"vless://{UUID}@h:443#MyName")
        ep = replace(n.endpoint, resolved_ip="8.8.8.8")
        n = replace(n, endpoint=ep)
        (out,) = annotate_resolved([n], provider=TableGeoProvider(TABLE))
        assert out.output_name.endswith("|MyName")
