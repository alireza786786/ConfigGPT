# -*- coding: utf-8 -*-
"""Phase 5 tests: dedup policy on top of Phase 1 identity keys.

The prime directive is tested explicitly: sharing host:port NEVER drops
a configuration. Only identical config identity does.
"""
import time
from dataclasses import replace

import pytest

from hubcore import (
    DedupOutcome,
    DedupPolicy,
    Node,
    Protocol,
    Security,
    SourceIngestor,
    SourceKind,
    SourceOrigin,
    Transport,
    config_index,
    config_key,
    dedup_counts,
    dedup_key,
    dedup_nodes,
    dedup_result,
    endpoint_index,
    endpoint_key,
    parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"
UUID2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def ing(text: str, name="s"):
    return SourceIngestor().ingest_text(text, SourceOrigin(name, SourceKind.RAW_TEXT))


def vless(uuid=UUID, host="a.com", port=443, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    return parse_url(f"vless://{uuid}@{host}:{port}{('?' + q) if q else ''}")


# ==========================================================================
# policy matrix (the prime directive)
# ==========================================================================

class TestPrimeDirective:
    def test_identical_configs_one_survives(self):
        text = f"vless://{UUID}@a.com:443?type=ws\n" * 3
        r = ing(text)
        out = dedup_result(r)
        assert out.kept_count == 1
        assert out.dropped_count == 2

    def test_same_endpoint_different_config_both_survive(self):
        r = ing(
            f"vless://{UUID}@a.com:443?type=ws\n"
            f"vless://{UUID}@a.com:443?type=grpc\n"
        )
        out = dedup_result(r)
        assert out.kept_count == 2  # ws and grpc are different configs
        assert out.dropped_count == 0

    def test_different_credentials_both_survive(self):
        r = ing(
            f"vless://{UUID}@a.com:443\n"
            f"vless://{UUID2}@a.com:443\n"
        )
        out = dedup_result(r)
        assert out.kept_count == 2

    def test_different_sni_path_servicename_survive(self):
        lines = [
            f"vless://{UUID}@a.com:443?sni=x.com&type=ws&path=/p1",
            f"vless://{UUID}@a.com:443?sni=y.com&type=ws&path=/p1",
            f"vless://{UUID}@a.com:443?sni=x.com&type=ws&path=/p2",
            f"vless://{UUID}@a.com:443?type=grpc&serviceName=s1",
            f"vless://{UUID}@a.com:443?type=grpc&serviceName=s2",
        ]
        out = dedup_result(ing("\n".join(lines)))
        assert out.kept_count == 5

    def test_different_protocols_same_endpoint_survive(self):
        r = ing(
            f"vless://{UUID}@a.com:443\n"
            f"trojan://pw@a.com:443\n"
            f"ss://cmM0OnB3@a.com:443\n"
        )
        out = dedup_result(r)
        assert out.kept_count == 3

    def test_reality_fields_keep_configs_distinct(self):
        r = ing(
            f"vless://{UUID}@a.com:443?security=reality&pbk=K1&sid=01\n"
            f"vless://{UUID}@a.com:443?security=reality&pbk=K2&sid=01\n"
        )
        assert dedup_result(r).kept_count == 2

    def test_query_params_participate_in_identity(self):
        r = ing(
            f"vless://{UUID}@a.com:443?type=ws&customFlag=1\n"
            f"vless://{UUID}@a.com:443?type=ws&customFlag=2\n"
        )
        assert dedup_result(r).kept_count == 2

    def test_conflicting_params_distinct(self):
        r = ing(
            f"vless://{UUID}@a.com:443?type=ws&type=grpc\n"
            f"vless://{UUID}@a.com:443?type=grpc\n"
        )
        assert dedup_result(r).kept_count == 2

    def test_metrics_and_names_never_split_identity(self):
        n1 = vless()
        n2 = replace(n1).with_score(99.0)
        out = dedup_nodes([n1, n2])
        assert out.kept_count == 1

    def test_rename_only_does_not_duplicate(self):
        a = parse_url(f"vless://{UUID}@a.com:443#NameA")
        b = parse_url(f"vless://{UUID}@a.com:443#NameB")
        assert dedup_nodes([a, b]).kept_count == 1


# ==========================================================================
# canonicalization
# ==========================================================================

class TestCanonicalization:
    def test_uppercase_host_dedups(self):
        a = parse_url(f"vless://{UUID}@A.COM:443")
        b = parse_url(f"vless://{UUID}@a.com:443")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_trailing_dot_dedups(self):
        a = parse_url(f"vless://{UUID}@a.com.:443")
        b = parse_url(f"vless://{UUID}@a.com:443")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_bare_nodes_accepted(self):
        out = dedup_nodes([vless(), vless()])
        assert out.kept_count == 1
        # bare Nodes get sentinel metadata
        assert out.kept[0].line_no == -1

    def test_ipv6_textual_case_dedups(self):
        a = parse_url(f"vless://{UUID}@[2001:DB8::1]:443")
        b = parse_url(f"vless://{UUID}@[2001:db8::1]:443")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_ipv4_literal_is_its_own_identity(self):
        a = parse_url(f"vless://{UUID}@1.2.3.4:443")
        b = parse_url(f"vless://{UUID}@example.com:443")  # may resolve later
        assert dedup_nodes([a, b]).kept_count == 2  # no DNS in Phase 5

    def test_canonical_host_unit(self):
        from hubcore import canonical_host
        assert canonical_host("A.COM.") == "a.com"
        assert canonical_host("[2001:DB8::1]") == "2001:db8::1"
        assert canonical_host("") == ""


# ==========================================================================
# ordering / determinism / metadata
# ==========================================================================

class TestOrderingAndMetadata:
    def test_first_occurrence_kept_with_its_metadata(self):
        text = (
            f"vless://{UUID}@a.com:443#First\n"
            f"vless://{UUID}@a.com:443#Second\n"
        )
        r = ing(text, "src")
        out = dedup_result(r)
        assert out.kept_count == 1
        kept = out.kept[0]
        assert kept.node.output_name == "First"
        assert kept.line_no == 1
        assert kept.origin.name == "src"

    def test_scattered_duplicates(self):
        lines = [f"vless://{UUID}@a.com:443"]
        for i in range(10):
            lines.append(f"trojan://pw{i}@b.com:1")
            lines.append(f"vless://{UUID}@a.com:443")
        out = dedup_result(ing("\n".join(lines)))
        assert out.kept_count == 11
        assert out.dropped_count == 10

    def test_deterministic_across_runs(self):
        text = "\n".join(
            [f"vless://{UUID}@a.com:{p}" for p in (1, 2, 3)]
            + [f"vless://{UUID}@a.com:1"]
        )
        o1 = dedup_result(ing(text))
        o2 = dedup_result(ing(text))
        assert [w.line_no for w in o1.kept] == [w.line_no for w in o2.kept]
        assert dedup_counts(o1) == dedup_counts(o2)

    def test_merged_result_from_phase3(self):
        ingor = SourceIngestor()
        r1 = ingor.ingest_text(f"vless://{UUID}@a.com:1\n",
                               SourceOrigin("s1", SourceKind.RAW_TEXT))
        r2 = ingor.ingest_text(f"vless://{UUID}@a.com:1\n",   # same config
                               SourceOrigin("s2", SourceKind.RAW_TEXT))
        merged = r1.merged(r2)
        out = dedup_result(merged)
        assert out.kept_count == 1
        assert out.kept[0].origin.name == "s1"  # first source wins

    def test_counts_report(self):
        r = ing(
            f"vless://{UUID}@a.com:1\n"
            f"vless://{UUID}@a.com:1\n"
            f"vless://{UUID}@a.com:1\n"
            f"vless://{UUID2}@a.com:1\n"
        )
        c = dedup_counts(dedup_result(r))
        assert c == {
            "kept": 2,
            "dropped": 2,
            "unique_configs": 2,
            "groups_with_duplicates": 1,
            "max_occurrences": 3,
        }


# ==========================================================================
# endpoint index vs config index (never conflated)
# ==========================================================================

class TestEndpointVsConfig:
    def test_endpoint_index_keeps_all_configs(self):
        r = ing(
            f"vless://{UUID}@a.com:443?type=ws\n"
            f"vless://{UUID}@a.com:443?type=grpc\n"
        )
        eidx = endpoint_index(r.nodes)
        cidx = config_index(r.nodes)
        assert len(eidx) == 1          # one endpoint...
        assert len(cidx) == 2          # ...two configs
        # dedup after endpoint grouping still keeps both configs
        out = dedup_result(r)
        assert out.kept_count == 2

    def test_endpoint_key_is_not_the_dedup_key(self):
        a = vless(host="a.com")
        b = vless(uuid=UUID2, host="a.com")
        assert endpoint_key(a) == endpoint_key(b)
        assert dedup_key(a) != dedup_key(b)


# ==========================================================================
# adversarial
# ==========================================================================

class TestAdversarial:
    def test_1000_plus_duplicates(self):
        r = ing(f"vless://{UUID}@a.com:443\n" * 1200)
        out = dedup_result(r)
        assert out.kept_count == 1
        assert out.dropped_count == 1199

    def test_similar_configs_one_field_apart(self):
        # nine configs differing in exactly one field each
        lines = [f"vless://{UUID}@a.com:443?type=ws&path=/{i}" for i in range(9)]
        lines.append(f"vless://{UUID}@a.com:443?type=ws&path=/0")  # dup of 0
        out = dedup_result(ing("\n".join(lines)))
        assert out.kept_count == 9
        assert out.dropped_count == 1

    def test_unicode_percent_encoding_same_config(self):
        a = parse_url(f"vless://{UUID}@a.com:443#%F0%9F%87%A9%F0%9F%87%AA")
        b = parse_url(f"vless://{UUID}@a.com:443#🇩🇪")
        # same decoded name, so identical identity
        assert dedup_nodes([a, b]).kept_count == 1

    def test_missing_optional_fields(self):
        a = parse_url(f"vless://{UUID}@a.com:443")
        b = parse_url(f"vless://{UUID}@a.com:443?type=ws")  # adds transport
        assert dedup_nodes([a, b]).kept_count == 2

    def test_empty_input(self):
        out = dedup_result(ing(""))
        assert out.kept_count == 0 and out.dropped_count == 0
        assert dedup_counts(out)["unique_configs"] == 0

    def test_policy_guard(self):
        with pytest.raises(ValueError):
            dedup_nodes([], policy=DedupPolicy(keep="last"))

    def test_no_dns_involved(self):
        # two distinct hostnames that would resolve identically in real
        # DNS must BOTH survive: Phase 5 is strictly textual
        a = parse_url(f"vless://{UUID}@cdn.example.com:443")
        b = parse_url(f"vless://{UUID}@origin.example.com:443")
        assert dedup_nodes([a, b]).kept_count == 2


# ==========================================================================
# performance
# ==========================================================================

class TestRegressionAdversarial:
    """Regression tests for cross-phase bugs found in the Phase 5 hunt."""

    def test_regression_percent_encoded_host_same_identity(self):
        # BUG (Phase1/2): 'ex%61mple.com' kept literal in identity and did
        # NOT dedup against 'example.com' (RFC 3986 requires host decoding)
        a = parse_url(f"vless://{UUID}@ex%61mple.com:443")
        b = parse_url(f"vless://{UUID}@example.com:443")
        assert a.endpoint.host == "example.com"
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_ipv6_compressed_vs_expanded(self):
        # BUG (Phase1): '[2001:db8::1]' vs '[2001:db8:0:0:0:0:0:1]' were
        # two identities; now canonically equal at the model level
        a = parse_url(f"vless://{UUID}@[2001:db8::1]:443")
        b = parse_url(f"vless://{UUID}@[2001:db8:0:0:0:0:0:1]:443")
        assert a.endpoint.host == "2001:db8::1"
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_invalid_ipv6_rejected_per_phase2_contract(self):
        # '[gg::gg]' is not an IPv6 literal: Phase 2 contract REJECTS it
        # cleanly (stdlib urlparse validates bracketed hosts; the parse
        # layer wraps that as MalformedURLError). Verified in the Phase 5
        # hunt that this is intentional strictness, not a regression.
        from hubcore import safe_parse_url
        assert safe_parse_url(f"vless://{UUID}@[gg::gg]:443") is None

    def test_regression_vmess_port_string_dedups(self):
        import base64, json
        def vmess(o):
            return parse_url("vmess://" + base64.b64encode(json.dumps(o).encode()).decode())
        a = vmess({"add": "h", "port": "443", "id": "u", "net": "ws"})
        b = vmess({"add": "h", "port": 443, "id": "u", "net": "ws"})
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_alias_and_encoding_equivalences(self):
        import base64 as B
        a = parse_url("hysteria2://pw@h:1")
        b = parse_url("hy2://pw@h:1")
        assert dedup_nodes([a, b]).kept_count == 1
        a = parse_url("ss://" + B.urlsafe_b64encode(b"rc4:pw").decode().rstrip("=") + "@h:1")
        b = parse_url("ss://rc4:pw@h:1")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_zero_padded_port_dedups(self):
        a = parse_url(f"vless://{UUID}@h.com:0443")
        b = parse_url(f"vless://{UUID}@h.com:443")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_qp_order_irrelevant(self):
        a = parse_url(f"vless://{UUID}@a.com:443?x=1&y=2")
        b = parse_url(f"vless://{UUID}@a.com:443?y=2&x=1")
        assert dedup_nodes([a, b]).kept_count == 1

    def test_regression_allow_insecure_encodings_equivalent(self):
        a = parse_url(f"vless://{UUID}@a.com:443?allowinsecure=1")
        b = parse_url(f"vless://{UUID}@a.com:443?allowinsecure=true")
        assert dedup_nodes([a, b]).kept_count == 1


class TestPerformance:
    def test_large_dataset_linear_behavior(self):
        # 20k lines, half duplicates: must complete well under a flat
        # O(n^2) budget; sanity guard, not a strict benchmark
        lines = []
        for i in range(10_000):
            lines.append(f"vless://{UUID}@host{i % 500}.com:443?path=/{i}")
        lines.extend(lines[:10_000])  # exact duplicates
        text = "\n".join(lines)
        r = ing(text, "big")
        t0 = time.monotonic()
        out = dedup_result(r)
        dt = time.monotonic() - t0
        assert out.kept_count == 10_000
        assert out.dropped_count == 10_000
        assert dt < 5.0, f"dedup too slow: {dt:.2f}s"
