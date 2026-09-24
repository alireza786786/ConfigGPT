# -*- coding: utf-8 -*-
"""Phase 12 tests: deterministic text output generation (fully offline).

Pins the extracted legacy output contract (CRLF + exactly one trailing
CRLF for plain files, LF-joined base64 payload with no trailing newline,
the exact brand template, percent-encoded non-vmess fragments, raw vmess
``ps``, group files as stable filters of the global order), the
no-fabrication policy, the canonical-enum -> legacy-filename mappings,
injection safety, secret safety, purity (no I/O at all) and determinism.
"""
import ast
import base64
import json
import pathlib
import re
import time
from dataclasses import replace

import pytest

import hubcore.output as output_mod
from hubcore import (
    CRLF,
    CHANNEL_TAG,
    DEFAULT_FLAG,
    GOOD_PING_MS,
    LEGACY_PROTOCOL_FILE,
    LEGACY_TRANSPORT_FILE,
    LF,
    PATH_ALL,
    PATH_ALL_BASE64,
    PATH_GOOD_PING,
    PATH_ULTRA_FAST,
    ULTRA_FAST_MS,
    UNKNOWN_COUNTRY_KEYS,
    UNKNOWN_TEXT,
    CountryGroup,
    GeoInfo,
    LatencyKind,
    LatencySample,
    Node,
    OutputBundle,
    OutputInputError,
    OutputPolicy,
    OutputPolicyError,
    Protocol,
    RankingResult,
    ScoreOutcome,
    Transport,
    UnsafeOutputTextError,
    arch_label,
    brand_name,
    build_outputs,
    config_key,
    country_filename,
    display_ping_ms,
    geo_city,
    geo_country,
    geo_flag,
    group_by_country,
    group_by_protocol,
    group_by_transport,
    parse_url,
    rank_candidates,
    render_base64,
    render_link,
    render_payload,
    render_ping_tiers,
    render_text,
    score_node,
)
from urllib.parse import quote

UUID = "11111111-2222-3333-4444-555555555555"
UUID2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
IP4 = "93.184.216.34"
IP6 = "2001:db8::1"
OBSERVED_AT = 1_700_000_000.0
VMESS_JSON = {"v": "2", "ps": "original-name", "add": "1.2.3.4", "port": "443",
              "id": UUID, "net": "ws", "type": "none", "tls": "tls"}
VMESS_URL = "vmess://" + base64.b64encode(
    json.dumps(VMESS_JSON).encode("utf-8")).decode("ascii")


# ----------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------
def build(url=None, host="a.com", port=443, uuid=UUID, ip=IP4, ms=180.0,
          jitter=24.0, type_="tcp", path="/p1", geo=None, name="", raw_url=None):
    n = parse_url(url or
                  f"vless://{uuid}@{host}:{port}?security=tls&type={type_}&path={path}")
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
    if raw_url is not None:
        n = replace(n, raw_url=raw_url)
    return n


def entry(n):
    """A real (Node, ScoreOutcome) pair."""
    return (n, score_node(n))


def text_lines(text):
    """The real lines of a plain artifact (drops the trailing separator)."""
    assert text.endswith(CRLF)
    return text[:-len(CRLF)].split(CRLF) if text != CRLF else []


def fragment(line):
    return line.split("#", 1)[1]


def vmess_json_from(line):
    body = line[len("vmess://"):]
    pad = "=" * (-len(body) % 4)
    return json.loads(base64.b64decode(body + pad).decode("utf-8"))


def de(geo_country_name="Canada", city="Vancouver", cc="CA", flag="🇨🇦"):
    return GeoInfo(country=geo_country_name, city=city, country_code=cc, flag=flag)


# ==========================================================================
# legacy byte contract
# ==========================================================================
class TestLegacyByteContract:
    def test_plain_text_uses_crlf_and_one_trailing_separator(self):
        items = [entry(build(path=f"/{i}", ms=100.0 + i)) for i in range(4)]
        text = render_text(items)
        assert text.endswith(CRLF)
        assert text.count(CRLF) == 4
        assert "\n" not in text.replace(CRLF, "")      # no bare LF anywhere
        assert text.count("#") == 4

    def test_empty_plain_text_is_exactly_one_crlf(self):
        # legacy: "\n".join([]) + "\n" -> the 2-byte file b"\r\n"
        assert render_text([]) == CRLF
        assert render_text([]).encode("utf-8") == b"\r\n"

    def test_payload_is_lf_joined_without_trailing_separator(self):
        items = [entry(build(path=f"/{i}")) for i in range(3)]
        payload = render_payload(items)
        assert payload.count("\n") == 2 and "\r" not in payload
        assert not payload.endswith("\n")
        assert render_payload([]) == ""

    def test_base64_has_no_line_breaks_and_no_trailing_newline(self):
        items = [entry(build(path=f"/{i}")) for i in range(3)]
        encoded = render_base64(render_payload(items))
        assert "\n" not in encoded and "\r" not in encoded
        assert not encoded.endswith("\n")
        assert base64.b64decode(encoded).decode("utf-8") == render_payload(items)

    def test_base64_round_trip_matches_plain_modulo_separators(self):
        # the exact relation verified on the committed artifacts:
        # decode(b64) == plain_with_CRLF_to_LF minus the trailing newline
        items = [entry(build(path=f"/{i}")) for i in range(5)]
        plain = render_text(items)
        decoded = base64.b64decode(render_base64(render_payload(items))).decode()
        assert decoded == plain.replace(CRLF, LF)[:-len(LF)]

    def test_group_file_is_a_stable_filter_of_the_global_order(self):
        items = [entry(build(path="/a")), entry(build(url=VMESS_URL, ip="1.2.3.4")),
                 entry(build(path="/b"))]
        bundle = build_outputs(items)
        vless_lines = text_lines(bundle.by_protocol["Config/vless.txt"])
        global_lines = text_lines(bundle.all_text)
        assert vless_lines == [l for l in global_lines if l.startswith("vless://")]
        vmess_lines = text_lines(bundle.by_protocol["Config/vmess.txt"])
        assert vmess_lines == [l for l in global_lines if l.startswith("vmess://")]

    def test_all_and_base64_all_paths_are_the_legacy_names(self):
        assert PATH_ALL == "all.txt" and PATH_ALL_BASE64 == "all_b64.txt"
        assert PATH_ULTRA_FAST == "Subscription/ultra_fast.txt"
        assert PATH_GOOD_PING == "Subscription/good_ping.txt"

    def test_lf_policy_value_is_available_but_not_the_default(self):
        assert OutputPolicy().line_separator == CRLF
        text = render_text([entry(build())], OutputPolicy(line_separator=LF))
        assert text.endswith("\n") and "\r" not in text

    def test_trailing_newline_can_be_disabled_explicitly(self):
        policy = OutputPolicy(trailing_newline=False)
        assert render_text([entry(build())], policy).count(CRLF) == 0


# ==========================================================================
# brand name
# ==========================================================================
class TestBrandName:
    def test_exact_legacy_template_for_a_scored_node(self):
        n = build(port=443, ms=1.4, jitter=0.0, geo=de())
        name = brand_name(n, score_node(n))
        assert name == ("👉🆔@Goodbaye_filtering📡🇨🇦®️Canada©️Vancouver"
                        "🅿️ping:1.4ms⚡️VLESS-TLS")

    def test_channel_tag_is_the_legacy_constant(self):
        assert CHANNEL_TAG == "Goodbaye_filtering"
        assert brand_name(build(geo=de()), score_node(build(geo=de()))).startswith(
            "👉🆔@Goodbaye_filtering")

    def test_all_markers_present_in_order(self):
        name = brand_name(build(geo=de()), score_node(build(geo=de())))
        order = ["👉", "🆔", "📡", "®️", "©️", "🅿️ping:", "⚡️"]
        positions = [name.index(m) for m in order]
        assert positions == sorted(positions)

    def test_ping_is_formatted_with_one_decimal(self):
        n = build(ms=123.456, jitter=0.0, geo=de())
        assert "🅿️ping:123.5ms" in brand_name(n, score_node(n))

    def test_architecture_label_comes_from_phase_10_components(self):
        n = build(geo=de())
        out = score_node(n)
        assert arch_label(out) == "VLESS-TLS" == out.components["arch_label"]

    def test_architecture_omitted_for_unscored_protocols(self):
        # Phase 10 refuses to probe vmess, so it never records an arch
        # label -> output cannot show one without re-scoring (documented)
        v = parse_url(VMESS_URL)
        out = score_node(v)
        assert out.status == "unsupported"
        assert arch_label(out) is None
        assert "⚡️" not in brand_name(v, out)

    def test_missing_arch_unknown_policy_renders_sentinel(self):
        v = parse_url(VMESS_URL)
        policy = OutputPolicy(missing_arch="unknown")
        assert brand_name(v, score_node(v), policy).endswith("⚡️Unknown")


# ==========================================================================
# link rendering / escaping
# ==========================================================================
class TestLinkRendering:
    def test_non_vmess_fragment_is_percent_encoded(self):
        n = build(geo=de())
        line = render_link(n, score_node(n))
        name = brand_name(n, score_node(n))
        assert fragment(line) == quote(name, safe="/")
        assert "%F0%9F%91%89" in line          # 👉 encoded
        assert "@" not in fragment(line)       # @ -> %40
        assert ":" not in fragment(line)       # : -> %3A
        assert line.startswith("vless://")

    def test_input_fragment_is_discarded(self):
        a = build(geo=de(), name="MyOwnName")
        b = build(geo=de())
        assert render_link(a[0] if isinstance(a, tuple) else a, score_node(b)) == \
            render_link(b, score_node(b))

    def test_scheme_spelling_of_the_raw_url_is_preserved(self):
        hy2 = parse_url("hysteria2://pw@h.com:443")
        hy2_alias = parse_url("hy2://pw@h.com:443")
        assert render_link(hy2, score_node(hy2)).startswith("hysteria2://")
        assert render_link(hy2_alias, score_node(hy2_alias)).startswith("hy2://")

    def test_vmess_name_is_raw_inside_the_reencoded_body(self):
        v = parse_url(VMESS_URL)
        line = render_link(v, score_node(v))
        data = vmess_json_from(line)
        name = brand_name(v, score_node(v))
        assert data["ps"] == name
        assert "%40" not in data["ps"] and "@Goodbaye_filtering" in data["ps"]
        # every other field is carried over untouched
        for key, value in VMESS_JSON.items():
            if key != "ps":
                assert data[key] == value

    def test_vmess_undecodable_body_falls_back_to_the_original_link(self):
        bad = replace(parse_url(VMESS_URL), raw_url="vmess://!!not-base64!!")
        assert render_link(bad, score_node(bad)) == "vmess://!!not-base64!!"

    def test_vmess_non_object_json_falls_back_to_the_original_link(self):
        body = base64.b64encode(b"[1, 2, 3]").decode("ascii")
        raw = f"vmess://{body}"
        bad = replace(parse_url(VMESS_URL), raw_url=raw)
        assert render_link(bad, score_node(bad)) == raw

    def test_every_supported_protocol_renders_a_single_line(self):
        urls = [
            f"vless://{UUID}@a.com:443?security=tls&type=tcp",
            VMESS_URL,
            "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443",
            "trojan://pw@t.com:443?security=tls&type=tcp",
            "hysteria2://pw@h.com:443",
            "socks5://Og%3D%3D@1.2.3.4:1080",
        ]
        items = [entry(parse_url(u)) for u in urls]
        for line in text_lines(render_text(items)):
            assert "\n" not in line and "\r" not in line and "://" in line
        assert len(text_lines(render_text(items))) == 6

    def test_ipv6_host_renders_and_is_canonical(self):
        n = build(host="[2001:db8::1]", ip=IP6)
        line = render_link(n, score_node(n))
        assert "2001:db8::1" in line and line.count("://") == 1


# ==========================================================================
# grouping / mappings
# ==========================================================================
class TestGrouping:
    def test_protocol_file_mapping_is_explicit_and_complete(self):
        assert LEGACY_PROTOCOL_FILE == {
            Protocol.VLESS: "vless", Protocol.VMESS: "vmess",
            Protocol.SHADOWSOCKS: "ss", Protocol.TROJAN: "trojan",
            Protocol.HYSTERIA2: "hysteria2", Protocol.SOCKS5: "socks",
            Protocol.OTHER: "other",
        }

    def test_transport_file_mapping_has_no_invented_kinds(self):
        assert LEGACY_TRANSPORT_FILE == {
            Transport.TCP: "tcp", Transport.WS: "ws",
            Transport.GRPC: "grpc", Transport.XHTTP: "xhttp",
        }
        for kind in (Transport.HTTP2, Transport.QUIC, Transport.UNKNOWN):
            assert kind not in LEGACY_TRANSPORT_FILE

    def test_protocol_groups_split_by_canonical_enum(self):
        items = [entry(parse_url(f"vless://{UUID}@a.com:443?security=tls&type=tcp")),
                 entry(parse_url(VMESS_URL)),
                 entry(parse_url("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443")),
                 entry(parse_url("hysteria2://pw@h.com:443")),
                 entry(parse_url("hy2://pw@h2.com:443")),
                 entry(parse_url("socks://Og%3D%3D@1.2.3.4:1080")),
                 entry(parse_url("socks5://Og%3D%3D@1.2.3.5:1080"))]
        groups = group_by_protocol(items)
        assert set(groups) == {"vless", "vmess", "ss", "hysteria2", "socks"}
        assert len(groups["hysteria2"]) == 2      # hysteria2 + hy2
        assert len(groups["socks"]) == 2          # socks + socks5

    def test_transport_groups_exclude_h2_quic_and_unknown(self):
        items = [entry(build(type_="tcp")), entry(build(type_="ws")),
                 entry(build(type_="grpc", path="/g")),
                 entry(build(type_="xhttp", path="/x")),
                 entry(build(type_="h2")), entry(build(type_="quic"))]
        groups = group_by_transport(items)
        assert set(groups) == {"tcp", "ws", "grpc", "xhttp"}
        assert sum(len(v) for v in groups.values()) == 4

    def test_transport_files_are_not_written_for_excluded_kinds(self):
        bundle = build_outputs([entry(build(type_="h2")), entry(build(type_="quic"))])
        assert bundle.by_transport == {}

    def test_country_grouping_comes_from_geo_not_from_the_name(self):
        # a node whose *name* claims Germany but whose GeoInfo says Canada
        n = build(geo=de(), name="📡🇩🇪Germany")
        groups = group_by_country([entry(n)])
        assert groups[0].country == "Canada"
        assert groups[0].path == "Country/Canada.txt"

    def test_country_filename_sanitized_rule(self):
        policy = OutputPolicy(country_filename="sanitized")
        assert country_filename("United States", policy) == "United_States"
        assert country_filename("آلمان", policy) == "آلمان"
        assert country_filename("Côte d'Ivoire", policy) == "Côte_dIvoire"
        assert country_filename("  ", policy) == ""

    def test_country_filename_alnum_lower_rule(self):
        policy = OutputPolicy(country_filename="alnum_lower")
        assert country_filename("United States", policy) == "unitedstates"
        assert country_filename("سایر سرورها (Global)", policy) == "سایرسرورهاglobal"

    def test_country_filename_contains_no_path_separator(self):
        for scheme in ("sanitized", "alnum_lower"):
            name = country_filename("../../etc/passwd", OutputPolicy(country_filename=scheme))
            assert "/" not in name and "\\" not in name and ".." not in name

    def test_unknown_country_groups_are_not_emitted(self):
        assert UNKNOWN_COUNTRY_KEYS == ("global", "other", "unknown")
        n = build(geo=GeoInfo(country="Unknown", city="Unknown",
                              country_code="XX", flag="🌐"))
        assert group_by_country([entry(n)]) == ()

    def test_empty_sanitised_name_is_hardened_not_a_hidden_file(self):
        n = build(geo=GeoInfo(country="★★★", city="x", country_code="XX", flag="🌐"))
        assert country_filename("★★★") == ""
        assert group_by_country([entry(n)]) == ()      # -> Unknown -> excluded

    def test_country_group_order_is_first_appearance(self):
        items = [entry(build(geo=de("Canada", "Vancouver", "CA", "🇨🇦"))),
                 entry(build(geo=de("Germany", "Berlin", "DE", "🇩🇪"))),
                 entry(build(geo=de("Canada", "Toronto", "CA", "🇨🇦")))]
        groups = group_by_country(items)
        assert [g.filename for g in groups] == ["Canada", "Germany"]
        assert groups[0].count == 2 and groups[0].flag == "🇨🇦"

    def test_group_text_preserves_the_global_order(self):
        items = [entry(build(geo=de(), path="/one")),
                 entry(build(geo=de("Germany", "Berlin", "DE", "🇩🇪"), path="/two")),
                 entry(build(geo=de(), path="/three"))]
        groups = {g.filename: g for g in group_by_country(items)}
        lines = text_lines(groups["Canada"].text)
        assert len(lines) == 2
        assert lines[0].split("#")[0] == items[0][0].raw_url.split("#")[0]
        assert lines[1].split("#")[0] == items[2][0].raw_url.split("#")[0]


# ==========================================================================
# geo policy
# ==========================================================================
class TestGeoPolicy:
    def test_missing_geo_uses_the_legacy_sentinels(self):
        n = build(geo=None)
        assert (geo_flag(n), geo_country(n), geo_city(n)) == ("🌐", "Unknown", "Unknown")
        name = brand_name(n, score_node(n))
        assert "📡🌐®️Unknown©️Unknown" in name

    def test_flag_derived_from_country_code_when_flag_is_default(self):
        n = build(geo=GeoInfo(country="Germany", city="Berlin", country_code="DE"))
        assert geo_flag(n) == "🇩🇪"

    def test_explicit_flag_wins(self):
        n = build(geo=GeoInfo(country="Germany", city="Berlin",
                              country_code="DE", flag="🏴"))
        assert geo_flag(n) == "🏴"

    def test_invalid_or_unknown_country_code_falls_back_to_globe(self):
        # "XX" is the legacy Unknown code: it must NOT become 🇽🇽
        for cc in ("", "X", "XXX", "12", "XX", "xx", "--"):
            n = build(geo=GeoInfo(country="Nowhere", city="x", country_code=cc,
                                  flag=DEFAULT_FLAG))
            assert geo_flag(n) == DEFAULT_FLAG, cc

    def test_valid_country_code_is_derived_when_the_flag_is_the_default(self):
        for cc, expected in (("DE", "🇩🇪"), ("de", "🇩🇪"), ("US", "🇺🇸")):
            n = build(geo=GeoInfo(country="C", city="x", country_code=cc,
                                  flag=DEFAULT_FLAG))
            assert geo_flag(n) == expected

    def test_unicode_country_and_city_survive_utf8(self):
        n = build(geo=de("آلمان", "برلین", "DE", "🇩🇪"))
        line = render_link(n, score_node(n))
        assert line.encode("utf-8").decode("utf-8") == line
        from urllib.parse import unquote
        assert "آلمان" in unquote(fragment(line))
        assert "برلین" in unquote(fragment(line))

    def test_geo_is_never_guessed_from_the_host(self):
        n = build(host="germany.example.com", geo=None)
        assert geo_country(n) == UNKNOWN_TEXT


# ==========================================================================
# latency policy
# ==========================================================================
class TestLatencyPolicy:
    def test_measured_latency_is_displayed(self):
        n = build(ms=88.25, jitter=0.0)
        assert display_ping_ms(n) == 88.25
        assert "🅿️ping:88.2ms" in brand_name(n, score_node(n))

    def test_missing_latency_omits_the_segment_by_default(self):
        n = build(ms=None, jitter=None)
        assert display_ping_ms(n) is None
        assert "🅿️" not in brand_name(n, score_node(n))

    def test_missing_latency_unknown_policy_renders_sentinel(self):
        n = build(ms=None, jitter=None)
        name = brand_name(n, score_node(n), OutputPolicy(missing_ping="unknown"))
        assert "🅿️ping:Unknown" in name
        assert "0ms" not in name

    def test_none_is_never_rendered_as_zero(self):
        n = build(ms=None, jitter=None)
        assert "0.0ms" not in brand_name(n, score_node(n))

    def test_tcp_connect_is_never_displayed_by_default(self):
        n = build(ms=None, jitter=None).with_tcp_connect(
            LatencySample(42.0, LatencyKind.TCP_CONNECT, measured_at=OBSERVED_AT))
        assert display_ping_ms(n) is None
        assert "42" not in brand_name(n, score_node(n))

    def test_tcp_connect_displayed_only_with_the_explicit_legacy_policy(self):
        n = build(ms=None, jitter=None).with_tcp_connect(
            LatencySample(42.0, LatencyKind.TCP_CONNECT, measured_at=OBSERVED_AT))
        policy = OutputPolicy(ping_sources=("measured", "tcp_connect"))
        assert display_ping_ms(n, policy) == 42.0
        assert "🅿️ping:42.0ms" in brand_name(n, score_node(n), policy)

    def test_measured_wins_over_tcp_connect_when_both_exist(self):
        n = build(ms=88.0, jitter=0.0).with_tcp_connect(
            LatencySample(42.0, LatencyKind.TCP_CONNECT, measured_at=OBSERVED_AT))
        policy = OutputPolicy(ping_sources=("measured", "tcp_connect"))
        assert display_ping_ms(n, policy) == 88.0

    def test_kind_confusion_is_refused_not_displayed(self):
        n = build(ms=None, jitter=None)
        n = replace(n, measured_latency=LatencySample(
            42.0, LatencyKind.TCP_CONNECT, measured_at=OBSERVED_AT))
        assert display_ping_ms(n) is None                        # measured slot, wrong kind
        policy = OutputPolicy(ping_sources=("measured", "tcp_connect"))
        assert display_ping_ms(n, policy) is None                # tcp slot is empty

    def test_handshake_sample_is_never_displayed(self):
        n = build(ms=None, jitter=None)
        n = replace(n, measured_latency=LatencySample(
            42.0, LatencyKind.PROTOCOL_HANDSHAKE, measured_at=OBSERVED_AT))
        policy = OutputPolicy(ping_sources=("measured", "tcp_connect"))
        assert display_ping_ms(n, policy) is None

    def test_nonfinite_and_negative_planted_latency_is_not_displayed(self):
        n = build(ms=None, jitter=None)
        template = LatencySample(1.0, LatencyKind.MEASURED, measured_at=OBSERVED_AT)
        for bad in (float("nan"), float("inf"), float("-inf"), -5.0, None):
            sample = replace(template)
            object.__setattr__(sample, "value_ms", bad)   # bypass the model guard
            assert display_ping_ms(replace(n, measured_latency=sample)) is None

    def test_no_fabricated_legacy_fallbacks(self):
        # legacy invented ping=150.0/jitter=10.0 for vless/vmess; never here
        v = parse_url(VMESS_URL)
        assert display_ping_ms(v) is None
        name = brand_name(v, score_node(v))
        assert "150" not in name and "10.0ms" not in name


# ==========================================================================
# ranking / ordering / identity preservation
# ==========================================================================
class TestOrderingPreservation:
    def test_ranking_order_is_preserved_verbatim(self):
        result = rank_candidates([entry(build(path="/slow", ms=400.0))[0:1][0] and
                                  (build(path="/slow", ms=400.0), score_node(build(path="/slow", ms=400.0))),
                                  (build(path="/fast", ms=100.0), score_node(build(path="/fast", ms=100.0)))])
        bundle = build_outputs(result)
        lines = text_lines(bundle.all_text)
        assert lines[0].startswith(str(result.ranked[0].node.raw_url).split("#")[0])
        assert [l.split("#")[0] for l in lines] == \
            [str(item.node.raw_url).split("#")[0] for item in result.ranked]

    def test_top_n_result_is_preserved(self):
        items = [(build(path=f"/p{i}", ms=100.0 + i * 10), None) for i in range(5)]
        items = [(n, score_node(n)) for n, _ in items]
        result = rank_candidates(items, n=2)
        bundle = build_outputs(result)
        assert len(text_lines(bundle.all_text)) == 2
        assert bundle.counts["nodes"] == 2

    def test_output_never_re_sorts(self):
        # deliberately unsorted input: output keeps the given order
        items = [entry(build(path="/z", ms=400.0)), entry(build(path="/a", ms=100.0))]
        lines = text_lines(render_text(items))
        assert lines[0].split("#")[0] == items[0][0].raw_url.split("#")[0]

    def test_shuffled_entries_shift_output_order_accordingly(self):
        items = [entry(build(path=f"/p{i}", ms=100.0 + i)) for i in range(4)]
        a = render_text(items)
        b = render_text(list(reversed(items)))
        assert a != b
        assert text_lines(b) == list(reversed(text_lines(a)))

    def test_equal_scores_are_preserved_in_ranking_order(self):
        items = [entry(build(path="/first", ms=150.0, jitter=0.0)),
                 entry(build(path="/second", ms=150.0, jitter=0.0))]
        result = rank_candidates(items)
        lines = text_lines(build_outputs(result).all_text)
        assert lines[0].split("#")[0] == items[0][0].raw_url.split("#")[0]

    def test_same_endpoint_different_config_both_rendered(self):
        a = build(path="/cfg1")
        b = build(path="/cfg2")
        assert a.endpoint == b.endpoint
        lines = text_lines(render_text([entry(a), entry(b)]))
        assert len(lines) == 2
        assert lines[0].split("#")[0] != lines[1].split("#")[0]

    def test_duplicate_config_lines_are_both_kept(self):
        a = build(path="/dup")
        b = build(path="/dup")
        assert render_text([entry(a), entry(b)]).count(CRLF) == 2

    def test_unranked_never_rendered_but_reported(self):
        scored = entry(build())
        result = rank_candidates([scored, (parse_url(VMESS_URL), score_node(parse_url(VMESS_URL))),
                                  (build(path="/over", ms=900.0), score_node(build(path="/over", ms=900.0)))])
        bundle = build_outputs(result)
        assert bundle.counts["nodes"] == 1
        assert len(text_lines(bundle.all_text)) == 1
        assert bundle.counts["unranked"] == 2
        assert set(bundle.counts["unranked_by_status"]) == {"unsupported", "unscorable"}
        assert all(len(pair) == 2 for pair in bundle.unranked)


# ==========================================================================
# ping tiers
# ==========================================================================
class TestPingTiers:
    def test_thresholds_are_inclusive(self):
        assert (ULTRA_FAST_MS, GOOD_PING_MS) == (200.0, 500.0)
        items = [entry(build(path="/fast", ms=100.0, jitter=0.0)),
                 entry(build(path="/edge200", ms=200.0, jitter=0.0)),
                 entry(build(path="/edge500", ms=500.0, jitter=0.0))]
        tiers = render_ping_tiers(items)
        assert len(text_lines(tiers[PATH_ULTRA_FAST])) == 2
        assert len(text_lines(tiers[PATH_GOOD_PING])) == 3

    def test_just_over_the_threshold_is_excluded(self):
        items = [entry(build(ms=200.001, jitter=0.0))]
        assert text_lines(render_ping_tiers(items)[PATH_ULTRA_FAST]) == []

    def test_nodes_without_a_ping_are_in_no_tier(self):
        items = [entry(build(ms=None, jitter=None))]
        tiers = render_ping_tiers(items)
        assert tiers[PATH_ULTRA_FAST] == CRLF and tiers[PATH_GOOD_PING] == CRLF

    def test_tier_order_follows_the_input_order(self):
        items = [entry(build(path="/slow", ms=180.0, jitter=0.0)),
                 entry(build(path="/fast", ms=20.0, jitter=0.0))]
        lines = text_lines(render_ping_tiers(items)[PATH_ULTRA_FAST])
        assert lines[0].split("#")[0] == items[0][0].raw_url.split("#")[0]

    def test_tiers_are_not_computed_from_the_name_text(self):
        # legacy parsed "ping:" out of the branded name; output never does
        n = build(ms=None, jitter=None, name="🅿️ping:10ms")
        assert render_ping_tiers([entry(n)])[PATH_ULTRA_FAST] == CRLF


# ==========================================================================
# injection / control characters
# ==========================================================================
class TestInjectionSafety:
    def test_newline_in_country_cannot_add_a_line(self):
        n = build(geo=GeoInfo(country="Bad\nCountry", city="X", country_code="XX",
                              flag="🌐"))
        text = render_text([entry(n)])
        assert text.count(CRLF) == 1
        assert "\n" not in text.replace(CRLF, "")
        assert "%0A" in text

    def test_crlf_in_country_and_city_cannot_break_the_line(self):
        n = build(geo=GeoInfo(country="C\r\nX", city="bad\r\ncity",
                              country_code="XX", flag="🌐"))
        text = render_text([entry(n)])
        assert text.count(CRLF) == 1
        assert "\n" not in text.replace(CRLF, "")
        assert "%0D%0A" in text

    def test_crlf_reaching_the_raw_url_is_refused_not_emitted(self):
        # a host carrying CRLF ends up inside raw_url; output fails closed
        # instead of writing an extra line
        n = build(host="a.com\r\nX")
        assert "\r\n" in n.raw_url
        with pytest.raises(UnsafeOutputTextError):
            render_text([entry(n)])

    def test_delimiter_injection_in_country_is_encoded(self):
        n = build(geo=GeoInfo(country="A#B&amp", city="C", country_code="XX",
                              flag="🌐"))
        line = text_lines(render_text([entry(n)]))[0]
        assert line.count("#") == 1
        assert "%23" in line

    def test_control_character_in_raw_url_is_refused(self):
        n = replace(build(), raw_url="vless://a.com:443?x=1\ninjected")
        with pytest.raises(UnsafeOutputTextError):
            render_text([entry(n)])

    def test_nul_and_del_are_refused(self):
        for ch in ("\x00", "\x7f", "\x1b", "\t"):
            n = replace(build(), raw_url=f"vless://a.com:443?x={ch}y")
            with pytest.raises(UnsafeOutputTextError):
                render_link(n, score_node(n))

    def test_empty_raw_url_is_refused(self):
        n = replace(build(), raw_url="")
        with pytest.raises(OutputInputError):
            render_link(n, score_node(n))

    def test_fragment_only_raw_url_is_refused(self):
        n = replace(build(), raw_url="#justaname")
        with pytest.raises(OutputInputError):
            render_link(n, score_node(n))

    def test_hostile_protocol_fields_reach_output_only_inside_the_url(self):
        n = parse_url(f"vless://{UUID}@a.com:443?security=tls&type=tcp&evil=1\n2")
        assert n is not None                       # parser kept it as a field
        if "\n" in n.raw_url:
            with pytest.raises(UnsafeOutputTextError):
                render_link(n, score_node(n))
        else:
            assert render_text([entry(n)]).count(CRLF) == 1

    def test_unicode_and_emoji_are_not_normalised(self):
        n = build(geo=de("🇩🇪 Deutschland", "München", "DE", "🇩🇪"))
        from urllib.parse import unquote
        name = unquote(fragment(render_link(n, score_node(n))))
        assert "🇩🇪 Deutschland" in name and "München" in name

    def test_huge_geo_strings_are_model_clamped_and_stay_single_line(self):
        n = build(geo=GeoInfo(country="X" * 5000, city="Y" * 5000,
                              country_code="XX", flag="🌐"))
        assert len(geo_country(n)) == 128 and len(geo_city(n)) == 128
        line = render_link(n, score_node(n))
        assert "\n" not in line and "\r" not in line
        assert "%F0%9F%91%89" in line

    def test_huge_url_is_rendered_without_crashing(self):
        huge = replace(build(), raw_url="vless://a.com:443?path=" + "p" * 200_000)
        line = render_link(huge, score_node(huge))
        assert len(line) > 200_000 and "\n" not in line
        assert len(text_lines(render_text([(huge, score_node(huge))]))) == 1

    def test_empty_strings_fall_back_to_sentinels(self):
        n = build(geo=GeoInfo(country="", city="", country_code="", flag=""))
        assert (geo_country(n), geo_city(n)) == (UNKNOWN_TEXT, UNKNOWN_TEXT)

    def test_hostile_output_name_cannot_change_the_output_bytes(self):
        # legacy replaces the fragment entirely; no input name is emitted
        base = build(geo=de())
        hostile = replace(base, output_name="x\r\nINJECTED\x00")
        assert render_link(base, score_node(base)) == \
            render_link(hostile, score_node(hostile))

    def test_malformed_protocol_fields_do_not_reach_the_rendered_line(self):
        n = build()
        n = replace(n, protocol_fields=(("evil", "a\nb"),))
        text = render_text([entry(build())])
        assert render_text([(n, score_node(n))]).count(CRLF) == text.count(CRLF)


# ==========================================================================
# secret safety
# ==========================================================================
class TestSecretSafety:
    SECRET = "SUPERSECRETPASSWORD"

    def test_credential_bearing_link_is_rendered_per_the_legacy_contract(self):
        n = parse_url(f"trojan://{self.SECRET}@t.com:443?security=tls&type=tcp")
        assert self.SECRET in render_link(n, score_node(n))

    def test_error_messages_never_leak_credentials(self):
        n = replace(
            parse_url(f"trojan://{self.SECRET}@t.com:443?security=tls&type=tcp"),
            raw_url=f"trojan://{self.SECRET}@t.com:443\n")
        with pytest.raises(UnsafeOutputTextError) as exc:
            render_link(n, score_node(n))
        assert self.SECRET not in str(exc.value)
        assert "trojan" not in str(exc.value)

    def test_empty_url_error_does_not_leak_the_host_or_uuid(self):
        n = replace(build(uuid=UUID), raw_url="")
        with pytest.raises(OutputInputError) as exc:
            render_link(n, score_node(n))
        assert UUID not in str(exc.value) and "a.com" not in str(exc.value)

    def test_input_errors_do_not_echo_the_offending_object(self):
        with pytest.raises(OutputInputError) as exc:
            build_outputs([("trojan://x@y:1", "nope")])
        assert "trojan" not in str(exc.value)


# ==========================================================================
# input validation / policy guard
# ==========================================================================
class TestInputAndPolicy:
    def test_bare_node_is_refused(self):
        with pytest.raises(OutputInputError):
            build_outputs([build()])

    def test_non_iterable_input_is_refused(self):
        for bad in (None, 42, object()):
            with pytest.raises(OutputInputError):
                build_outputs(bad)

    def test_ranking_result_and_pairs_agree(self):
        items = [entry(build(path="/p1", ms=120.0)), entry(build(path="/p2", ms=250.0))]
        via_pairs = build_outputs(items)
        via_result = build_outputs(rank_candidates(items))
        assert via_pairs.all_text == via_result.all_text

    def test_generator_input_is_accepted(self):
        assert build_outputs(iter([entry(build())])).counts["nodes"] == 1

    @pytest.mark.parametrize("kwargs", [
        {"line_separator": "|"}, {"payload_separator": "\r"},
        {"missing_ping": "zero"}, {"missing_arch": "guess"},
        {"country_filename": "random"}, {"ping_sources": ()},
        {"ping_sources": ("tcp",)}, {"ping_decimals": 9},
        {"ping_decimals": True},
    ])
    def test_invalid_policy_values_are_refused(self, kwargs):
        with pytest.raises(OutputPolicyError):
            build_outputs([entry(build())], OutputPolicy(**kwargs))

    def test_policy_type_is_checked(self):
        with pytest.raises(OutputPolicyError):
            build_outputs([entry(build())], policy={"line_separator": CRLF})

    def test_errors_are_value_errors(self):
        for exc in (OutputInputError, OutputPolicyError, UnsafeOutputTextError):
            assert issubclass(exc, ValueError)


# ==========================================================================
# purity
# ==========================================================================
ALLOWED_MODULES = {
    "__future__", "base64", "json", "math", "re", "dataclasses", "typing",
    "urllib.parse", "hubcore.enums", "hubcore.geo", "hubcore.latency",
    "hubcore.model", "hubcore.ranking", "hubcore.scoring",
}
BANNED_TOKENS = (
    "socket", "subprocess", "urllib.request", "urllib.error", "urlopen",
    "open(", "os.environ", "import os", "from time", "import time",
    "datetime", "random", "eval(", "exec(", "write_text", "mkdir",
    "shutil", "os.rename", "os.remove", "Path(",
)
BANNED_CALLS = {
    "open", "eval", "exec", "compile", "write_text", "write_bytes", "mkdir",
    "makedirs", "system", "popen", "urlopen", "getenv", "urandom", "time",
    "monotonic", "now", "utcnow", "strftime", "id", "rename", "remove",
}


def output_source():
    return pathlib.Path(output_mod.__file__).read_text(encoding="utf-8")


def called_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


class TestPurity:
    def test_imports_are_whitelisted(self):
        tree = ast.parse(output_source())
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module or "")
        assert modules <= ALLOWED_MODULES, modules - ALLOWED_MODULES

    def test_no_banned_source_tokens(self):
        src = output_source()
        for token in BANNED_TOKENS:
            assert token not in src, f"output must not reference {token}"

    def test_no_banned_calls(self):
        names = called_names(ast.parse(output_source()))
        assert not (names & BANNED_CALLS), names & BANNED_CALLS

    def test_no_io_objects_are_reachable(self):
        for name in ("socket", "os", "sys", "time", "random", "subprocess",
                     "urllib", "requests", "pathlib", "shutil"):
            assert not hasattr(output_mod, name), name

    def test_nothing_is_written_to_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bundle = build_outputs([entry(build())])
        assert bundle.all_text
        assert list(tmp_path.iterdir()) == []

    def test_ranking_and_scoring_are_not_invoked(self):
        # output must not re-rank or re-score: feeding the same nodes in a
        # deliberately non-ranked order must not be "corrected"
        items = [entry(build(path="/z", ms=400.0)), entry(build(path="/a", ms=100.0))]
        assert text_lines(render_text(items))[0].split("#")[0] == \
            items[0][0].raw_url.split("#")[0]

    def test_output_never_reaches_stdout(self, capsys):
        build_outputs([entry(build())])
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""


# ==========================================================================
# mutation / determinism
# ==========================================================================
class TestMutationAndDeterminism:
    def snapshot(self, items):
        return (
            [id(x) for x in items],
            [(n.measured_latency, n.jitter_ms, n.score, n.geo, n.output_name,
              n.raw_url, n.endpoint, n.protocol_fields, n.transport, n.protocol)
             for n, _ in items],
            [(o.status, o.score, o.detail, dict(o.components)) for _, o in items],
        )

    def test_nothing_is_mutated(self):
        items = [entry(build(path=f"/p{i}", ms=100.0 + i)) for i in range(4)]
        before = self.snapshot(items)
        build_outputs(items)
        assert self.snapshot(items) == before

    def test_ranking_result_is_not_mutated(self):
        result = rank_candidates([entry(build(path=f"/p{i}", ms=100.0 + i))
                                  for i in range(3)]).ranked
        before = [i.sort_key for i in result]
        build_outputs(rank_candidates([entry(build(path=f"/p{i}", ms=100.0 + i))
                                       for i in range(3)]))
        assert [i.sort_key for i in result] == before

    def test_same_input_yields_byte_identical_output(self):
        items = [entry(build(path=f"/p{i}", ms=100.0 + i))
                 for i in range(5)] + [entry(parse_url(VMESS_URL))]
        a = build_outputs(items)
        b = build_outputs(items)
        assert a.all_text == b.all_text
        assert a.all_base64 == b.all_base64
        assert a.by_protocol == b.by_protocol
        assert a.by_transport == b.by_transport
        assert a.ping_tiers == b.ping_tiers
        assert a.counts == b.counts
        assert [(g.filename, g.text, g.count) for g in a.by_country] == \
               [(g.filename, g.text, g.count) for g in b.by_country]

    def test_rebuilt_equal_inputs_are_byte_identical(self):
        def items():
            return [entry(build(path=f"/p{i}", ms=100.0 + i)) for i in range(3)]
        assert build_outputs(items()).all_text == build_outputs(items()).all_text

    def test_bundle_is_frozen(self):
        bundle = build_outputs([entry(build())])
        assert isinstance(bundle, OutputBundle)
        with pytest.raises(Exception):
            bundle.all_text = "tampered"

    def test_country_group_is_frozen(self):
        group = build_outputs([entry(build(geo=de()))]).by_country[0]
        assert isinstance(group, CountryGroup)
        with pytest.raises(Exception):
            group.filename = "other"


# ==========================================================================
# adversarial invariants
# ==========================================================================
class TestAdversarialInvariants:
    def test_fake_country_and_city_are_not_invented(self):
        n = build(geo=None)
        assert "Germany" not in brand_name(n, score_node(n))
        assert geo_country(n) == UNKNOWN_TEXT and geo_city(n) == UNKNOWN_TEXT

    def test_unknown_protocol_never_gets_an_invented_group_name(self):
        n = replace(build(), protocol=Protocol.OTHER)     # recognised-but-unclassified
        groups = group_by_protocol([entry(n)])
        assert set(groups) == {"other"}
        assert set(groups) <= set(LEGACY_PROTOCOL_FILE.values())

    def test_kcp_like_transport_is_never_promoted_to_quic(self):
        # a node whose transport cannot be recognised stays UNKNOWN and is
        # excluded from transports/ exactly like legacy's "other"
        n = replace(build(), transport=Transport.UNKNOWN, raw_url="vless://a.com:443?type=kcp")
        assert group_by_transport([entry(n)]) == {}

    def test_duplicate_endpoint_distinct_config_both_survive(self):
        a = build(path="/one", uuid=UUID)
        b = build(path="/two", uuid=UUID)
        c = build(path="/one", uuid=UUID2)
        assert render_text([entry(a), entry(b), entry(c)]).count(CRLF) == 3

    def test_missing_latency_only_drops_the_ping_segment(self):
        out = ScoreOutcome(status="scored", score=1.0,
                           components={"arch_label": "VLESS-TLS"})
        with_ping = build(geo=de(), ms=88.0, jitter=0.0)
        without = build(geo=de(), ms=None, jitter=None)
        assert brand_name(with_ping, out).replace("🅿️ping:88.0ms", "") == \
            brand_name(without, out)
        assert "🅿️" not in brand_name(without, out)

    def test_huge_node_count_keeps_structure(self):
        items = [entry(build(path=f"/p{i}", ms=100.0 + (i % 300))) for i in range(1500)]
        bundle = build_outputs(items)
        assert bundle.counts["nodes"] == 1500
        assert text_lines(bundle.all_text).__len__() == 1500
        assert all(len(text_lines(g.text)) == g.count for g in bundle.by_country) \
            if bundle.by_country else True

    def test_unrenderable_entry_stops_the_batch_with_a_clear_error(self):
        items = [entry(build(path="/ok")), entry(replace(build(path="/bad"), raw_url=""))]
        with pytest.raises(OutputInputError):
            build_outputs(items)

    def test_country_names_that_sanitise_alike_share_one_group(self):
        # documented legacy collision: "United States" and "United_States"
        # sanitise to the same legacy file name, so they share one file
        items = [entry(build(geo=de("United States", "NY", "US", "🇺🇸"))),
                 entry(build(geo=de("United_States", "LA", "US", "🇺🇸")))]
        groups = group_by_country(items)
        assert [g.filename for g in groups] == ["United_States"]
        assert groups[0].count == 2 and groups[0].country == "United States"
        assert len(text_lines(groups[0].text)) == 2


# ==========================================================================
# round-trip identity (output must not damage a configuration)
# ==========================================================================
def _identity_without_pin(node):
    return config_key(replace(node, endpoint=replace(node.endpoint, resolved_ip=None)))


class TestRoundTripIdentity:
    URLS = [
        f"vless://{UUID}@a.com:443?security=tls&type=tcp&path=/x",
        f"vless://{UUID}@b.com:8443?security=tls&type=ws&path=/ws",
        f"vless://{UUID}@c.com:443?security=tls&type=grpc&serviceName=s",
        f"vless://{UUID}@d.com:443?security=tls&type=xhttp&path=/xh",
        "trojan://pw@t.com:443?security=tls&type=tcp",
        "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443",
        "hysteria2://pw@h.com:443",
        "hy2://pw@h2.com:443",
        "socks5://Og%3D%3D@1.2.3.4:1080",
        "socks://Og%3D%3D@1.2.3.5:1080",
        VMESS_URL,
    ]

    def test_rendered_lines_reparse_to_the_same_config(self):
        for url in self.URLS:
            n = build(url=url, ip=IP4, geo=de(), ms=88.0, jitter=0.0)
            assert config_key(n) == config_key(n)          # sanity
            back = parse_url(render_link(n, score_node(n)))
            assert back is not None, url
            assert back.protocol is n.protocol, url
            assert _identity_without_pin(n) == config_key(back), url
            assert back.endpoint.port == n.endpoint.port, url

    def test_rendered_lines_reparse_for_hostile_names(self):
        for country in ("A#B", "A&ampB", "A\nB", "100% Pure", "A/B", "A?B"):
            n = build(geo=GeoInfo(country=country, city=f"{country}-city",
                                  country_code="DE", flag="🇩🇪"))
            line = render_link(n, score_node(n))
            assert line.count("#") == 1
            back = parse_url(line)
            assert back is not None and _identity_without_pin(n) == config_key(back), country

    def test_policy_fields_cannot_inject_lines(self):
        for tag in ("x\r\nINJECTED", "#frag", "%00", "ok-tag"):
            policy = OutputPolicy(channel_tag=tag)
            text = render_text([entry(build())], policy)
            assert text.count(CRLF) == 1
            assert "\n" not in text.replace(CRLF, "")
            assert text.count("#") == 1

    def test_vmess_name_field_policy_cannot_inject_lines(self):
        policy = OutputPolicy(vmess_name_field="ps\nINJECTED")
        v = build(url=VMESS_URL, ip="1.2.3.4")
        text = render_text([(v, score_node(v))], policy)
        assert text.count(CRLF) == 1 and "\n" not in text.replace(CRLF, "")


# ==========================================================================
# regressions found in this phase's hunt
# ==========================================================================
class TestRegressionAdversarial:
    """Regressions for the two real defects the Phase 12 hunt reproduced."""

    def test_regression_vmess_body_prefix_is_stripped_before_decode(self):
        """BUG (reproduced): ``render_link`` handed the whole
        ``vmess://<b64>`` string to the base64 decoder, so decoding always
        failed and EVERY vmess line silently took the legacy fallback path
        - emitting the original, UN-branded link with its old ``ps``.
        FIX: strip the scheme prefix exactly like legacy rename_node
        (``raw_link[len("vmess://"):]``)."""
        v = build(url=VMESS_URL, ip="1.2.3.4", geo=de())
        line = render_link(v, score_node(v))
        data = vmess_json_from(line)
        assert data["ps"] == brand_name(v, score_node(v))
        assert data["ps"] != VMESS_JSON["ps"]        # no longer the input name
        assert line != VMESS_URL                      # no fallback path taken

    def test_regression_unknown_country_code_is_not_regional_indicators(self):
        """BUG (reproduced): country code ``XX`` - GeoInfo's sentinel for an
        unknown country - is two alphabetic letters, so ``flag_from_cc``
        produced the regional indicators for X (🇽🇽) instead of the legacy
        globe sentinel, branding unknown-location nodes as "country XX".
        FIX: ``XX`` is treated as unknown."""
        from hubcore import flag_from_cc
        assert flag_from_cc("XX") == "🇽🇽"          # the raw helper is literal
        n = build(geo=GeoInfo(country="Unknown", city="Unknown",
                              country_code="XX", flag="🌐"))
        assert geo_flag(n) == "🌐"
        assert "🇽🇽" not in brand_name(n, score_node(n)) and "📡🌐" in \
            brand_name(n, score_node(n))

    def test_regression_no_fabricated_latency_in_any_artifact(self):
        """INVARIANT PIN: legacy invented ping=150.0/jitter=10.0; no
        artifact may contain a number that was never observed."""
        v = parse_url(VMESS_URL)
        bundle = build_outputs([(v, score_node(v))])
        blob = bundle.all_text + "".join(bundle.ping_tiers.values())
        assert "150.0" not in blob and "jitter" not in blob


# ==========================================================================
# performance
# ==========================================================================
class TestPerformance:
    def test_a_few_thousand_nodes_render_quickly(self):
        items = [entry(build(path=f"/p{i}", ms=100.0 + (i % 400))) for i in range(3000)]
        t0 = time.monotonic()
        bundle = build_outputs(items)
        dt = time.monotonic() - t0
        assert bundle.counts["nodes"] == 3000
        assert dt < 10.0, f"output generation too slow: {dt:.2f}s"

    def test_large_output_is_still_deterministic(self):
        def items():
            return [entry(build(path=f"/p{i}", ms=100.0 + (i % 200)))
                    for i in range(800)]
        assert build_outputs(items()).all_base64 == build_outputs(items()).all_base64
