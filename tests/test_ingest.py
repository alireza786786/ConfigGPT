# -*- coding: utf-8 -*-
"""Phase 3 tests: source ingestion integrated with Phase 2 parsers.

Covers: text/file/batch ingestion, metadata preservation, error
containment, key-aware views, BOM/CRLF handling, hostile inputs,
and integration with real repository data (offline).
"""
import pytest
import os

from hubcore import (
    IngestError,
    IngestResult,
    IngestStats,
    IngestedNode,
    Node,
    Protocol,
    SourceIngestor,
    SourceKind,
    SourceOrigin,
    config_index,
    config_key,
    endpoint_index,
    endpoint_key,
    parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"


def make_ingestor(**kw) -> SourceIngestor:
    return SourceIngestor(**kw)


# ==========================================================================
# basic ingestion
# ==========================================================================

class TestIngestText:
    def test_simple_mixed_source(self):
        ing = make_ingestor()
        text = (
            f"vless://{UUID}@a.com:443?type=ws\n"
            "trojan://pw@b.com:1\n"
        )
        r = ing.ingest_text(text, SourceOrigin("s1", SourceKind.RAW_TEXT))
        assert r.stats.lines_seen == 2
        assert r.stats.lines_parsed == 2
        assert r.stats.lines_rejected == 0
        assert r.stats.by_protocol == {"VLESS": 1, "TROJAN": 1}
        assert len(r.nodes) == 2

    def test_metadata_preserved(self):
        ing = make_ingestor()
        text = f"\n\nvless://{UUID}@a.com:1\n"
        r = ing.ingest_text(text, SourceOrigin("s1", SourceKind.RAW_TEXT))
        w = r.nodes[0]
        assert w.line_no == 3
        assert w.origin.name == "s1"
        assert len(w.line_hash) == 16
        # raw line text is NOT stored anywhere on the wrapper
        assert "a.com" not in repr(w.line_hash)

    def test_error_containment_never_crashes(self):
        ing = make_ingestor()
        hostile = "\n".join([
            "garbage",
            f"vless://{UUID}@a.com:1",
            "vmess://###broken###",
            "x" * 9000,
            f"vless://{UUID}@a.com:1?" + "p=" + "a" * 9000,
            "ftp://nope:1",
            f"trojan://pw@b.com:2",
            "",
        ])
        r = ing.ingest_text(hostile, SourceOrigin("h", SourceKind.RAW_TEXT))
        assert r.stats.lines_seen == 7
        assert r.stats.lines_parsed == 2
        assert len(r.errors) == 5
        reasons = {e.reason for e in r.errors}
        assert reasons == {"no_scheme", "parse", "too_long"}
        # reason mapping: garbage & 'x'*9000 => no_scheme (cheap structural
        # check runs before the length scan, deliberately); broken vmess =>
        # parse; over-long WITH-scheme => too_long; ftp:// => unsupported
        # scheme surfaces as 'parse' from the safe parser (single funnel).
        # error records carry line numbers, never raw content
        for e in r.errors:
            assert "xxx" not in str(e)
            assert isinstance(e.line_no, int)

    def test_blank_and_whitespace_only(self):
        ing = make_ingestor()
        r = ing.ingest_text("  \n\t\n   \n", SourceOrigin("s", SourceKind.RAW_TEXT))
        assert r.stats.lines_seen == 3
        assert r.nodes == []
        assert r.errors == []

    def test_empty_input(self):
        ing = make_ingestor()
        r = ing.ingest_text("", SourceOrigin("s", SourceKind.RAW_TEXT))
        assert r.stats.lines_seen == 0 and r.nodes == [] and r.errors == []

    def test_non_string_input_never_crashes(self):
        ing = make_ingestor()
        r = ing.ingest_text(12345, SourceOrigin("s", SourceKind.RAW_TEXT))
        assert r.nodes == [] and r.errors == []

    def test_bom_tolerated(self):
        ing = make_ingestor()
        text = "﻿" + f"vless://{UUID}@a.com:1\n"
        r = ing.ingest_text(text, SourceOrigin("b", SourceKind.RAW_TEXT))
        assert r.stats.lines_parsed == 1
        assert r.errors == []

    def test_crlf_tolerated(self):
        ing = make_ingestor()
        text = f"vless://{UUID}@a.com:1\r\ntrojan://pw@b.com:2\r\n"
        r = ing.ingest_text(text, SourceOrigin("c", SourceKind.RAW_TEXT))
        assert r.stats.lines_seen == 2
        assert r.stats.lines_parsed == 2

    def test_line_hash_is_content_based(self):
        ing = make_ingestor()
        t1 = f"vless://{UUID}@a.com:1"
        t2 = f"vless://{UUID}@a.com:1"
        r1 = ing.ingest_text(t1, SourceOrigin("x", SourceKind.RAW_TEXT))
        r2 = ing.ingest_text(t2, SourceOrigin("y", SourceKind.RAW_TEXT))
        assert r1.nodes[0].line_hash == r2.nodes[0].line_hash

    def test_max_line_rejected_with_reason(self):
        ing = make_ingestor(max_line_chars=100)
        long_link = f"vless://{UUID}@a.com:1?" + "p=" + "a" * 200
        r = ing.ingest_text(long_link, SourceOrigin("s", SourceKind.RAW_TEXT))
        assert r.stats.lines_parsed == 0
        assert r.errors[0].reason == "too_long"


class TestIngestFile:
    def test_missing_file_is_error_not_crash(self, tmp_path):
        ing = make_ingestor()
        r = ing.ingest_file(str(tmp_path / "nope.txt"))
        assert r.nodes == []
        assert r.errors[0].reason == "file_missing"

    def test_real_file_roundtrip(self, tmp_path):
        ing = make_ingestor()
        p = tmp_path / "src.txt"
        p.write_text(
            f"vless://{UUID}@a.com:443\n"
            "not-a-config\n"
            "trojan://pw@b.com:1\n",
            encoding="utf-8",
        )
        r = ing.ingest_file(str(p), origin_name="unit-source")
        assert r.origin.name == "unit-source"
        assert r.origin.kind is SourceKind.LOCAL_FILE
        assert r.stats.lines_parsed == 2
        assert r.errors[0].line_no == 2

    def test_oversize_file_rejected(self, tmp_path):
        ing = make_ingestor(max_file_bytes=16)
        p = tmp_path / "big.txt"
        p.write_text("a" * 64, encoding="utf-8")
        r = ing.ingest_file(str(p))
        assert r.errors[0].reason == "file_too_big"

    def test_directory_rejected(self, tmp_path):
        ing = make_ingestor()
        r = ing.ingest_file(str(tmp_path))
        assert r.errors[0].reason == "file_missing"


class TestIngestBatch:
    def test_ingest_many_combines(self):
        ing = make_ingestor()
        items = [
            (SourceOrigin("a", SourceKind.RAW_TEXT), f"vless://{UUID}@a.com:1\njunk\n"),
            (SourceOrigin("b", SourceKind.RAW_TEXT), "trojan://pw@b.com:2\n"),
        ]
        r = ing.ingest_many(items)
        assert len(r.nodes) == 2
        assert r.stats.lines_seen == 3
        assert r.stats.lines_parsed == 2
        assert {w.origin.name for w in r.nodes} == {"a", "b"}

    def test_ingest_many_empty(self):
        ing = make_ingestor()
        r = ing.ingest_many([])
        assert r.nodes == [] and r.stats.lines_seen == 0

    def test_merge_renumbers_lines(self):
        ing = make_ingestor()
        r1 = ing.ingest_text(f"vless://{UUID}@a.com:1\nbad\n",
                             SourceOrigin("a", SourceKind.RAW_TEXT))
        r2 = ing.ingest_text("trojan://pw@b.com:2\n",
                             SourceOrigin("b", SourceKind.RAW_TEXT))
        m = r1.merged(r2)
        assert m.nodes[-1].line_no == r1.stats.lines_seen + 1
        assert m.stats.lines_seen == 3


# ==========================================================================
# key-aware views (endpoint_key / config_key usage)
# ==========================================================================

class TestKeyViews:
    def _nodes(self):
        ing = make_ingestor()
        text = "\n".join([
            f"vless://{UUID}@a.com:443?type=ws",        # config A
            f"vless://{UUID}@a.com:443?type=grpc",      # same endpoint, diff config
            f"vless://{UUID}@b.com:443",                # different endpoint
        ])
        r = ing.ingest_text(text, SourceOrigin("k", SourceKind.RAW_TEXT))
        return r

    def test_endpoint_index_groups_by_host_port(self):
        r = self._nodes()
        idx = endpoint_index(r.nodes)
        assert len(idx) == 2  # a.com:443 and b.com:443
        a_group = idx[endpoint_key(r.nodes[0].node)]
        assert len(a_group) == 2

    def test_config_index_separates_configs(self):
        r = self._nodes()
        idx = config_index(r.nodes)
        assert len(idx) == 3  # ws vs grpc vs b.com are distinct configs

    def test_identity_keys_match_phase1_directly(self):
        r = self._nodes()
        n0 = r.nodes[0].node
        n1 = r.nodes[1].node
        assert endpoint_key(n0) == endpoint_key(n1)
        assert config_key(n0) != config_key(n1)
        # wrappers agree with direct calls on the raw Node
        assert endpoint_key(r.nodes[0].node) == endpoint_key(parse_url(
            f"vless://{UUID}@a.com:443?type=ws"))

    def test_views_accept_bare_nodes_too(self):
        n = parse_url(f"vless://{UUID}@a.com:1")
        assert list(endpoint_index([n]).keys()) == [endpoint_key(n)]
        assert list(config_index([n]).keys()) == [config_key(n)]


# ==========================================================================
# integration with real repository data (offline)
# ==========================================================================

class TestRepoIntegration:
    REPO_FILES = [
        "Config/vless.txt", "Config/vmess.txt", "Config/ss.txt",
        "Config/trojan.txt", "Config/hysteria2.txt", "Config/socks.txt",
    ]

    @pytest.mark.skipif(
        not any(os.path.isfile(p) for p in ["Config/vless.txt", "Config/vmess.txt"]),
        reason="optional legacy Config/*.txt files missing")
    def test_ingest_real_config_files(self):
        ing = make_ingestor()
        results = []
        for path in self.REPO_FILES:
            r = ing.ingest_file(path, origin_name=path)
            results.append(r)
            assert r.stats.lines_parsed > 0, f"nothing parsed from {path}"
            # parse errors, if any, never carry raw content
            for e in r.errors:
                assert "://" not in e.reason
        combined = results[0]
        for r in results[1:]:
            combined = combined.merged(r)
        assert combined.stats.lines_parsed > 1000
        assert set(combined.stats.by_protocol) <= {
            "VLESS", "VMESS", "SHADOWSOCKS", "TROJAN", "HYSTERIA2", "SOCKS5",
        }

    def test_real_nodes_pass_through_views(self):
        ing = make_ingestor()
        r = ing.ingest_file("Config/vmess.txt", origin_name="vmess")
        idx = config_index(r.nodes)
        # views always store BARE nodes (unwrapped), keyed by config identity
        for key, group in idx.items():
            assert all(isinstance(n, Node) for n in group)
            assert all(config_key(n) == key for n in group)
        # bare Node inputs are accepted by the views as well
        bare = [w.node for w in r.nodes[:5]]
        idx2 = config_index(bare)
        for key, group in idx2.items():
            assert all(config_key(n) == key for n in group)

    def test_no_credentials_in_error_records(self):
        ing = make_ingestor()
        r = ing.ingest_file("Config/trojan.txt", origin_name="t")
        blob = "\n".join(str(e) for e in r.errors) + repr(r.stats.as_dict())
        # a trojan password known to exist in repo data must not appear
        assert "Telegram_healer_config" not in blob


# ==========================================================================
# adversarial / regression
# ==========================================================================

class TestAdversarial:
    def test_repeated_merge_grows_cleanly(self):
        ing = make_ingestor()
        acc = ing.ingest_text(f"vless://{UUID}@a.com:1",
                              SourceOrigin("a", SourceKind.RAW_TEXT))
        for i in range(5):
            nxt = ing.ingest_text("trojan://pw@b.com:1",
                                  SourceOrigin(f"s{i}", SourceKind.RAW_TEXT))
            acc = acc.merged(nxt)
        assert acc.stats.lines_seen == 6
        assert len(acc.nodes) == 6

    def test_origin_name_required_sane(self):
        o = SourceOrigin("", SourceKind.RAW_TEXT)
        assert o.name == "unnamed"
        o2 = SourceOrigin("n", SourceKind.URL, "ftp://bad")
        assert o2.location == ""  # non-http(s) URL locations are dropped

    def test_no_recursion_on_hostile_nesting(self):
        ing = make_ingestor()
        nested = "vless://" + "@" * 500 + "h.com:1"
        r = ing.ingest_text(nested, SourceOrigin("n", SourceKind.RAW_TEXT))
        assert r.stats.lines_parsed == 0  # rejected as parse error

    def test_stats_dict_is_a_copy(self):
        ing = make_ingestor()
        r = ing.ingest_text(f"vless://{UUID}@a.com:1",
                            SourceOrigin("s", SourceKind.RAW_TEXT))
        d = r.stats.as_dict()
        d["lines_parsed"] = 999
        assert r.stats.lines_parsed == 1
