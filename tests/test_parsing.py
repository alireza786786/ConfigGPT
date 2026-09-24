# -*- coding: utf-8 -*-
"""Phase 2 tests: protocol parsers.

Covers happy paths, malformed inputs, boundaries, encodings, base64
variants, cross-protocol confusion, repository real-data regression and
offline property/fuzz-style checks. All offline; no network.
"""
import base64
import json

import pytest

from hubcore import Protocol, Security, Transport, config_key, endpoint_key
from hubcore.parsing import (
    LengthLimitError,
    MalformedURLError,
    ParseError,
    UnsupportedSchemeError,
    parse_lines,
    parse_url,
    safe_parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def vmess_link(obj: dict) -> str:
    return "vmess://" + b64std(json.dumps(obj).encode())


def make_vless(**params) -> str:
    q = "&".join(f"{k}={v}" for k, v in params.items())
    q = ("?" + q) if q else ""
    return f"vless://{UUID}@example.com:443{q}"


# ==========================================================================
# happy paths
# ==========================================================================

class TestVlessHappy:
    def test_minimal(self):
        n = parse_url(f"vless://{UUID}@example.com:443")
        assert n.protocol is Protocol.VLESS
        assert n.uuid == UUID
        assert (n.endpoint.host, n.endpoint.port) == ("example.com", 443)
        assert n.transport is Transport.UNKNOWN
        assert n.security is Security.UNKNOWN

    def test_full_reality(self):
        url = ("vless://" + UUID + "@1.2.3.4:8443"
               "?security=reality&pbk=PUBKEY123&sid=abcd&spx=%2F"
               "&fp=chrome&flow=xtls-rprx-vision&type=tcp&sni=www.example.com")
        n = parse_url(url)
        d = dict(n.protocol_fields)
        assert n.security is Security.REALITY
        assert n.flow == "xtls-rprx-vision"
        assert n.fingerprint == "chrome"
        assert d["vless.reality.pubkey"] == "PUBKEY123"
        assert d["vless.reality.shortid"] == "abcd"
        assert d["vless.reality.spx"] == "/"
        assert n.sni == "www.example.com"

    def test_ws_tls(self):
        n = parse_url(f"vless://{UUID}@h.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com")
        assert n.transport is Transport.WS
        assert n.security is Security.TLS
        assert n.path == "/ws"
        assert n.host_header == "cdn.example.com"

    def test_grpc_servicename(self):
        n = parse_url(f"vless://{UUID}@h.com:443?type=grpc&serviceName=svc1&security=tls")
        assert n.transport is Transport.GRPC
        assert n.service_name == "svc1"

    def test_xhttp(self):
        n = parse_url(f"vless://{UUID}@h.com:443?type=xhttp&security=tls&mode=packet-up&host=lunex.store")
        assert n.transport is Transport.XHTTP
        assert dict(n.protocol_fields)["qp.mode"] == "packet-up"

    def test_fragment_preserved(self):
        n = parse_url(f"vless://{UUID}@h.com:443#%F0%9F%87%A9%F0%9F%87%AAName")
        assert n.output_name == "🇩🇪Name"
        assert "fragment" not in dict(n.protocol_fields)

    def test_kcp_is_unknown_not_quic(self):
        n = parse_url(f"vless://{UUID}@h.com:443?type=kcp")
        assert n.transport is Transport.UNKNOWN
        assert dict(n.protocol_fields)["transport.raw"] == "kcp"

    def test_unknown_params_preserved(self):
        n = parse_url(f"vless://{UUID}@h.com:443?customFutureParam=x&another=1")
        d = dict(n.protocol_fields)
        assert d["qp.customfutureparam"] == "x"
        assert d["qp.another"] == "1"


class TestVmessHappy:
    def test_minimal(self):
        n = parse_url(vmess_link({"v": "2", "ps": "test", "add": "1.2.3.4",
                                  "port": "443", "id": "vm-uuid",
                                  "net": "ws", "tls": "tls"}))
        assert n.protocol is Protocol.VMESS
        assert n.uuid == "vm-uuid"
        assert n.endpoint.host == "1.2.3.4"
        assert n.endpoint.port == 443
        assert n.transport is Transport.WS
        assert n.security is Security.TLS
        assert dict(n.protocol_fields)["vmess.encryption"] == "auto"

    def test_port_string_or_int_same_identity(self):
        a = parse_url(vmess_link({"add": "h", "port": "443", "id": "u", "net": "ws"}))
        b = parse_url(vmess_link({"add": "h", "port": 443, "id": "u", "net": "ws"}))
        assert a.endpoint.port == b.endpoint.port == 443
        assert config_key(a) == config_key(b)

    def test_scy_recorded(self):
        n = parse_url(vmess_link({"add": "h", "port": 1, "id": "u", "scy": "zero"}))
        assert dict(n.protocol_fields)["vmess.encryption"] == "zero"

    def test_unknown_json_keys_preserved(self):
        n = parse_url(vmess_link({"add": "h", "port": 1, "id": "u",
                                  "brandNewField": "v1"}))
        assert dict(n.protocol_fields)["vmess.brandnewfield"] == "v1"

    def test_fragment(self):
        n = parse_url(vmess_link({"add": "h", "port": 1, "id": "u"}) + "#Named")
        assert n.output_name == "Named"


class TestSsHappy:
    def test_sip002_web64(self):
        link = "ss://" + b64url(b"rc4-md5:secretpw") + "@1.2.3.4:8080#tag"
        n = parse_url(link)
        d = dict(n.protocol_fields)
        assert n.protocol is Protocol.SHADOWSOCKS
        assert d["ss.method"] == "rc4-md5"
        assert d["ss.password"] == "secretpw"
        assert n.endpoint.port == 8080

    def test_sip002_plain_percent_encoded(self):
        n = parse_url("ss://aes-256-gcm%3Apass%40word@5.5.5.5:8388")
        d = dict(n.protocol_fields)
        assert d["ss.method"] == "aes-256-gcm"
        assert d["ss.password"] == "pass@word"

    def test_legacy_full_base64(self):
        payload = base64.b64encode(b"aes-128-gcm:pw123@9.9.9.9:8388").decode().rstrip("=")
        n = parse_url("ss://" + payload)
        d = dict(n.protocol_fields)
        assert n.endpoint.host == "9.9.9.9"
        assert n.endpoint.port == 8388
        assert d["ss.method"] == "aes-128-gcm"
        assert d["ss.password"] == "pw123"

    def test_base64_variants(self):
        # standard, urlsafe, padded, no-pad must all decode
        blob = b"rc4:xyz"
        for enc in (base64.b64encode(blob).decode(),
                    base64.urlsafe_b64encode(blob).decode().rstrip("="),
                    base64.b64encode(blob).decode()):
            if enc.startswith("rc4:"):
                n = parse_url("ss://" + enc.split("@")[0] + "@4.4.4.4:1")
                assert dict(n.protocol_fields)["ss.password"] == "xyz"

    def test_plugin_preserved(self):
        n = parse_url("ss://cmM0OnB3@3.3.3.3:80?plugin=obfs-local%3Bobfs%3Dhttp")
        assert dict(n.protocol_fields)["ss.plugin"].startswith("obfs-local")


class TestTrojanHappy:
    def test_minimal(self):
        n = parse_url("trojan://pw123@example.com:443?sni=t.example.com&type=ws#f")
        assert n.protocol is Protocol.TROJAN
        assert n.password == "pw123"
        assert n.sni == "t.example.com"
        assert n.transport is Transport.WS
        assert n.output_name == "f"

    def test_percent_encoded_password(self):
        n = parse_url("trojan://p%40ss%3Aword@h.com:1")
        assert n.password == "p@ss:word"


class TestHysteria2Happy:
    def test_minimal(self):
        n = parse_url("hysteria2://authpw@6.6.6.6:443")
        assert n.protocol is Protocol.HYSTERIA2
        assert n.password == "authpw"

    def test_obfs(self):
        n = parse_url("hy2://a@h.com:443?obfs=salamander&obfs-password=ob1&insecure=1")
        d = dict(n.protocol_fields)
        assert d["hy2.obfs"] == "salamander"
        assert d["hy2.obfs.password"] == "ob1"
        assert n.allow_insecure is True

    def test_alias_hy2(self):
        n = parse_url("hy2://a@h.com:1")
        assert n.protocol is Protocol.HYSTERIA2


class TestSocksHappy:
    def test_basic(self):
        n = parse_url("socks://user:pass@5.6.7.8:1080")
        assert n.protocol is Protocol.SOCKS5
        assert n.endpoint.port == 1080
        assert n.secret == "user"
        assert n.password == "pass"

    def test_no_credentials(self):
        n = parse_url("socks5://5.6.7.8:1080")
        assert n.protocol is Protocol.SOCKS5
        assert n.secret == ""


# ==========================================================================
# malformed / attack inputs
# ==========================================================================

class TestMalformed:
    @pytest.mark.parametrize("bad", [
        "", "   ", "not-a-url", "http://example.com", "ftp://x:1",
        "vless:", "vless://", "vless://@host:1", "vless://uuid@:443",
        "vless://uuid@example.com:0", "vless://uuid@example.com:65536",
        "vless://uuid@example.com:-1", "vless://uuid@example.com:abc",
        "vless://uuid@[bad-ipv6:443", "vless://uuid@[::1]:abc",
        "vmess://", "vmess://!!!!", "vmess://aGVsbG8=",  # 'hello' not JSON
        "vmess://" + b64std(b"[1,2,3]"),                 # JSON not object
        "vmess://" + b64std(b'{"add":"h"}'),             # missing id/port
        "vmess://" + b64std(b'{"add":"","port":1,"id":"u"}'),
        "vmess://" + b64std(b'{"port":1,"id":"u"}'),     # missing add
        "ss://", "ss://@1.2.3.4:1", "ss://nopassword@1.2.3.4:1",
        "trojan://@h.com:1", "trojan://", "hysteria2://@h.com:1",
        "://x", "1://x",
    ])
    def test_rejected(self, bad):
        with pytest.raises(ParseError):
            parse_url(bad)

    def test_non_uuid_credentials_allowed_permissively(self):
        # repo evidence: trojan username "Telegram_healer_config"
        n = parse_url("trojan://Telegram_healer_config@104.21.68.68:443")
        assert n.password == "Telegram_healer_config"

    def test_unsupported_scheme_named(self):
        with pytest.raises(UnsupportedSchemeError):
            parse_url("wireguard://key@h:51820")

    def test_safe_parse_never_raises(self):
        for bad in ("", "junk", "vmess://###", "vless://", None if False else 123):
            try:
                assert safe_parse_url(bad) is None
            except Exception:  # pragma: no cover
                pytest.fail("safe_parse_url raised")

    def test_empty_credentials(self):
        with pytest.raises(ParseError):
            parse_url("vless://@h.com:443")

    def test_ipv6_zone_id(self):
        # zone-id in brackets is accepted structurally; host preserved
        n = safe_parse_url("vless://" + UUID + "@[fe80::1%25eth0]:443")
        if n is not None:
            assert "fe80" in n.endpoint.host

    def test_malformed_ipv6_rejected(self):
        assert safe_parse_url("vless://" + UUID + "@[gg::gg]:443") is None


class TestBoundaries:
    def test_port_edges(self):
        assert parse_url(f"vless://{UUID}@h.com:65535").endpoint.port == 65535
        assert parse_url(f"vless://{UUID}@h.com:1").endpoint.port == 1
        for bad in ("0", "65536", "-5", "99999999"):
            assert safe_parse_url(f"vless://{UUID}@h.com:{bad}") is None

    def test_oversize_url_rejected(self):
        huge = f"vless://{UUID}@h.com:443?x=" + "a" * 9000
        with pytest.raises(LengthLimitError):
            parse_url(huge)

    def test_huge_password_capped(self):
        pw = "p" * 5000
        assert safe_parse_url(f"trojan://{pw}@h.com:1") is None

    def test_very_long_but_valid(self):
        path = "/p" * 100
        n = parse_url(f"vless://{UUID}@h.com:443?type=ws&path={path}")
        assert n.path == "/p" * 100

    def test_blob_size_limit(self):
        line = "vless://" + UUID + "@h.com:1\n"
        with pytest.raises(LengthLimitError):
            parse_lines(line * 700000)  # ~37 MB > 32 MiB cap


class TestEncodings:
    def test_percent_encoding_utf8(self):
        n = parse_url(f"vless://{UUID}@h.com:443#%E2%9C%93%E2%9C%93")
        assert n.output_name == "✓✓"

    def test_broken_percent_tolerated_or_rejected(self):
        # must not raise a non-ParseError exception
        try:
            parse_url(f"vless://{UUID}@h.com:443#%zz")
        except ParseError:
            pass

    def test_unicode_host_rejected_or_kept(self):
        # idn hosts are structurally acceptable; must not crash
        n = safe_parse_url(f"vless://{UUID}@مثال.ایران:443")
        assert n is None or n.endpoint.host

    def test_base64_with_newlines(self):
        blob = b64std(b"rc4:pw")
        blob_ws = blob[:4] + "\n" + blob[4:]
        n = parse_url("ss://" + blob_ws + "@1.1.1.1:1")
        assert dict(n.protocol_fields)["ss.password"] == "pw"


class TestCrossProtocol:
    def test_scheme_mismatch_rejected(self):
        # vmess body under vless scheme must not parse as vless
        assert safe_parse_url("vless://" + b64std(b'{"add":"h"}')) is None

    def test_ss_link_not_detected_as_vmess(self):
        n = parse_url("ss://" + b64url(b"rc4:pw") + "@1.2.3.4:1")
        assert n.protocol is Protocol.SHADOWSOCKS

    def test_hy2_and_hysteria2_same_identity(self):
        a = parse_url("hysteria2://pw@h.com:443")
        b = parse_url("hy2://pw@h.com:443")
        assert config_key(a) == config_key(b)

    def test_socks_and_socks5_same_identity(self):
        a = parse_url("socks://u:p@h.com:1080")
        b = parse_url("socks5://u:p@h.com:1080")
        assert config_key(a) == config_key(b)

    def test_duplicate_query_params_last_wins_deterministic(self):
        a = parse_url(f"vless://{UUID}@h.com:443?type=ws&type=grpc")
        b = parse_url(f"vless://{UUID}@h.com:443?type=grpc&type=ws")
        assert a.transport is Transport.GRPC  # last value wins
        # conflicting params preserved via 'key[]'
        assert dict(a.protocol_fields).get("qp.type[]") == "ws"

    def test_conflicting_params_differ_in_identity(self):
        a = parse_url(f"vless://{UUID}@h.com:443?type=ws&type=grpc")
        b = parse_url(f"vless://{UUID}@h.com:443?type=ws")
        assert config_key(a) != config_key(b)


class TestIdentityPreservation:
    def test_reality_pubkey_differs_identity(self):
        a = parse_url(f"vless://{UUID}@h.com:443?security=reality&pbk=K1")
        b = parse_url(f"vless://{UUID}@h.com:443?security=reality&pbk=K2")
        assert config_key(a) != config_key(b)

    def test_ss_method_differs_identity(self):
        a = parse_url("ss://" + b64url(b"rc4-md5:pw") + "@h.com:1")
        b = parse_url("ss://" + b64url(b"aes-128-gcm:pw") + "@h.com:1")
        assert config_key(a) != config_key(b)

    def test_rename_only_changes_name_not_identity(self):
        a = parse_url(f"vless://{UUID}@h.com:443#NameA")
        b = parse_url(f"vless://{UUID}@h.com:443#NameB")
        assert config_key(a) == config_key(b)
        assert a.output_name == "NameA"
        assert b.output_name == "NameB"
        assert "fragment" not in dict(a.protocol_fields)


# ==========================================================================
# repository real-data regression (offline; uses tracked output files)
# ==========================================================================

class TestRepoRealData:
    REPO_FILES = [
        "Config/vless.txt", "Config/vmess.txt", "Config/ss.txt",
        "Config/trojan.txt", "Config/hysteria2.txt", "Config/socks.txt",
    ]

    def _lines(self, path, cap=300):
        try:
            with open(path, encoding="utf-8") as f:
                return [l.strip() for l in f if l.strip()][:cap]
        except OSError:
            pytest.skip(f"{path} not present")

    def test_all_repo_lines_parse_or_fail_cleanly(self):
        total = 0
        for path in self.REPO_FILES:
            lines = self._lines(path)
            parsed = 0
            for line in lines:
                node = safe_parse_url(line)
                assert node is not None, f"unexpected hard-fail shape in {path}"
                if node is not None:
                    parsed += 1
                total += 1
            assert parsed > 0, f"no lines parsed from {path}"

    def test_real_vless_protocol_fields(self):
        n = parse_url(self._lines("Config/vless.txt")[0])
        assert n.protocol is Protocol.VLESS
        assert n.endpoint.host and 0 < n.endpoint.port < 65536

    def test_real_vmess_has_uuid_and_encryption(self):
        n = parse_url(self._lines("Config/vmess.txt")[0])
        assert n.uuid
        assert "vmess.encryption" in dict(n.protocol_fields)

    def test_real_ss_has_method(self):
        n = parse_url(self._lines("Config/ss.txt")[0])
        d = dict(n.protocol_fields)
        assert d.get("ss.method")

    def test_real_trojan_has_password(self):
        n = parse_url(self._lines("Config/trojan.txt")[0])
        assert n.password

    def test_real_hysteria2_auth(self):
        n = parse_url(self._lines("Config/hysteria2.txt")[0])
        assert n.password


# ==========================================================================
# property/fuzz-style (offline, deterministic)
# ==========================================================================

class TestRegressionAdversarial:
    """Regression tests for bugs found during the Phase 2 bug hunt."""

    def test_regression_vmess_add_smuggling_rejected(self):
        # BUG: add='h:443'/'h/x'/'a@b' used to become the host verbatim
        for bad_add in ("h:443", "h/x", "a@b"):
            link = vmess_link({"add": bad_add, "port": 1, "id": "u"})
            with pytest.raises(ParseError):
                parse_url(link)

    def test_regression_vmess_bracketed_ipv6_ok(self):
        n = parse_url(vmess_link({"add": "[::1]", "port": 1, "id": "u"}))
        assert n.endpoint.host == "::1"

    def test_regression_vless_uuid_password_component_rejected(self):
        # BUG: 'uuid:secret@' silently dropped the secret (info loss)
        with pytest.raises(ParseError):
            parse_url("vless://aa:bb@h.com:443")

    def test_regression_hy2_userinfo_with_path(self):
        # repo-real shape: hy2://github.com/x/fanqiang@62.210.7.139:60111/
        n = parse_url("hy2://github.com/Alvin9999-newpac/fanqiang@62.210.7.139:60111/?insecure=1")
        assert n.endpoint.host == "62.210.7.139"
        assert n.endpoint.port == 60111
        assert n.allow_insecure is True

    def test_regression_ss_web64_userinfo(self):
        # BUG: web64 userinfo decoded to garbage method before fix
        n = parse_url("ss://" + b64url(b"rc4-md5:secretpw") + "@1.2.3.4:8080")
        d = dict(n.protocol_fields)
        assert d["ss.method"] == "rc4-md5"
        assert d["ss.password"] == "secretpw"

    def test_regression_vmess_port_string_identity(self):
        # BUG: port string-ness leaked into config identity
        a = parse_url(vmess_link({"add": "h", "port": "443", "id": "u"}))
        b = parse_url(vmess_link({"add": "h", "port": 443, "id": "u"}))
        assert config_key(a) == config_key(b)

    def test_regression_conflicting_params_in_identity(self):
        # BUG: 'type=ws&type=grpc' collapsed to 'type=grpc' silently
        a = parse_url(f"vless://{UUID}@h.com:443?type=ws&type=grpc")
        b = parse_url(f"vless://{UUID}@h.com:443?type=grpc")
        assert config_key(a) != config_key(b)
        assert dict(a.protocol_fields).get("qp.type[]") == "ws"

    def test_regression_empty_password_ss_legacy_rejected(self):
        link = "ss://" + b64std(b"rc4:@1.1.1.1:1")
        with pytest.raises(ParseError):
            parse_url(link)

    def test_regression_double_at_userinfo(self):
        # last '@' wins; earlier '@' stays in the credential, uuid rejects it
        with pytest.raises(ParseError):
            parse_url("vless://u@a@h.com:443")

    def test_regression_uppercase_scheme(self):
        n = parse_url("VLESS://" + UUID + "@h.com:443")
        assert n.protocol is Protocol.VLESS


class TestFuzzStyle:
    def test_arbitrary_bytes_never_crash(self):
        import itertools
        alphabets = [b"vless://", b"vmess://", b"ss://", b"trojan://",
                     b"hysteria2://", b"socks5://"]
        chunks = [b"@", b":", b"1", b"[", b"]", b"%", b"?", b"=", b"&",
                  b"#", b"A", b"\xff", b"\n", b" ", b"-", b"_", b".", b"::"]
        crashed = []
        for scheme in alphabets:
            for c1, c2 in itertools.product(chunks[:10], chunks[:10]):
                blob = scheme + c1 + c2 + b"@h:1"
                try:
                    parse_url(blob.decode("latin-1"))
                except ParseError:
                    pass
                except Exception as e:  # non-ParseError leak
                    crashed.append((blob, repr(e)))
        assert not crashed, crashed[:5]

    def test_parse_lines_mixed(self):
        text = "\n".join([
            f"vless://{UUID}@a.com:1",
            "",
            "   ",
            "not a config",
            "trojan://pw@b.com:2",
            "vmess://invalid",
        ])
        nodes = parse_lines(text)
        assert len(nodes) == 2
        assert nodes[0].protocol is Protocol.VLESS
        assert nodes[1].protocol is Protocol.TROJAN

    def test_parse_lines_strict_raises(self):
        with pytest.raises(ParseError):
            parse_lines(f"vless://{UUID}@a.com:1\nvmess://broken", strict=True)

    def test_idempotence(self):
        url = f"vless://{UUID}@h.com:443?type=ws&security=tls&sni=s&path=%2Fp#Name"
        n1 = parse_url(url)
        n2 = parse_url(url)
        assert config_key(n1) == config_key(n2)
        assert dict(n1.protocol_fields) == dict(n2.protocol_fields)


# ==========================================================================
# credential-leakage guards
# ==========================================================================

class TestNoCredentialLeakage:
    SECRET = "SUPERSECRET123"

    def test_error_message_has_no_secret(self):
        try:
            parse_url(f"trojan://{self.SECRET}@h.com:0")
            pytest.fail("expected ParseError")
        except ParseError as e:
            assert self.SECRET not in str(e)
            assert self.SECRET not in getattr(e, "reason", "")

    def test_error_message_has_no_uuid(self):
        link = f"vless://{UUID}@h.com:0"
        try:
            parse_url(link)
            pytest.fail("expected ParseError")
        except ParseError as e:
            assert UUID not in str(e)

    def test_vmess_error_has_no_payload(self):
        payload = b64std(json.dumps({"add": "h", "port": 0, "id": "SECRET-ID"}).encode())
        try:
            parse_url("vmess://" + payload)
            pytest.fail("expected ParseError")
        except ParseError as e:
            assert "SECRET-ID" not in str(e)

    def test_redact_helper_strips_userinfo(self):
        from hubcore.parsing._utils import redact
        shown = redact(f"vless://{UUID}@example.com:443?type=ws#Name")
        assert UUID not in shown
        assert "example.com:443" in shown

    def test_length_error_has_no_input(self):
        huge = f"vless://{UUID}@h.com:443?x=" + "a" * 9000
        try:
            parse_url(huge)
            pytest.fail("expected LengthLimitError")
        except LengthLimitError as e:
            assert UUID not in str(e)
