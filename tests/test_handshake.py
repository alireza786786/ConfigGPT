# -*- coding: utf-8 -*-
"""Phase 8 tests: protocol handshake validation (fully offline).

Injected fake transports prove, deterministically:
* the dial ALWAYS goes to the pinned IP (hostname never dialed),
* SNI is the ORIGINAL hostname (never the IP),
* TCP success alone NEVER becomes protocol success (no fake success),
* TLS verification cannot be bypassed and tls_error != protocol_error,
* responses are capped; credentials/OS text never leak.
"""
import socket
import ssl
from dataclasses import replace

import pytest

from hubcore import (
    HandshakeValidator,
    LatencyKind,
    Protocol,
    parse_url,
)

UUID = "11111111-2222-3333-4444-555555555555"


def vless_tls_node(host="example.com", ip="93.184.216.34", port=443,
                   uuid=UUID, **kw):
    n = parse_url(f"vless://{uuid}@{host}:{port}?security=tls&type=tcp")
    ep = replace(n.endpoint, resolved_ip=ip)
    return replace(n, endpoint=ep, **kw)


def trojan_node(host="example.com", ip="93.184.216.34", port=443):
    n = parse_url(f"trojan://pass@{host}:{port}?security=tls&type=tcp")
    ep = replace(n.endpoint, resolved_ip=ip)
    return replace(n, endpoint=ep)


class FakeTLSSock:
    """Stands in for the wrapped TLS socket; scripted recv/send."""

    def __init__(self, script):
        self.script = script          # callable() -> bytes | Exception
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent = data

    def recv(self, cap):
        item = self.script()
        if isinstance(item, Exception):
            raise item
        return item() if callable(item) else item

    def close(self):
        self.closed = True


class Harness:
    """Collects every observable the tests assert on."""

    def __init__(self, response_script=lambda: b"\x00\x2a\x00\x00",
                 tls_script=None, tcp_error=None, tls_error=None):
        self.dials = []
        self.sni_values = []
        self.wraps = 0
        self.closes = []
        self.response_script = response_script
        self.tls_script = tls_script or response_script
        self.tcp_error = tcp_error
        self.tls_error = tls_error
        self.factory = self._factory
        self.tls_wrap = self._tls_wrap
        self.tls_socks = []          # every FakeTLSSock produced

    def _factory(self, family, socktype, target, port, timeout):
        self.dials.append((target, port, family))

        class RawSock:
            def connect(self, addr):
                if self._owner.tcp_error is not None:
                    raise self._owner.tcp_error
            def close(self):
                self._owner.closes.append("tcp")
        RawSock._owner = self
        return RawSock()

    def _tls_wrap(self, raw_sock, server_hostname):
        self.wraps += 1
        self.sni_values.append(server_hostname)
        if self.tls_error is not None:
            raise self.tls_error
        fake = FakeTLSSock(self.tls_script)
        self.tls_socks.append(fake)
        return fake




class TestVlessTLSSuccess:
    def test_success_records_protocol_handshake_sample(self):
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert out.ok and out.status == "success"
        assert out.semantics == "server_present"
        assert out.latency is not None
        assert out.latency.kind is LatencyKind.PROTOCOL_HANDSHAKE
        assert out.latency.value_ms is not None and out.latency.value_ms >= 0

    def test_probe_bytes_are_vless_shaped(self):
        import uuid as _uuid
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        v.validate(vless_tls_node())
        sent = h.tls_socks[0].sent
        # 56-byte VLESS request: version 0x00 + 16-byte uuid + 39 zero pad
        assert len(sent) == 56
        assert sent[0] == 0x00
        assert sent[1:17] == _uuid.UUID(UUID).bytes
        assert sent[17:] == b"\x00" * 39

    def test_pinning_and_sni_split(self):
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node(host="real-name.example",
                                        ip="93.184.216.34"))
        assert h.dials == [("93.184.216.34", 443, socket.AF_INET)]
        assert h.sni_values == ["real-name.example"]
        assert out.identity_hostname == "real-name.example"
        assert out.dial_target == "93.184.216.34"


class TestNoFakeSuccess:
    def test_tcp_success_with_silent_server_is_protocol_error(self):
        # server accepts TLS then closes without any bytes: NOT success
        h = Harness(response_script=lambda: b"")
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert out.reason == "closed_without_response"
        assert out.latency is None

    def test_tcp_alone_never_flips_protocol(self):
        # TCP connect OK, TLS handshake fails -> protocol layer FAILED,
        # and there is no code path reporting success
        h = Harness(tls_error=ssl.SSLError("bad handshake"))
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "tls_error"
        assert out.reason == "tls_handshake_failed"
        assert out.latency is None

    def test_tcp_stage_failure_reports_timeout_not_protocol(self):
        h = Harness(tcp_error=socket.timeout())
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "timeout"
        assert out.notes == ("tcp_stage_failed",)

    def test_cert_verification_failure_is_tls_error(self):
        h = Harness(tls_error=ssl.SSLCertVerificationError(
            "certificate verify failed: detail"))
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "tls_error"
        assert out.reason == "cert_verification_failed"
        # the verification failure text must not leak into the report
        assert "verify" not in repr(out) and "detail" not in repr(out)


class TestUnsupportedNotFaked:
    def test_vmess_unsupported(self):
        n = parse_url("vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicHJvdG9jb2wiOiJ2bWVzcyIsInNjaWQiOiIwMCJ9")
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "vmess_aead_envelope_not_implemented"

    def test_ss_unsupported(self):
        n = parse_url("ss://YWVzLTI1Ni1nY206cGFzcw@93.184.216.34:443")
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "ss_target_relay_required"

    def test_hysteria2_never_validated_over_tcp(self):
        # hy2 is QUIC/UDP; a TCP validator must refuse it, not fake it
        n = parse_url(f"hysteria2://pass@93.184.216.34:443")
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "hy2_quic_out_of_scope"

    def test_vless_reality_unsupported(self):
        n = parse_url(f"vless://{UUID}@93.184.216.34:443?security=reality&pbk=X&s id=Y")
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"

    def test_vless_unknown_security_never_guessed_from_port(self):
        # no security param at all: must NOT assume TLS on 443
        n = parse_url(f"vless://{UUID}@93.184.216.34:443")
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "vless_security_layer_not_explicit"

    def test_trojan_credential_probe_disabled_by_default(self):
        v = HandshakeValidator(connect_factory=Harness().factory)
        out = v.validate(trojan_node())
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "credential_probe_disabled"

    def test_trojan_relay_verified_when_enabled(self):
        h = Harness(response_script=lambda: b"HTTP/1.1 200 OK\r\n\r\n")
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               allow_credential_probe=True,
                               accept_injected_tls=True)
        out = v.validate(trojan_node())
        assert out.ok and out.status == "success"
        assert out.semantics == "relay_verified"

    def test_trojan_probe_is_hash_not_raw_password(self):
        import hashlib
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               allow_credential_probe=True,
                               accept_injected_tls=True)
        v.validate(trojan_node())
        sent = h.tls_socks[0].sent
        # wire form: CRLF + sha224-hex + CRLF + addr + CRLF + payload
        expect_hash = hashlib.sha224(b"pass").hexdigest().encode()
        assert expect_hash in sent
        assert b"pass\r\n" not in sent           # raw password never on the wire
        assert b"example.com" in sent            # domain-typed relay target

    def test_trojan_without_password_never_probed(self):
        # Phase 2 rejects password-less trojan at parse time; the gate
        # remains as defense-in-depth for raw-constructed Nodes.
        from hubcore import Endpoint, Node as N, Security, Transport
        n = N(protocol=Protocol.TROJAN,
              endpoint=Endpoint(host="93.184.216.34", port=443,
                                resolved_ip="93.184.216.34"),
              security=Security.TLS, transport=Transport.TCP, password="")
        v = HandshakeValidator(connect_factory=Harness().factory,
                               tls_wrap=Harness().tls_wrap,
                               allow_credential_probe=True,
                               accept_injected_tls=True)
        out = v.validate(n)
        assert not out.ok and out.status == "unsupported"
        assert out.unsupported_reason == "trojan_password_missing"


class TestPinningHardGuarantees:
    def test_no_pinned_ip_fails_closed(self):
        n = parse_url(f"vless://{UUID}@example.com:443?security=tls")
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(n)
        assert out.status == "no_pinned_ip" and h.dials == []

    def test_private_resolved_ip_never_dialed(self):
        n = vless_tls_node(ip="10.1.2.3")
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(n)
        assert h.dials == []                     # nothing dialed
        assert out.unsupported_reason.startswith("forbidden_target:")

    def test_v4mapped_private_blocked(self):
        n = vless_tls_node(ip="::ffff:10.0.0.5")
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(n)
        assert h.dials == [] and out.status == "unsupported"

    def test_unparseable_ip_never_dialed(self):
        n = vless_tls_node(ip="0177.0.0.1")
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(n)
        assert h.dials == []
        assert out.unsupported_reason == "unparseable_ip"

    def test_forbidden_target_never_reports_dial_target(self):
        """REGRESSION: dial_target is only set after the policy gate, so a
        blocked endpoint never claims it was dialed."""
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node(ip="10.1.2.3"))
        assert out.dial_target == "" and h.dials == []

    def test_custom_tls_wrap_rejected_without_explicit_optin(self):
        """REGRESSION: a custom wrapper silently weakened verification;
        now it requires accept_injected_tls=True (test seam only)."""
        with pytest.raises(ValueError):
            HandshakeValidator(tls_wrap=lambda raw, sni: raw)

    def test_default_wrapper_reports_verified_layer(self):
        v = HandshakeValidator()
        h = Harness()
        # verify via validator built with NO injection: gate outcome must
        # still carry tls_layer=verified
        out = HandshakeValidator().validate(
            vless_tls_node(ip="10.0.0.9"))
        assert out.tls_layer == "verified"


class TestResourcesAndLeak:
    def test_raw_socket_closed_after_tls_success(self):
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        v.validate(vless_tls_node())
        assert "tcp" in h.closes

    def test_raw_socket_closed_after_tls_failure(self):
        h = Harness(tls_error=ssl.SSLError("nope"))
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        v.validate(vless_tls_node())
        assert "tcp" in h.closes

    def test_timeout_mid_read_reports_timeout(self):
        h = Harness(response_script=lambda: socket.timeout())
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "timeout"

    def test_oversized_response_capped(self):
        # 100KB starting with the valid VLESS 0x00 byte: bounded read loop
        # caps memory (RECV_CAP*MAX_READS) and success still reports
        big = b"\x00" + b"x" * 100000
        h = Harness(response_script=lambda: big)
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert out.ok and out.status == "success"

    def test_wrong_protocol_response_rejected(self):
        """REGRESSION: an SMTP banner (or any non-VLESS reply) must NOT
        count as protocol evidence -> unexpected_response, not success."""
        h = Harness(response_script=lambda: b"220 mail.example.com ESMTP ready")
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert out.reason == "unexpected_response"
        assert out.latency is None

    def test_recv_exception_contained(self):
        h = Harness(response_script=lambda: OSError(104, "reset by peer detail"))
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               accept_injected_tls=True)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert "reset by peer" not in repr(out)

    def test_factory_raising_contained(self):
        def evil(family, socktype, target, port, timeout):
            raise RuntimeError("factory on fire")
        v = HandshakeValidator(connect_factory=evil)
        out = v.validate(vless_tls_node())
        assert not out.ok and out.status == "protocol_error"
        assert "fire" not in repr(out)

    def test_no_credentials_in_report(self):
        h = Harness()
        v = HandshakeValidator(connect_factory=h.factory, tls_wrap=h.tls_wrap,
                               allow_credential_probe=True,
                               accept_injected_tls=True)
        out = v.validate(trojan_node())
        blob = repr(out) + repr(out.notes) + (out.reason or "")
        assert "pass" not in blob            # trojan password never appears


class TestDeterminism:
    def test_same_inputs_same_outputs(self):
        h1, h2 = Harness(), Harness()
        o1 = HandshakeValidator(connect_factory=h1.factory,
                                tls_wrap=h1.tls_wrap,
                                accept_injected_tls=True).validate(vless_tls_node())
        o2 = HandshakeValidator(connect_factory=h2.factory,
                                tls_wrap=h2.tls_wrap,
                                accept_injected_tls=True).validate(vless_tls_node())
        strip = lambda o: (o.ok, o.status, o.reason, o.semantics, o.dial_target)
        assert strip(o1) == strip(o2)
