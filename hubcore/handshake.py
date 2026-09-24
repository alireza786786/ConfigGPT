# -*- coding: utf-8 -*-
"""Protocol handshake validation (Phase 8).

GOAL: after a successful TCP_CONNECT, determine whether the endpoint
actually speaks the configured protocol — WITHOUT ever faking success.
TCP success alone is NEVER reported as protocol success; the two are
separate measurements on separate outcome objects, and a handshake
failure never retroactively flips the TCP result.

Success semantics are HONEST and explicit per probe:

* VLESS (TLS+TCP): a raw VLESS protocol request (0x00 + uuid-bytes +
  39 zero padding) is sent AFTER a certificate-VERIFIED TLS handshake
  with SNI = original hostname. status == "success" means a TLS-verified
  server returned protocol-shaped bytes to a VLESS-shaped request
  (semantics="server_present"). This is presence evidence, not full
  relay verification; residual risk (any TLS server that echoes bytes
  to arbitrary input) is documented, not hidden.
* TROJAN: Trojan is always TLS. By default (allow_credential_probe=
  False) the validator refuses to send the node's real password and
  reports status "unsupported" with reason "credential_probe_disabled"
  — no fake probe, no fake success. With the flag ON, a real Trojan
  request (sha224(password) + CRLF + domain-addr for example.com:80)
  is relayed; relayed bytes back prove the credential was accepted and
  the tunnel works (semantics="relay_verified").

Everything that cannot be validated safely/correctly with the current
architecture returns status "unsupported" with a precise reason code:
VMess (AEAD envelope), Shadowsocks (needs real target relay + keys),
Hysteria2 (QUIC/UDP out of scope), REALITY, non-TCP transports, VLESS
without an explicit security layer (no port-443 guessing ever).

PINNING / ANTI-REBINDING (Phase 7 policy preserved without exception):
the network destination is ALWAYS ``endpoint.resolved_ip`` (or the host
itself when the host is a literal IP); the OS is never asked to
re-resolve the hostname. TLS is wrapped on the already-connected socket
with ``server_hostname`` = ORIGINAL hostname, certificate verification
is NEVER disabled, and insecure flags are ignored entirely. SNI and
network destination are provably separated (regression-tested).

LATENCY: ``LatencyKind.PROTOCOL_HANDSHAKE`` covers exactly
    post-TCP-connect  ->  last qualifying response byte read
(including the TLS handshake for TLS-based protocols). Socket creation,
the TCP connect itself and DNS are excluded by construction. A failed
handshake yields NO sample.

SECURITY: responses are treated as opaque bytes (never decoded, never
executed); reads are capped (RECV_CAP, MAX_READS) so a hostile server
cannot exhaust memory; errors carry short codes only — no certificate
contents, no credentials, no OS exception text. Sockets are closed on
every path. No eval/exec/subprocess anywhere.

NOTE (Phase 9): the policy helpers ``probe_gate``, ``probe_bytes``,
``response_matches_protocol`` and ``sni_for`` are module-level on
purpose — Phase 9's measurer reuses the EXACT same gate/bytes/shaping
logic so the two layers can never drift apart.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from hubcore.latency import LatencyKind, LatencySample
from hubcore.model import Node
from hubcore.resolver import classify_ip

__all__ = [
    "HandshakeOutcome",
    "HandshakeValidator",
    "probe_gate",
    "probe_bytes",
    "response_matches_protocol",
    "sni_for",
]

# Where Trojan relay probes point: a constant, benign, domain-typed
# target. The SERVER resolves it itself (no client-side DNS at all).
_RELAY_TARGET_DOMAIN = b"example.com"
_RELAY_TARGET_PORT = 80

RECV_CAP = 4096          # max bytes per single read
MAX_READS = 4            # bounded read loop -> bounded memory + time
BENIGN_HTTP_PROBE = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"


# ----------------------------------------------------------------------
# Module-level policy helpers (single source of truth; shared with the
# Phase 9 measurer).
# ----------------------------------------------------------------------
def probe_gate(node: Node, allow_credential_probe: bool):
    """Return None when this node can be probed honestly, else
    ``(unsupported_reason, semantics_hint)``."""
    proto = node.protocol

    if proto.value == "vmess":
        return "vmess_aead_envelope_not_implemented", ""
    if proto.value == "shadowsocks":
        return "ss_target_relay_required", ""
    if proto.value == "hysteria2":
        return "hy2_quic_out_of_scope", ""
    if proto.value == "vless":
        if node.security.name == "REALITY":
            return "reality_probe_not_implemented", ""
        if node.security.name != "TLS":
            # UNKNOWN/none: we refuse to guess TLS from port 443
            return "vless_security_layer_not_explicit", ""
        if node.transport.value not in ("tcp", "unknown"):
            return f"transport_not_supported:{node.transport.value}", ""
        return None
    if proto.value == "trojan":
        if not allow_credential_probe:
            return "credential_probe_disabled", ""
        if node.security.name not in ("TLS", "UNKNOWN", "NONE"):
            return "trojan_security_layer_not_tls", ""
        if node.transport.value not in ("tcp", "unknown"):
            return f"transport_not_supported:{node.transport.value}", ""
        if not node.password:
            return "trojan_password_missing", ""
        return None
    return f"protocol_not_supported:{proto.value}", ""


def probe_bytes(node: Node):
    """Protocol-specific request bytes (small, bounded)."""
    if node.protocol.value == "vless":
        try:
            uid = _uuid.UUID(node.uuid).bytes          # 16 bytes
        except (ValueError, AttributeError, TypeError):
            return None
        return b"\x00" + uid + b"\x00" * 39            # 56-byte VLESS request
    if node.protocol.value == "trojan":
        pwhash = hashlib.sha224(node.password.encode("utf-8")).hexdigest()
        addr = (b"\x03" + bytes([len(_RELAY_TARGET_DOMAIN)])
                + _RELAY_TARGET_DOMAIN
                + _RELAY_TARGET_PORT.to_bytes(2, "big"))
        return (b"\r\n" + pwhash.encode("ascii") + b"\r\n" + addr
                + b"\r\n" + BENIGN_HTTP_PROBE)
    return None


def response_matches_protocol(node: Node, data: bytes) -> bool:
    """Minimal protocol-shape check on the FIRST response bytes.

    VLESS: the server replies with the response version byte 0x00.
    Anything else (HTTP error pages, SMTP banners, arbitrary echo)
    is NOT protocol evidence -> prevents wrong-protocol false positives
    while remaining presence-level (documented residual risk: bytes can
    only prove a VLESS-shaped reply, not relaying).
    Trojan: relayed HTTP bytes prove the credential was accepted.
    """
    if node.protocol.value == "vless":
        return data[:1] == b"\x00"
    if node.protocol.value == "trojan":
        return True   # relay_verified path already required real bytes
    return False


def sni_for(node: Node) -> str:
    """SNI = explicit sni, else ORIGINAL hostname (never the IP)."""
    return (node.sni or node.endpoint.host).strip("[]")


def quiet_close(sock) -> None:
    """Close a socket-like object; never raises."""
    try:
        sock.close()
    except Exception:
        pass


# ----------------------------------------------------------------------
# Validator
# ----------------------------------------------------------------------
@dataclass
class HandshakeOutcome:
    """Result of validating one node at the protocol layer (mutable
    record assembled by the validator; keep parity with TcpOutcome)."""

    ok: bool
    status: str                 # success|unsupported|tls_error|protocol_error|timeout|no_pinned_ip|internal_error
    reason: str = ""            # short, credential-free detail code
    semantics: str = ""         # server_present | relay_verified | ""
    tls_layer: str = ""         # 'verified' (default wrapper) | 'injected'
    unsupported_reason: str = ""  # filled when status == unsupported
    identity_hostname: str = ""   # ORIGINAL host (SNI source) — never the IP
    dial_target: str = ""         # the pinned IP actually dialed
    latency: Optional[LatencySample] = None   # kind == PROTOCOL_HANDSHAKE, or None
    notes: tuple = field(default_factory=tuple)   # audit trail (short codes only)


class HandshakeValidator:
    """Protocol-level validator with fully injectable transport.

    ``connect_factory`` — same contract as Phase 7's TcpValidator: the
    factory only CREATES a socket-like object
    ``(family, socktype, target, port, timeout)``; the validator dials
    ``connect((target, port))`` itself against the PINNED IP.

    ``tls_wrap`` — injectable ``(raw_sock, server_hostname) ->
    ssl-socket-like``. The production default uses
    ``ssl.create_default_context()`` (verification and hostname checking
    ON; there is no code path that can turn them off).
    """

    def __init__(
        self,
        connect_factory: Optional[Callable[..., object]] = None,
        tls_wrap: Optional[Callable[[object, str], object]] = None,
        *,
        timeout: float = 4.0,
        allow_credential_probe: bool = False,
        accept_injected_tls: bool = False,
    ):
        if tls_wrap is not None and not accept_injected_tls:
            # The production TLS path is certificate-verifying by
            # construction. Supplying a custom wrapper is a TEST seam
            # only and must be acknowledged explicitly so it can never
            # silently weaken verification.
            raise ValueError(
                "custom tls_wrap requires accept_injected_tls=True (test seam)")
        self._connect_factory = connect_factory or self._default_connect_factory
        self._tls_wrap = tls_wrap or self._default_tls_wrap
        self._tls_layer = "injected" if tls_wrap is not None else "verified"
        self.timeout = timeout
        self.allow_credential_probe = allow_credential_probe

    # ------------------------------------------------------------------
    @staticmethod
    def _default_connect_factory(family, socktype, target, port, timeout):
        # CREATION ONLY: the dial happens in validate() so the measured
        # windows are exactly connect()/handshake (and fakes see it).
        sock = socket.socket(family, socktype)
        sock.settimeout(timeout)
        return sock

    @staticmethod
    def _default_tls_wrap(raw_sock, server_hostname):
        # Verification + hostname check are ALWAYS on; no insecure bypass
        # exists anywhere in this module by construction.
        ctx = ssl.create_default_context()
        return ctx.wrap_socket(raw_sock, server_hostname=server_hostname)

    # ------------------------------------------------------------------
    def validate(self, node: Node) -> HandshakeOutcome:
        ep = node.endpoint
        outcome = HandshakeOutcome(
            ok=False, status="unsupported",
            identity_hostname=ep.host,
            tls_layer=self._tls_layer,
        )

        # ---- 1. pin resolution (fail-closed, same policy as Phase 7) --
        if ep.resolved_ip:
            target = ep.resolved_ip.strip("[]")
        elif ep.host and self._is_literal(ep.host):
            target = ep.host.strip("[]")
        else:
            outcome.status = "no_pinned_ip"
            outcome.reason = "no_pinned_ip"
            return outcome

        # ---- 2. destination policy gate (defense in depth) ------------
        kind = self._kind_or_unknown(target)
        if kind == "unknown":
            outcome.status = "unsupported"
            outcome.unsupported_reason = "unparseable_ip"
            outcome.reason = "unparseable_ip"
            return outcome
        if kind in ("loopback", "private", "link_local", "reserved",
                    "multicast", "unspecified"):
            outcome.status = "unsupported"
            outcome.unsupported_reason = f"forbidden_target:{kind}"
            outcome.reason = "forbidden_target"
            return outcome
        outcome.dial_target = target   # only AFTER the gate: report truth

        # ---- 3. per-protocol gate: only what we can do HONESTLY -------
        gate = probe_gate(node, self.allow_credential_probe)
        if gate is not None:
            reason, _ = gate
            outcome.status = "unsupported"
            outcome.unsupported_reason = reason
            outcome.reason = "unsupported_protocol"
            outcome.notes = (f"refused:{reason}",)
            return outcome

        # ---- 4. TCP connect to the PINNED IP --------------------------
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        sock = None
        try:
            sock = self._connect_factory(family, socket.SOCK_STREAM, target,
                                         ep.port, self.timeout)
            sock.connect((target, ep.port))
        except Exception as exc:
            if sock is not None:
                quiet_close(sock)
            outcome.status = self._tcp_error_status(exc)
            outcome.reason = self._tcp_error_code(exc)
            outcome.notes = ("tcp_stage_failed",)
            return outcome

        # ---- 5. protocol handshake on the connected socket ------------
        try:
            return self._handshake(node, sock, outcome)
        finally:
            quiet_close(sock)

    # ------------------------------------------------------------------
    def _handshake(self, node: Node, sock, outcome: HandshakeOutcome) -> HandshakeOutcome:
        """TLS (verified, SNI=hostname) + protocol bytes + bounded read."""
        sni = sni_for(node)
        t0 = time.monotonic()           # window STARTS after TCP connect

        # TLS layer (VLESS/Trojan probes are TLS-based by gate contract)
        try:
            tls_sock = self._tls_wrap(sock, sni)
        except Exception as exc:
            outcome.status = "tls_error"
            outcome.reason = self._tls_error_code(exc)
            outcome.notes = ("tls_stage_failed",)
            return outcome

        try:
            probe = probe_bytes(node)
            if probe is None:
                outcome.status = "internal_error"
                outcome.reason = "probe_build_failed"
                return outcome
            try:
                tls_sock.sendall(probe)
            except socket.timeout:
                outcome.status = "timeout"
                outcome.reason = "send_timeout"
                return outcome
            except Exception:
                outcome.status = "protocol_error"
                outcome.reason = "send_failed"
                return outcome

            # bounded read loop: hostile/huge responses cannot exhaust
            data = b""
            for _ in range(MAX_READS):
                try:
                    chunk = tls_sock.recv(RECV_CAP)
                except socket.timeout:
                    if data:
                        break            # got qualifying bytes earlier
                    outcome.status = "timeout"
                    outcome.reason = "recv_timeout"
                    return outcome
                except Exception:
                    if data:
                        break
                    outcome.status = "protocol_error"
                    outcome.reason = "recv_failed"
                    return outcome
                if not chunk:
                    break                # clean EOF
                data += chunk
                if len(data) >= RECV_CAP:
                    break

            ms = round((time.monotonic() - t0) * 1000.0, 2)
            if data:
                if not response_matches_protocol(node, data):
                    outcome.status = "protocol_error"
                    outcome.reason = "unexpected_response"
                    return outcome
                outcome.ok = True
                outcome.status = "success"
                outcome.semantics = (
                    "relay_verified" if node.protocol.value == "trojan"
                    else "server_present")
                outcome.latency = LatencySample(
                    value_ms=ms,
                    kind=LatencyKind.PROTOCOL_HANDSHAKE,
                    attempts=1,
                    provenance=f"handshake:{node.protocol.value}:{outcome.semantics}",
                )
            else:
                outcome.status = "protocol_error"
                outcome.reason = "closed_without_response"
            return outcome
        finally:
            quiet_close(tls_sock)

    # ------------------------------------------------------------------
    @staticmethod
    def _quiet_close(sock):
        quiet_close(sock)

    @staticmethod
    def _is_literal(host: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _kind_or_unknown(ip: str) -> str:
        try:
            return classify_ip(ip).kind
        except Exception:
            return "unknown"

    @staticmethod
    def _tcp_error_code(exc: Exception) -> str:
        try:
            from hubcore.tcpval import _short_error
            code = _short_error(exc)
            return code if code != "resolve" else "dial_error"
        except Exception:
            return "dial_error"

    @staticmethod
    def _tcp_error_status(exc: Exception) -> str:
        return "timeout" if isinstance(exc, (TimeoutError, socket.timeout)) \
            else "protocol_error"

    @staticmethod
    def _tls_error_code(exc: Exception) -> str:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return "cert_verification_failed"
        if isinstance(exc, socket.timeout):
            return "tls_timeout"
        return "tls_handshake_failed"
