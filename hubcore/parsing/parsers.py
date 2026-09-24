# -*- coding: utf-8 -*-
"""Per-protocol config parsers (Phase 2).

Contracts:
- pure/offline; no I/O; no dynamic code execution (no eval/exec/subprocess).
- any failure raises :class:`ParseError` subclasses (never leaks raw input
  or credentials); :func:`safe_parse_url` converts failures to None.
- unknown-but-meaningful query parameters are preserved into
  ``Node.protocol_fields`` under ``qp.<name>`` so identity never loses them.
- KCP maps to Transport.UNKNOWN (per Phase 1 constraint) while its
  presence is recorded in protocol_fields.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from hubcore.enums import Protocol, Security, Transport
from hubcore.latency import LatencyKind, LatencySample
from hubcore.model import Endpoint, Node

from ._utils import (
    MAX_SECRET_LEN,
    MAX_URL_LEN,
    b64_decode_flexible,
    parse_query,
    percent_decode,
    redact,
    safe_int,
    safe_str,
)
from .errors import (
    LengthLimitError,
    MalformedURLError,
    ParseError,
    UnsupportedSchemeError,
)

__all__ = ["parse_url", "safe_parse_url", "parse_lines", "SUPPORTED_SCHEMES"]

SUPPORTED_SCHEMES = {
    "vless": Protocol.VLESS,
    "vmess": Protocol.VMESS,
    "ss": Protocol.SHADOWSOCKS,
    "trojan": Protocol.TROJAN,
    "hysteria2": Protocol.HYSTERIA2,
    "hy2": Protocol.HYSTERIA2,
    "socks": Protocol.SOCKS5,
    "socks5": Protocol.SOCKS5,
}

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://", re.DOTALL)


def _endpoint_from_netloc(netloc: str, default_port: Optional[int]) -> Endpoint:
    """Build an Endpoint from a URL netloc, IPv6-aware, strict on ports."""
    netloc = (netloc or "").strip()
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if not netloc:
        raise MalformedURLError(detail="missing host")
    if netloc.startswith("["):
        # [v6addr] or [v6addr]:port  (bracketed IPv6 only)
        end = netloc.find("]")
        if end == -1:
            raise MalformedURLError(detail="unterminated IPv6 brackets")
        host = netloc[: end + 1]
        rest = netloc[end + 1 :]
        if rest and not rest.startswith(":"):
            raise MalformedURLError(detail="junk after IPv6 brackets")
        port_part = rest[1:] if rest else ""
    else:
        if ":" in netloc:
            # bare v6 with >=2 colons and no port is malformed here; a
            # single colon is host:port.
            if netloc.count(":") > 1:
                raise MalformedURLError(detail="bare IPv6 must be bracketed")
            host, port_part = netloc.rsplit(":", 1)
        else:
            host, port_part = netloc, ""
    host = host.strip().strip("[]")
    if not host:
        raise MalformedURLError(detail="missing host")
    if len(host) > 253:
        raise MalformedURLError(detail="host too long")
    port = safe_int(port_part, None) if port_part else default_port
    if port_part and safe_int(port_part, None) is None:
        raise MalformedURLError(detail="invalid port")
    if port is None:
        port = default_port
    if port is None:
        raise MalformedURLError(detail="missing port")
    return Endpoint(host=host, port=port)


def _validate_vmess_add(add: str) -> str:
    """Validate the VMess ``add`` (host) field; return bracket-stripped host.

    Rejects smuggling like 'h:443', 'h/x', 'a@b' — the separate ``port``
    JSON field is the only port source. Bracketed IPv6 is allowed.
    """
    a = add.strip()
    if not a:
        raise MalformedURLError("vmess", "missing add")
    if a.startswith("["):
        if not a.endswith("]") or any(c in a for c in "@/"):
            raise MalformedURLError("vmess", "malformed IPv6 add")
        return a[1:-1]
    if any(c in a for c in ":@/"):
        raise MalformedURLError("vmess", "malformed add")
    return a


def _split_userinfo_hostport(url: str, default_port):
    """Tolerant userinfo/hostport extraction for @-auth schemes.

    Real-world feeds contain links whose userinfo itself includes '/'
    (e.g. ``hy2://some/path@host:port/``) which strict RFC parsing cannot
    represent (urlparse would swallow the true host into the path). We
    recover by splitting the pre-query body at the LAST literal '@' and
    stripping a single trailing '/'. Returns (user, password, Endpoint);
    user/password are still percent-encoded (callers decode).
    """
    marker = url.find("://")
    body = url[marker + 3:] if marker != -1 else url
    main = re.split(r"[#?]", body, maxsplit=1)[0]
    if "@" in main:
        userinfo, _, hostport = main.rpartition("@")
    else:
        userinfo, hostport = "", main
    hostport = hostport.rstrip("/")
    user, pwd = userinfo, ""
    if ":" in userinfo:
        user, _, pwd = userinfo.rpartition(":")
    ep = _endpoint_from_netloc(hostport, default_port)
    return user, pwd, ep


def _qp_into_protocol_fields(q: dict, pf: dict, drop=()):
    """Preserve unknown query parameters into protocol_fields (qp.*).

    Conflicting-duplicate markers (``key[]``) are preserved too: they are
    identity-relevant (ambiguous input), not noise.
    """
    drop = set(drop or ())
    for k, v in sorted(q.items()):
        if k in drop:
            continue
        pf[f"qp.{k}"] = v


def _fragment_name(p) -> str:
    """Percent-decoded fragment as the display name (NOT identity)."""
    frag = getattr(p, "fragment", "") or ""
    if not frag:
        return ""
    return safe_str(percent_decode(frag), 512)


def _base_node(scheme: str, url: str, ep: Endpoint) -> Node:
    return Node(
        protocol=SUPPORTED_SCHEMES[scheme.lower()],
        endpoint=ep,
        raw_url=url,
    )


def _finish(node: Node, q: dict, url: str) -> Node:
    """Apply shared query-derived fields (sni/alpn/fp/flow/insecure)."""
    sni = safe_str(q.get("sni", ""), MAX_SECRET_LEN)
    fp = safe_str(q.get("fp", "") or q.get("fingerprint", ""), MAX_SECRET_LEN)
    alpn = safe_str(q.get("alpn", ""), MAX_SECRET_LEN)
    flow = safe_str(q.get("flow", ""), MAX_SECRET_LEN)
    insecure = q.get("allowinsecure", q.get("insecure", "0")).lower() in ("1", "true", "yes")
    updates = {}
    if sni:
        updates["sni"] = sni
    if alpn:
        updates["alpn"] = alpn
    if fp:
        updates["fingerprint"] = fp
    if flow:
        updates["flow"] = flow
    if insecure:
        updates["allow_insecure"] = True
    if updates:
        from dataclasses import replace as _replace

        node = _replace(node, **updates)
    return node


def _transport_and_security(node: Node, q: dict) -> Node:
    """Derive Transport/Security from query; record KCP + raw type."""
    raw_type = (q.get("type", "") or q.get("net", "")).strip().lower()
    raw_sec = (q.get("security", "") or ("reality" if q.get("pbk") else "")).strip().lower()
    updates = {}
    t = Transport.from_string(raw_type)
    if raw_type == "kcp":
        # Phase 1 constraint: KCP must NOT become QUIC.
        t = Transport.UNKNOWN
    updates["transport"] = t
    if raw_sec in ("tls", "reality", "none"):
        updates["security"] = Security.from_string(raw_sec)
    elif q.get("pbk") or q.get("sid"):
        updates["security"] = Security.REALITY
    from dataclasses import replace as _replace

    node = _replace(node, **updates)
    pf = dict(node.protocol_fields)
    if raw_type and node.transport is Transport.UNKNOWN:
        pf["transport.raw"] = raw_type  # preserve KCP etc.
    return _replace(node, protocol_fields=list(pf.items()))


# --------------------------------------------------------------------------
# per-protocol parsers
# --------------------------------------------------------------------------

def _parse_vless(url: str) -> Node:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme != "vless":
        raise UnsupportedSchemeError(scheme)
    user, pwd, ep = _split_userinfo_hostport(url, default_port=443)
    if pwd:
        # VLESS has no password component; 'uuid:secret@' is nonstandard
        # and would silently lose data if tolerated.
        raise MalformedURLError("vless", "unexpected password component")
    uuid = percent_decode(user)
    if not uuid:
        raise MalformedURLError("vless", "missing uuid")
    if any(c in uuid for c in ":@/"):
        raise MalformedURLError("vless", "malformed uuid")
    if len(uuid) > MAX_SECRET_LEN:
        raise LengthLimitError("vless uuid", MAX_SECRET_LEN)
    node = _base_node(scheme, url, ep)
    node = _replace_fields(node, uuid=uuid)
    q = parse_query(p.query)
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    pf = dict(node.protocol_fields)
    if q.get("pbk"):
        pf["vless.reality.pubkey"] = safe_str(q["pbk"])
    if q.get("sid"):
        pf["vless.reality.shortid"] = safe_str(q["sid"])
    if q.get("spx"):
        pf["vless.reality.spx"] = safe_str(q["spx"])
    _qp_into_protocol_fields(q, pf, drop={"type", "security", "sni", "alpn", "fp",
                                          "fingerprint", "flow", "pbk", "sid", "spx",
                                          "allowinsecure", "insecure", "path", "host",
                                          "servicename"})
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    if q.get("type", "").lower() == "grpc" or q.get("servicename"):
        node = _replace_fields(node, service_name=safe_str(q.get("servicename", "")))
    if q.get("path"):
        node = _replace_fields(node, path=safe_str(q["path"]))
    if q.get("host"):
        node = _replace_fields(node, host_header=safe_str(q["host"]))
    return node


def _parse_vmess(url: str) -> Node:
    p = urlparse(url)
    body = url[len("vmess://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    body = body.strip()
    if not body:
        raise MalformedURLError("vmess", "empty payload")
    raw = b64_decode_flexible(body)
    if raw is None:
        raise MalformedURLError("vmess", "invalid base64 payload")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            raise MalformedURLError("vmess", "undecodable payload")
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise MalformedURLError("vmess", "payload is not valid JSON")
    if not isinstance(data, dict):
        raise MalformedURLError("vmess", "payload JSON is not an object")
    add = safe_str(data.get("add", ""))
    host = _validate_vmess_add(add)
    port = safe_int(data.get("port"), None)
    if port is None:
        raise MalformedURLError("vmess", "missing/invalid port")
    ep = Endpoint(host=host, port=port)
    uuid = safe_str(data.get("id", ""))
    if not uuid:
        raise MalformedURLError("vmess", "missing id")
    q = {
        "security": safe_str(data.get("tls", "")).lower(),
        "type": safe_str(data.get("net", "")).lower(),
        "path": safe_str(data.get("path", "")),
        "host": safe_str(data.get("host", "")),
        "sni": safe_str(data.get("sni", "")),
        "alpn": safe_str(data.get("alpn", "")),
        "fp": safe_str(data.get("fp", "")),
    }
    node = _base_node("vmess", url, ep)
    node = _replace_fields(node, uuid=uuid)
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    pf = dict(node.protocol_fields)
    pf["vmess.encryption"] = safe_str(data.get("scy", "") or "auto")
    ps = safe_str(data.get("ps", ""), 512)
    if ps:
        node = _replace_fields(node, output_name=ps)
    if q.get("path"):
        pf["vmess.path"] = q["path"]
    if q.get("host"):
        pf["vmess.host"] = q["host"]
    # preserve unknown vmess JSON keys (identity-relevant; unknown = kept)
    known = {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type",
             "host", "path", "tls", "sni", "alpn", "fp"}
    for k in sorted(data.keys()):
        if k not in known:
            pf[f"vmess.{str(k).strip().lower()}"] = safe_str(data[k], 512)
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    if q.get("path"):
        node = _replace_fields(node, path=q["path"])
    if q.get("host"):
        node = _replace_fields(node, host_header=q["host"])
    if q.get("type", "").lower() == "grpc":
        node = _replace_fields(node, service_name=safe_str(data.get("path", "")))
    return node


def _parse_ss(url: str) -> Node:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme != "ss":
        raise UnsupportedSchemeError(scheme)

    def _split_cred(blob: str):
        """'method:password' -> (method, password); raises on bad shape."""
        if ":" not in blob:
            raise MalformedURLError("ss", "payload lacks method:password")
        method, _, password = blob.partition(":")
        return method.strip().lower(), password

    # Case 1: fully-legacy form ss://BASE64(method:password@host:port)
    # (no '@' in netloc; the whole netloc is the base64 blob).
    if not p.username and p.netloc and "@" not in p.netloc:
        raw = b64_decode_flexible(percent_decode(p.netloc))
        if raw is None:
            raise MalformedURLError("ss", "legacy payload is not base64")
        blob = raw.decode("utf-8", errors="replace")
        cred, _, hostport = blob.rpartition("@")
        if not cred:
            raise MalformedURLError("ss", "legacy payload lacks credentials")
        method, password = _split_cred(cred)
        if not password:
            raise MalformedURLError("ss", "missing password")
        if len(password) > MAX_SECRET_LEN:
            raise LengthLimitError("ss password", MAX_SECRET_LEN)
        ep = _endpoint_from_netloc(hostport, default_port=443)
        node = _base_node(scheme, url, ep)
        pf = {"ss.method": method or "unknown", "ss.password": password}
        q = parse_query(p.query)
        if q.get("plugin"):
            pf["ss.plugin"] = safe_str(q["plugin"])
        if p.fragment:
            pf["fragment"] = percent_decode(p.fragment)
        node = _replace_fields(node, protocol_fields=list(pf.items()))
        node = _transport_and_security(node, q)
        node = _finish(node, q, url)
        if q.get("path"):
            node = _replace_fields(node, path=safe_str(q["path"]))
        return node

    userinfo = p.username or ""
    if p.username and p.password:
        userinfo = f"{p.username}:{p.password}"
    method, password = "", ""
    if userinfo and ":" in userinfo:
        # SIP002 plain (possibly percent-encoded) method:password
        method, password = _split_cred(percent_decode(userinfo))
    elif userinfo and "%3a" in userinfo.lower():
        # encoded colon: decode FIRST, then split
        method, password = _split_cred(percent_decode(userinfo))
    elif userinfo:
        # SIP002 web64: base64(method:password) without padding
        raw = b64_decode_flexible(percent_decode(userinfo))
        if raw is not None:
            method, password = _split_cred(raw.decode("utf-8", errors="replace"))
        else:
            password = percent_decode(userinfo)  # permissive: password-only
    else:
        raise MalformedURLError("ss", "missing credentials")
    if not password:
        raise MalformedURLError("ss", "missing password")
    if len(password) > MAX_SECRET_LEN:
        raise LengthLimitError("ss password", MAX_SECRET_LEN)
    ep = _endpoint_from_netloc(p.netloc, default_port=443)
    node = _base_node(scheme, url, ep)
    pf = {
        "ss.method": method or "unknown",
        "ss.password": password,
    }
    q = parse_query(p.query)
    plugin = q.get("plugin", "")
    if plugin:
        pf["ss.plugin"] = safe_str(plugin)
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    if q.get("type", "").lower() == "grpc" or q.get("servicename"):
        node = _replace_fields(node, service_name=safe_str(q.get("servicename", "")))
    if q.get("path"):
        node = _replace_fields(node, path=safe_str(q["path"]))
    return node


def _parse_trojan(url: str) -> Node:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme != "trojan":
        raise UnsupportedSchemeError(scheme)
    user, pwd, ep = _split_userinfo_hostport(url, default_port=443)
    password = percent_decode(user)
    if pwd:
        password = f"{password}:{percent_decode(pwd)}"
    if not password:
        raise MalformedURLError("trojan", "missing password")
    if len(password) > MAX_SECRET_LEN:
        raise LengthLimitError("trojan password", MAX_SECRET_LEN)
    node = _base_node(scheme, url, ep)
    node = _replace_fields(node, password=password)
    q = parse_query(p.query)
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    pf = dict(node.protocol_fields)
    _qp_into_protocol_fields(q, pf, drop={"type", "security", "sni", "alpn", "fp",
                                          "fingerprint", "flow", "allowinsecure",
                                          "insecure", "path", "host", "servicename"})
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    if q.get("type", "").lower() == "grpc" or q.get("servicename"):
        node = _replace_fields(node, service_name=safe_str(q.get("servicename", "")))
    if q.get("path"):
        node = _replace_fields(node, path=safe_str(q["path"]))
    if q.get("host"):
        node = _replace_fields(node, host_header=safe_str(q["host"]))
    return node


def _parse_hysteria2(url: str) -> Node:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme not in ("hysteria2", "hy2"):
        raise UnsupportedSchemeError(scheme)
    user, pwd, ep = _split_userinfo_hostport(url, default_port=443)
    auth = percent_decode(user)
    if pwd:
        auth = f"{auth}:{percent_decode(pwd)}" if auth else percent_decode(pwd)
    if not auth:
        raise MalformedURLError("hysteria2", "missing auth")
    if len(auth) > MAX_SECRET_LEN:
        raise LengthLimitError("hysteria2 auth", MAX_SECRET_LEN)
    node = _base_node("hysteria2", url, ep)
    node = _replace_fields(node, password=auth)
    q = parse_query(p.query)
    pf = dict(node.protocol_fields)
    if q.get("obfs"):
        pf["hy2.obfs"] = safe_str(q["obfs"])
        if q.get("obfs-password"):
            pf["hy2.obfs.password"] = safe_str(q["obfs-password"])
    if q.get("pinSHA256"):
        pf["hy2.pinSHA256"] = safe_str(q["pinSHA256"])
    _qp_into_protocol_fields(q, pf, drop={"type", "security", "sni", "alpn", "fp",
                                          "fingerprint", "flow", "allowinsecure",
                                          "insecure", "obfs", "obfs-password",
                                          "pinSHA256", "path", "host", "servicename"})
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    if q.get("path"):
        node = _replace_fields(node, path=safe_str(q["path"]))
    return node


def _parse_socks(url: str) -> Node:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme not in ("socks", "socks5", "socks5h"):
        raise UnsupportedSchemeError(scheme)
    raw_user, raw_pwd, ep = _split_userinfo_hostport(url, default_port=1080)
    user = percent_decode(raw_user)
    pwd = percent_decode(raw_pwd)
    node = _base_node("socks5", url, ep)
    updates = {}
    if user:
        updates["password"] = pwd  # socks has user/pass; reuse password slot
        updates["secret"] = user
    node = _replace_fields(node, **updates) if updates else node
    q = parse_query(p.query)
    node = _transport_and_security(node, q)
    node = _finish(node, q, url)
    pf = dict(node.protocol_fields)
    _qp_into_protocol_fields(q, pf, drop={"type", "security", "sni", "alpn", "fp",
                                          "fingerprint", "flow", "allowinsecure",
                                          "insecure", "path", "host", "servicename"})
    node = _replace_fields(node, protocol_fields=list(pf.items()))
    return node


_PARSERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "ss": _parse_ss,
    "trojan": _parse_trojan,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "socks": _parse_socks,
    "socks5": _parse_socks,
    "socks5h": _parse_socks,
}


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def parse_url(url: str) -> Node:
    """Parse one config URI into a canonical Node (raises ParseError)."""
    if not isinstance(url, str):
        raise MalformedURLError(detail="input is not a string")
    if not url.strip():
        raise MalformedURLError(detail="empty input")
    if len(url) > MAX_URL_LEN:
        raise LengthLimitError("config URL", MAX_URL_LEN)
    m = _SCHEME_RE.match(url.strip())
    if not m:
        raise MalformedURLError(detail="no scheme")
    scheme = m.group(1).lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise UnsupportedSchemeError(scheme)
    try:
        node = _PARSERS[scheme](url.strip())
    except ParseError:
        raise
    except Exception:
        # Endpoint/ValueError and any unexpected error: sanitized re-raise.
        raise MalformedURLError(scheme, "invalid parameters") from None
    # Display name: decoded fragment (never part of identity).
    name = _fragment_name(urlparse(url))
    if name and not node.output_name:
        node = _replace_fields(node, output_name=name)
    return node


def safe_parse_url(url: str) -> Optional[Node]:
    """Parse one config URI; returns None on any failure (never raises)."""
    try:
        return parse_url(url)
    except ParseError:
        return None
    except Exception:
        return None


def parse_lines(text: str, *, strict: bool = False):
    """Parse multi-line text; yields only successfully parsed Nodes.

    - blank lines and non-config lines are skipped silently
    - malformed config lines are skipped unless ``strict=True``
      (then the first ParseError propagates)
    - per-line failures never include the raw line in the error
    """
    if not isinstance(text, str):
        raise MalformedURLError(detail="input is not a string")
    if len(text) > 4 * MAX_URL_LEN * 1024:  # 32 MiB cap on a single blob
        raise LengthLimitError("input blob", 4 * MAX_URL_LEN * 1024)
    results = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "://" not in line:
            continue
        if strict:
            results.append(parse_url(line))
            continue
        node = safe_parse_url(line)
        if node is not None:
            results.append(node)
    return results


def _replace_fields(node: Node, **updates):
    from dataclasses import replace as _replace

    return _replace(node, **updates)
