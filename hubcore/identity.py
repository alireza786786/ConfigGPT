# -*- coding: utf-8 -*-
"""Identity layer for the canonical model (Phase 1).

Two distinct concepts, never to be conflated:

- **endpoint identity** — "which network endpoint does this node use?"
  Used only for endpoint-level analytics (e.g. counting configs behind a
  single host:port). It is deliberately coarse.
- **configuration identity** — "is this the same proxy configuration?"
  Used for deduplication of configs. It includes protocol, credentials,
  TLS/transport material, and ALL ``protocol_fields``. Two nodes that
  share a host:port but differ in uuid/path/SNI/protocol fields are
  DIFFERENT configurations and must remain distinct.

Rule (per approved constraint 2): deduplication must never delete a
configuration solely because host:port or resolved ip:port is identical.
"""
from __future__ import annotations

from .model import Node

__all__ = ["endpoint_key", "config_key", "same_endpoint", "same_config"]


def endpoint_key(node: Node):
    """Coarse endpoint identity: (identity_host, port)."""
    return (node.endpoint.identity_host, node.endpoint.port)


def config_key(node: Node):
    """Full configuration identity (protocol-aware, extensible).

    Includes every field that materially changes a configuration:
    protocol, credentials (uuid/password/secret), TLS/transport material
    (sni, host header, transport, security, path, serviceName, alpn,
    fingerprint, allow_insecure, flow), and the extensible
    ``protocol_fields`` (Reality pubkey/shortId, SS method/plugin,
    Hysteria2 obfs, VMess encryption, XHTTP mode, ...). Deliberately
    excludes measurement/classification (latency/score/geo) and cosmetic
    naming, so measurement updates never change identity.
    """
    ep = node.endpoint
    return (
        node.protocol,
        ep.identity_host,
        ep.port,
        node.uuid,
        node.password,
        node.secret,
        node.sni,
        node.host_header,
        node.transport,
        node.security,
        node.path,
        node.service_name,
        node.alpn,
        node.fingerprint,
        node.allow_insecure,
        node.flow,
        tuple(node.protocol_fields),
        # raw_url is excluded on purpose: renaming the fragment would
        # otherwise change identity.
    )


def same_endpoint(a: Node, b: Node) -> bool:
    """True when both nodes terminate on the same host/ip:port."""
    return endpoint_key(a) == endpoint_key(b)


def same_config(a: Node, b: Node) -> bool:
    """True when both nodes are the same configuration."""
    return config_key(a) == config_key(b)
