# -*- coding: utf-8 -*-
"""Phase 4 tests: secure URL fetching + ingest_url integration.

All tests are OFFLINE: a fake transport (urlopen-like callable) is
injected; no real network access happens.
"""
import io
import time

import pytest

from hubcore import (
    FetchBlockedError,
    FetchError,
    FetchNetworkError,
    FetchSizeError,
    FetchTimeoutError,
    Fetcher,
    Protocol,
    SourceIngestor,
    SourceKind,
)


class FakeResponse:
    def __init__(self, *, status=200, body=b"", headers=None, delay=0.0):
        self.status = status
        self.headers = headers or {}
        self._body = body
        self._io = io.BytesIO(body)
        self._delay = delay
        self.closed = False

    def read(self, n=-1):
        if self._delay:
            time.sleep(self._delay)
        return self._io.read(n)

    def close(self):
        self.closed = True


class FakeTransport:
    """Scripted urlopen replacement: url -> response or exception."""

    def __init__(self, script=None, *, calls=None):
        self.script = script or {}
        self.calls = calls if calls is not None else []

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        item = self.script.get(url)
        if item is None:
            raise OSError(f"no route to {url}")
        if isinstance(item, Exception):
            raise item
        return item


VLESS_LINE = "vless://11111111-2222-3333-4444-555555555555@a.com:443?type=ws"
HTTPS_OK = "https://example.com/list.txt"


def ok_transport(body: bytes) -> FakeTransport:
    return FakeTransport({HTTPS_OK: FakeResponse(body=body)})


class TestPolicy:
    def test_https_only(self):
        f = Fetcher(transport=ok_transport(b"x"))
        for bad in ("http://example.com/a", "ftp://example.com/a",
                    "file:///etc/passwd", "gopher://x/1"):
            with pytest.raises(FetchBlockedError):
                f.fetch(bad)

    @pytest.mark.parametrize("bad", [
        "https://localhost/x", "https://sub.localhost/x",
        "https://127.0.0.1/x", "https://10.0.0.1/x",
        "https://192.168.1.1/x", "https://172.16.0.1/x",
        "https://172.31.255.255/x", "https://169.254.169.254/latest/meta-data",
        "https://100.64.0.1/x", "https://0.0.0.0/x",
        "https://224.0.0.1/x", "https://[::1]/x", "https://[fd00::1]/x",
        "https://", "https:// ", "not-a-url", "",
    ])
    def test_private_and_malformed_refused(self, bad):
        f = Fetcher(transport=FakeTransport())
        with pytest.raises(FetchBlockedError):
            f.fetch(bad)

    def test_public_ips_allowed(self):
        # public literal IPs pass the policy gate (no DNS in Phase 4)
        url = "https://93.184.216.34/a.txt"
        t = FakeTransport({url: FakeResponse(body=b"x")})
        r = Fetcher(transport=t).fetch(url)
        assert r.status == 200

    def test_empty_url(self):
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=FakeTransport()).fetch("   ")


class TestHappyPath:
    def test_fetch_and_ingest_roundtrip(self):
        body = (VLESS_LINE + "\n" + "trojan://pw@b.com:1\n").encode()
        t = ok_transport(body)
        r = Fetcher(transport=t).fetch(HTTPS_OK)
        assert r.status == 200
        assert r.bytes_read == len(body)
        assert r.redirects == 0
        assert "vless" in r.text

    def test_ingest_url_end_to_end(self):
        body = (VLESS_LINE + "\ngarbage\n" + "trojan://pw@b.com:1\n").encode()
        ing = SourceIngestor()
        res = ing.ingest_url(HTTPS_OK, fetcher=Fetcher(transport=ok_transport(body)),
                             origin_name="remote1")
        assert res.origin.kind is SourceKind.URL
        assert res.stats.lines_parsed == 2
        assert res.stats.lines_rejected == 1
        assert res.nodes[0].origin.name == "remote1"

    def test_content_type_captured(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(
            body=b"x", headers={"Content-Type": "text/plain; charset=utf-8"})})
        r = Fetcher(transport=t).fetch(HTTPS_OK)
        assert "text/plain" in r.content_type

    def test_no_fetcher_means_no_implicit_network(self):
        res = SourceIngestor().ingest_url(HTTPS_OK, fetcher=None)
        assert res.stats.lines_parsed == 0
        assert res.errors[0].reason == "fetch_no_fetcher"


class TestRedirects:
    def _redirect(self, location):
        return FakeResponse(status=302, headers={"Location": location})

    def test_same_host_redirect_followed(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("/final.txt"),
            "https://example.com/final.txt": FakeResponse(body=b"data"),
        })
        r = Fetcher(transport=t).fetch(HTTPS_OK)
        assert r.redirects == 1
        assert r.url == "https://example.com/final.txt"
        assert r.bytes_read == 4

    def test_cross_host_redirect_refused(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("https://evil.example.net/x"),
        })
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_downgrade_to_http_refused(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("http://example.com/x"),
        })
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_redirect_to_private_refused(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("https://169.254.169.254/meta"),
        })
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_redirect_loop_capped(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("/r1"),
            "https://example.com/r1": self._redirect("/r2"),
            "https://example.com/r2": self._redirect("/r3"),
            "https://example.com/r3": self._redirect("/r4"),
        })
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_redirect_without_location(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(status=302, headers={})})
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_relative_location_resolved(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("sub/dir.txt"),
            "https://example.com/sub/dir.txt": FakeResponse(body=b"ok"),
        })
        r = Fetcher(transport=t).fetch(HTTPS_OK)
        assert r.url == "https://example.com/sub/dir.txt"

    def test_subdomain_same_registrable_host_allowed(self):
        t = FakeTransport({
            HTTPS_OK: self._redirect("https://cdn.example.com/x"),
            "https://cdn.example.com/x": FakeResponse(body=b"d"),
        })
        r = Fetcher(transport=t).fetch(HTTPS_OK)
        assert r.redirects == 1


class TestLimits:
    def test_size_cap_enforced_midstream(self):
        big = b"a" * (64 * 1024 * 10)  # 640 KiB
        t = FakeTransport({HTTPS_OK: FakeResponse(body=big)})
        f = Fetcher(transport=t, max_bytes=1024)
        with pytest.raises(FetchSizeError):
            f.fetch(HTTPS_OK)

    def test_exact_cap_ok(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(body=b"z" * 1024)})
        assert Fetcher(transport=t, max_bytes=1024).fetch(HTTPS_OK).bytes_read == 1024

    def test_timeout_budget(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(body=b"x", delay=0.5)})
        with pytest.raises(FetchTimeoutError):
            Fetcher(transport=t, budget_seconds=0.05).fetch(HTTPS_OK)

    def test_transport_oserror_is_network(self):
        t = FakeTransport({})  # raises OSError for anything
        with pytest.raises(FetchNetworkError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_http_error_status(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(status=403)})
        with pytest.raises(FetchNetworkError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_response_closed_even_on_error(self):
        resp = FakeResponse(status=500)
        t = FakeTransport({HTTPS_OK: resp})
        with pytest.raises(FetchError):
            Fetcher(transport=t).fetch(HTTPS_OK)
        assert resp.closed


class TestIngestUrlErrors:
    def test_blocked(self):
        res = SourceIngestor().ingest_url(
            "http://insecure.example/x", fetcher=Fetcher(transport=FakeTransport()))
        assert res.errors[0].reason == "fetch_blocked"

    def test_network(self):
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=FakeTransport({})))
        assert res.errors[0].reason == "fetch_network"

    def test_size(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(body=b"a" * 2048)})
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=t, max_bytes=1024))
        assert res.errors[0].reason == "fetch_size"

    def test_timeout(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(body=b"a", delay=0.4)})
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=t, budget_seconds=0.05))
        assert res.errors[0].reason == "fetch_timeout"

    def test_fetch_error_never_contains_url_or_body(self):
        evil_body = b"SECRET-CONTENT-SHOULD-NOT-LEAK"
        t = FakeTransport({HTTPS_OK: FakeResponse(status=503, body=evil_body)})
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=t))
        blob = "\n".join(str(e) for e in res.errors)
        assert "SECRET-CONTENT" not in blob
        assert "503" not in blob  # sanitized reason code only

    def test_batch_url_plus_text(self):
        ing = SourceIngestor()
        body = (VLESS_LINE + "\n").encode()
        res = ing.ingest_many([
            (__import__("hubcore", fromlist=["SourceOrigin"]).SourceOrigin(
                "f1", SourceKind.RAW_TEXT), VLESS_LINE + "\n"),
        ])
        res = res.merged(ing.ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=ok_transport(body))))
        assert res.stats.lines_parsed == 2


class TestRegressionAdversarial:
    """Regression tests for bugs found during the Phase 4 bug hunt."""

    def test_regression_decimal_ip_bypass_blocked(self):
        # BUG: https://2130706433/x (=127.0.0.1) reached the transport
        url = "https://2130706433/x"
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=FakeTransport()).fetch(url)

    def test_regression_octal_ip_bypass_blocked(self):
        url = "https://0177.0.0.1/x"
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=FakeTransport()).fetch(url)

    def test_regression_hex_ip_bypass_blocked(self):
        for url in ("https://0x7f000001/x", "https://0x7f.0.0.1/x"):
            with pytest.raises(FetchBlockedError):
                Fetcher(transport=FakeTransport()).fetch(url)

    def test_regression_userinfo_url_blocked_cleanly(self):
        # BUG: credentials in URL produced a confusing FetchNetworkError
        # and were forwarded to the transport; now refused as Blocked
        url = "https://user:pass@example.com/a.txt"
        t = FakeTransport()
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(url)
        assert t.calls == []  # transport never saw the credentialed URL

    def test_regression_public_quad_still_allowed(self):
        url = "https://93.184.216.34/a.txt"
        r = Fetcher(transport=FakeTransport(
            {url: FakeResponse(body=b"x")})).fetch(url)
        assert r.status == 200

    def test_regression_scheme_relative_redirect_blocked(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(
            status=302, headers={"Location": "//evil.com/x"})})
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_regression_huge_location_blocked(self):
        t = FakeTransport({HTTPS_OK: FakeResponse(
            status=302, headers={"Location": "https://example.com/" + "a" * 5000})})
        with pytest.raises(FetchBlockedError):
            Fetcher(transport=t).fetch(HTTPS_OK)

    def test_regression_binary_body_ingests_as_zero_nodes(self):
        body = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=FakeTransport(
                {HTTPS_OK: FakeResponse(body=body)})))
        assert res.stats.lines_parsed == 0
        assert res.stats.lines_rejected == 5
        assert {e.reason for e in res.errors} == {"no_scheme"}

    def test_regression_empty_body_is_clean_zero(self):
        res = SourceIngestor().ingest_url(
            HTTPS_OK, fetcher=Fetcher(transport=FakeTransport(
                {HTTPS_OK: FakeResponse(body=b"")})))
        assert res.stats.lines_seen == 0 and res.errors == []

    def test_regression_trailing_dot_host_allowed(self):
        url = "https://example.com./a.txt"
        r = Fetcher(transport=FakeTransport(
            {url: FakeResponse(body=b"x")})).fetch(url)
        assert r.status == 200


class TestNoLeakage:
    def test_error_str_has_no_credentials(self):
        secret_line = "trojan://TOPSECRET@private.example:1"
        t = FakeTransport({HTTPS_OK: FakeResponse(status=500, body=secret_line.encode())})
        res = SourceIngestor().ingest_url(HTTPS_OK, fetcher=Fetcher(transport=t))
        blob = repr(res.errors)
        assert "TOPSECRET" not in blob

    def test_fetch_error_hierarchy(self):
        assert issubclass(FetchBlockedError, FetchError)
        assert issubclass(FetchNetworkError, FetchError)
        assert issubclass(FetchSizeError, FetchError)
        assert issubclass(FetchTimeoutError, FetchError)
