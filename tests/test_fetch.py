import socket

import requests

import config
from ml_engine.fetch import http_client
from ml_engine.fetch.html_features import extract
from ml_engine.fetch.redirect_resolver import resolve_chain
from ml_engine.fetch.sandboxed_fetcher import fetch
from ml_engine.fetch.ssrf_guard import validate_url


PUBLIC_IP = "8.8.8.8"


def public_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]


class FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=None, read_error=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.chunks = [] if chunks is None else chunks
        self.read_error = read_error
        self.closed = False
        self.iterated = False

    def iter_content(self, chunk_size=8192):
        self.iterated = True
        yield from self.chunks
        if self.read_error:
            raise self.read_error

    def close(self):
        self.closed = True


def test_production_transport_pins_ip_and_preserves_tls_identity(monkeypatch):
    captured = {}

    class RawResponse:
        status = 200
        headers = {"Content-Type": "text/html"}

        def stream(self, chunk_size, decode_content):
            yield b"ok"

        def close(self):
            pass

        def release_conn(self):
            pass

    class FakePool:
        def __init__(self, **kwargs):
            captured["pool"] = kwargs

        def request(self, method, target, **kwargs):
            captured["request"] = (method, target, kwargs)
            return RawResponse()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(http_client, "HTTPSConnectionPool", FakePool)
    validated = validate_url(
        "https://page.example.com/path?q=1", resolver=public_resolver
    )
    response = http_client.open_response(validated, timeout_s=2)
    assert b"".join(response.iter_content()) == b"ok"
    response.close()

    assert captured["pool"]["host"] == PUBLIC_IP
    assert captured["pool"]["server_hostname"] == "page.example.com"
    assert captured["pool"]["assert_hostname"] == "page.example.com"
    method, target, kwargs = captured["request"]
    assert (method, target) == ("GET", "/path?q=1")
    assert kwargs["headers"]["Host"] == "page.example.com"
    assert kwargs["redirect"] is False
    assert captured["closed"] is True


def test_redirect_chain_revalidates_each_hop_and_closes_responses():
    responses = [
        FakeResponse(302, {"Location": "/login"}),
        FakeResponse(301, {"Location": "https://destination.example.net/final"}),
        FakeResponse(200),
    ]
    calls = []

    def requester(url, **kwargs):
        calls.append((url, kwargs))
        return responses[len(calls) - 1]

    result = resolve_chain(
        "https://start.example.com/a", requester=requester, resolver=public_resolver
    )

    assert result["blocked"] is False
    assert result["chain"] == [
        "https://start.example.com/a",
        "https://start.example.com/login",
        "https://destination.example.net/final",
    ]
    assert result["redirect_count"] == 2
    assert result["domain_changed"] is True
    assert all(response.closed for response in responses)
    assert all(call[1]["allow_redirects"] is False for call in calls)
    assert all(call[1]["stream"] is True for call in calls)


def test_private_redirect_is_blocked_before_second_request():
    response = FakeResponse(
        302, {"Location": "http://169.254.169.254/latest/meta-data/"}
    )
    calls = []

    def requester(url, **kwargs):
        calls.append(url)
        return response

    result = resolve_chain(
        "https://public.example.com/", requester=requester, resolver=public_resolver
    )

    assert result["blocked"] is True
    assert "blocked address range" in result["block_reason"]
    assert calls == ["https://public.example.com/"]
    assert response.closed is True


def test_redirect_to_unsafe_port_is_blocked_before_request():
    response = FakeResponse(302, {"Location": "http://public.example.com:22/admin"})
    result = resolve_chain(
        "https://public.example.com/",
        requester=lambda *args, **kwargs: response,
        resolver=public_resolver,
    )
    assert result["blocked"] is True
    assert "port 22" in result["block_reason"]


def test_redirect_loop_is_detected_without_repeating_request():
    response = FakeResponse(302, {"Location": "#different-fragment"})
    calls = []

    def requester(url, **kwargs):
        calls.append(url)
        return response

    result = resolve_chain(
        "https://loop.example.com/path", requester=requester, resolver=public_resolver
    )

    assert result["blocked"] is True
    assert result["block_reason"] == "redirect loop detected"
    assert len(calls) == 1


def test_redirect_limit_allows_exact_limit_then_blocks_another(monkeypatch):
    monkeypatch.setattr(config, "MAX_REDIRECTS", 2)
    calls = []

    def requester(url, **kwargs):
        calls.append(url)
        return FakeResponse(302, {"Location": f"/hop-{len(calls)}"})

    result = resolve_chain(
        "https://redirect.example.com/start",
        requester=requester,
        resolver=public_resolver,
    )

    assert result["blocked"] is True
    assert result["redirect_count"] == 2
    assert "exceeded 2" in result["block_reason"]
    assert len(calls) == 3


def test_redirect_network_error_is_fail_closed():
    def requester(*args, **kwargs):
        raise requests.ConnectTimeout("timed out")

    result = resolve_chain(
        "https://public.example.com/", requester=requester, resolver=public_resolver
    )
    assert result["blocked"] is True
    assert "timed out" in result["block_reason"]


def test_fetch_streams_html_and_closes_response():
    response = FakeResponse(
        headers={"Content-Type": "text/html; charset=utf-8"},
        chunks=[b"<html>", b"ok</html>"],
    )
    result = fetch(
        "https://page.example.com/",
        requester=lambda *args, **kwargs: response,
        resolver=public_resolver,
    )

    assert result["ok"] is True
    assert result["body"] == "<html>ok</html>"
    assert result["bytes_read"] == 15
    assert result["truncated"] is False
    assert response.closed is True


def test_fetch_caps_decompressed_body(monkeypatch):
    monkeypatch.setattr(config, "MAX_FETCH_BYTES", 10)
    response = FakeResponse(
        headers={"Content-Type": "text/html", "Content-Length": "1000"},
        chunks=[b"12345678", b"abcdefgh"],
    )
    result = fetch(
        "https://page.example.com/",
        requester=lambda *args, **kwargs: response,
        resolver=public_resolver,
    )

    assert result["ok"] is True
    assert result["body"] == "12345678ab"
    assert result["bytes_read"] == 10
    assert result["truncated"] is True
    assert response.closed is True


def test_fetch_never_calls_requester_for_blocked_target():
    def requester(*args, **kwargs):
        raise AssertionError("requester must not be called")

    result = fetch("http://127.0.0.1/", requester=requester, resolver=public_resolver)
    assert result["ok"] is False
    assert "blocked address range" in result["error"]


def test_fetch_rejects_redirect_and_binary_without_reading_body():
    for response in (
        FakeResponse(302, {"Location": "https://other.example.com/"}, [b"ignored"]),
        FakeResponse(200, {"Content-Type": "application/octet-stream"}, [b"binary"]),
    ):
        result = fetch(
            "https://page.example.com/",
            requester=lambda *args, _response=response, **kwargs: _response,
            resolver=public_resolver,
        )
        assert result["ok"] is False
        assert response.iterated is False
        assert response.closed is True


def test_fetch_honours_declared_charset():
    response = FakeResponse(
        headers={"Content-Type": "text/html; charset=iso-8859-1"},
        chunks=["caf\u00e9".encode("iso-8859-1")],
    )
    result = fetch(
        "https://page.example.com/",
        requester=lambda *args, **kwargs: response,
        resolver=public_resolver,
    )
    assert result["ok"] is True
    assert result["body"] == "caf\u00e9"


def test_fetch_normalises_stream_read_error_and_closes():
    response = FakeResponse(
        headers={"Content-Type": "text/html"},
        chunks=[b"partial"],
        read_error=requests.ReadTimeout("slow body"),
    )
    result = fetch(
        "https://page.example.com/",
        requester=lambda *args, **kwargs: response,
        resolver=public_resolver,
    )
    assert result["ok"] is False
    assert "slow body" in result["error"]
    assert response.closed is True


def test_html_features_cover_forms_hidden_inputs_domains_and_brand_title():
    html = """
    <html><head>
      <title>PayPal Account Verification</title>
      <base href="https://assets.attacker.net/root/">
      <link rel="shortcut icon" href="/favicon.ico">
      <meta http-equiv="refresh" content="0; url=https://collector.attacker.net/next">
    </head><body>
      <form action="javascript:steal()">
        <input type="hidden"><input type="hidden"><input type="password">
      </form>
      <form action="https://collector.attacker.net/submit"></form>
      <script src="app.js"></script><script>inline()</script>
      <iframe src="/frame"></iframe>
    </body></html>
    """
    result = extract(html, "https://login.paypal-check.co.uk/account")

    assert result["form_count"] == 2
    assert result["unsafe_form_action"] is True
    assert result["form_domain_mismatch"] is True
    assert result["password_field_count"] == 1
    assert result["hidden_input_count"] == 2
    assert result["script_count"] == 2
    assert result["external_script_count"] == 1
    assert result["iframe_count"] == 1
    assert result["external_iframe_count"] == 1
    assert result["base_domain_mismatch"] is True
    assert result["external_favicon"] is True
    assert result["has_meta_refresh"] is True
    assert result["meta_refresh_domain_mismatch"] is True
    assert result["title_brand_mismatch"] is True


def test_html_feature_domain_matching_handles_multi_label_public_suffix():
    html = """
    <html><head><title>PayPal</title></head><body>
      <form action="https://auth.paypal.co.uk/submit"><input type="password"></form>
      <script src="https://static.paypal.co.uk/app.js"></script>
    </body></html>
    """
    result = extract(html, "https://www.paypal.co.uk/login")

    assert result["form_domain_mismatch"] is False
    assert result["external_script_count"] == 0
    assert result["title_brand_mismatch"] is False


def test_html_features_treat_private_suffix_tenants_as_different_origins():
    html = """
    <form action="https://collector.github.io/submit"></form>
    <script src="https:\\attacker.example.com\\payload.js"></script>
    """
    result = extract(html, "https://victim.github.io/login")

    assert result["form_domain_mismatch"] is True
    assert result["unsafe_script_source_count"] == 1
