import socket
import threading

import pytest

import config
from ml_engine.fetch.ssrf_guard import (
    SSRFBlocked,
    check_url,
    resolve_and_check,
    validate_url,
)

PUBLIC_V4 = "8.8.8.8"
PUBLIC_V6 = "2606:4700:4700::1111"


def resolver_for(*addresses):
    def resolve(host, port):
        results = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (
                (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            )
            results.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return results

    return resolve


def test_validate_url_returns_dns_pinning_inputs_and_removes_fragment():
    calls = []

    def resolver(host, port):
        calls.append((host, port))
        return resolver_for(PUBLIC_V4)(host, port)

    result = validate_url("https://Example.COM/a/b?q=1#ignored", resolver=resolver)

    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.resolved_ips == (PUBLIC_V4,)
    assert result.request_target == "/a/b?q=1"
    assert result.url == "https://example.com/a/b?q=1"
    assert calls == [("example.com", 443)]
    assert check_url("https://example.com", resolver=resolver) == "example.com"


def test_unicode_hostname_is_idna_normalised_before_resolution():
    seen = []

    def resolver(host, port):
        seen.append(host)
        return resolver_for(PUBLIC_V4)(host, port)

    result = validate_url("https://b\u00fccher.com/", resolver=resolver)

    assert result.hostname == "xn--bcher-kva.com"
    assert seen == ["xn--bcher-kva.com"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "//example.com/path",
        "file:///etc/passwd",
        "ftp://example.com/file",
        "https:///missing-host",
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https://example.com:/",
        "https://example.com:80/",
        "https://example.com:0/",
        "http://example.com:443/",
        "http://example.com:8080/",
        "https://example.com:99999/",
        "https://example.com/a b",
        "https://example.com/\nnext",
        "https://example.com\\@127.0.0.1/",
        "https://foo..example.com/",
        "https://foo_bar.example.com/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://metadata.google.internal/",
        "http://service.cluster.local/",
        "http://intranet/",
    ],
)
def test_rejects_malformed_or_unsafe_urls_before_request(url):
    with pytest.raises(SSRFBlocked):
        validate_url(url, resolver=resolver_for(PUBLIC_V4))


@pytest.mark.parametrize(
    "url",
    [
        "http://0.0.0.0/",
        "http://10.0.0.1/",
        "http://100.64.0.1/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.0.2.1/",
        "http://224.0.0.1/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[2002:0a00:0001::]/",
        "http://[64:ff9b::7f00:1]/",
    ],
)
def test_rejects_non_global_ip_literals_without_dns(url):
    def must_not_resolve(*args):
        raise AssertionError("literal IP targets must not need DNS")

    with pytest.raises(SSRFBlocked):
        validate_url(url, resolver=must_not_resolve)


def test_accepts_global_ipv4_and_ipv6_literals_without_dns():
    assert validate_url(f"https://{PUBLIC_V4}/").resolved_ips == (PUBLIC_V4,)
    ipv6 = validate_url(f"https://[{PUBLIC_V6}]/x")
    assert ipv6.resolved_ips == (PUBLIC_V6,)
    assert ipv6.host_header == f"[{PUBLIC_V6}]"


def test_rejects_entire_dns_answer_if_one_address_is_private():
    with pytest.raises(SSRFBlocked, match="blocked address range"):
        resolve_and_check(
            "mixed.example.com",
            resolver=resolver_for(PUBLIC_V4, "10.0.0.2"),
            port=443,
        )


def test_resolver_results_are_deduplicated_and_must_be_usable():
    assert resolve_and_check(
        "public.example.com",
        resolver=resolver_for(PUBLIC_V4, PUBLIC_V4, PUBLIC_V6),
        port=443,
    ) == [PUBLIC_V4, PUBLIC_V6]

    with pytest.raises(SSRFBlocked, match="no usable addresses"):
        resolve_and_check("empty.example.com", resolver=lambda host, port: [], port=443)


def test_resolution_failure_is_fail_closed():
    def broken_resolver(host, port):
        raise socket.gaierror("DNS unavailable")

    with pytest.raises(SSRFBlocked, match="could not resolve"):
        validate_url("https://example.com/", resolver=broken_resolver)


def test_production_dns_lookup_has_a_deadline(monkeypatch):
    release = threading.Event()
    finished = threading.Event()

    def blocking_getaddrinfo(host, port):
        try:
            release.wait(timeout=1)
            return resolver_for(PUBLIC_V4)(host, port)
        finally:
            finished.set()

    monkeypatch.setattr(config, "DNS_TIMEOUT_S", 0.01)
    monkeypatch.setattr(socket, "getaddrinfo", blocking_getaddrinfo)
    try:
        with pytest.raises(SSRFBlocked, match="DNS resolution timed out"):
            validate_url("https://timeout.example.com/")
    finally:
        release.set()
    assert finished.wait(timeout=1)
