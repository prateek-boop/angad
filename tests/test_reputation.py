import time
from datetime import UTC, datetime

from ml_engine.reputation import ReputationChecker

NOW = datetime(2026, 7, 15, tzinfo=UTC)
PUBLIC_DNS = [(2, 1, 6, "", ("93.184.216.34", 0))]
CERT = {
    "issuer": ((("organizationName", "Example CA"),),),
    "notBefore": "Jul  1 00:00:00 2026 GMT",
    "notAfter": "Aug  1 00:00:00 2026 GMT",
}


def test_collects_rdap_dns_tls_and_multilabel_registered_domain():
    requested_domains = []
    checker = ReputationChecker(
        rdap_fetch=lambda domain: (
            requested_domains.append(domain)
            or {
                "events": [
                    {
                        "eventAction": "last changed",
                        "eventDate": "2026-07-14T00:00:00Z",
                    },
                    {
                        "eventAction": "registration",
                        "eventDate": "2020-07-15T00:00:00Z",
                    },
                    {"eventAction": "expiration", "eventDate": "2027-07-15T00:00:00Z"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar"]],
                        ],
                    }
                ],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.NET."}],
            }
        ),
        dns_resolve=lambda hostname: PUBLIC_DNS,
        tls_connect=lambda hostname: CERT,
        cache_path=None,
        now=lambda: NOW,
    )

    result = checker.check("https://login.example.co.uk/account")

    assert requested_domains == ["example.co.uk"]
    assert result["hostname"] == "login.example.co.uk"
    assert result["registered_domain"] == "example.co.uk"
    assert result["dns_resolves"] is True
    assert result["dns_addresses"] == ["93.184.216.34"]
    assert result["domain_age_days"] == 2191.0
    assert result["domain_expires_in_days"] == 365.0
    assert result["registrar"] == "Example Registrar"
    assert result["nameservers"] == ["ns1.example.net"]
    assert result["tls_issuer"] == "Example CA"
    assert result["tls_age_days"] == 14.0
    assert result["tls_expires_in_days"] == 17.0
    assert result["tls_expired"] is False
    assert result["lookup_errors"] == {}


def test_private_literal_never_invokes_network_lookup():
    def unexpected(*args):
        raise AssertionError("network seam should not be called")

    result = ReputationChecker(
        rdap_fetch=unexpected,
        dns_resolve=unexpected,
        tls_connect=unexpected,
        cache_path=None,
    ).check("http://127.0.0.1/admin")

    assert result["has_non_public_address"] is True
    assert result["dns_resolves"] is False
    assert result["lookup_errors"] == {"target": "non_public_hostname"}


def test_private_or_mixed_dns_answer_prevents_tls_connection():
    tls_calls = []
    checker = ReputationChecker(
        rdap_fetch=lambda domain: {},
        dns_resolve=lambda hostname: ["93.184.216.34", "10.0.0.8"],
        tls_connect=lambda hostname: tls_calls.append(hostname) or CERT,
        cache_path=None,
        now=lambda: NOW,
    )

    result = checker.check("https://rebind.example.com/")

    assert result["dns_resolves"] is True
    assert result["dns_addresses"] == ["93.184.216.34"]
    assert result["has_non_public_address"] is True
    assert result["lookup_errors"]["target"] == "dns_contains_non_public_address"
    assert tls_calls == []


def test_cache_is_persistent_and_blocklists_are_evaluated_after_cache(tmp_path):
    cache_path = tmp_path / "reputation.sqlite3"
    calls = {"dns": 0, "rdap": 0, "tls": 0}

    def counted(name, value):
        def lookup(*args):
            calls[name] += 1
            return value

        return lookup

    first = ReputationChecker(
        rdap_fetch=counted("rdap", {}),
        dns_resolve=counted("dns", PUBLIC_DNS),
        tls_connect=counted("tls", CERT),
        cache_path=str(cache_path),
        blocklists={},
        now=lambda: NOW,
    ).check("https://Example.com:443/path#old-fragment")

    def unexpected(*args):
        raise AssertionError("cached network lookup should not run")

    second = ReputationChecker(
        rdap_fetch=unexpected,
        dns_resolve=unexpected,
        tls_connect=unexpected,
        cache_path=str(cache_path),
        blocklists={"openphish": {"https://example.com/path#different-fragment"}},
        now=lambda: NOW,
    ).check("https://example.com/path")

    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["blocklist_hit"] == "openphish"
    assert calls == {"dns": 1, "rdap": 1, "tls": 1}


def test_lookup_timeout_is_bounded_and_reported():
    def slow_dns(hostname):
        time.sleep(0.2)
        return PUBLIC_DNS

    checker = ReputationChecker(
        rdap_fetch=lambda domain: {},
        dns_resolve=slow_dns,
        tls_connect=lambda hostname: CERT,
        dns_timeout_s=0.01,
        cache_path=None,
        now=lambda: NOW,
    )

    started = time.monotonic()
    result = checker.check("https://example.com")
    elapsed = time.monotonic() - started

    assert elapsed < 0.15
    assert result["dns_resolves"] is False
    assert result["lookup_errors"]["dns"] == "timeout"
    assert result["tls_issuer"] is None


def test_invalid_scheme_or_hostname_does_not_call_lookups():
    def unexpected(*args):
        raise AssertionError("lookup should not run for invalid URL")

    checker = ReputationChecker(
        rdap_fetch=unexpected,
        dns_resolve=unexpected,
        tls_connect=unexpected,
        cache_path=None,
    )

    assert checker.check("file:///etc/passwd")["lookup_errors"] == {
        "target": "invalid_url"
    }
    assert checker.check("https://bad host.example")["lookup_errors"] == {
        "target": "invalid_url"
    }


def test_individual_lookup_failures_preserve_other_signals():
    def failed_rdap(domain):
        raise OSError("provider unavailable")

    checker = ReputationChecker(
        rdap_fetch=failed_rdap,
        dns_resolve=lambda hostname: PUBLIC_DNS,
        tls_connect=lambda hostname: CERT,
        cache_path=None,
        now=lambda: NOW,
    )

    result = checker.check("https://example.com")

    assert result["domain_age_days"] is None
    assert result["lookup_errors"]["rdap"] == "lookup_failed"
    assert result["dns_resolves"] is True
    assert result["tls_issuer"] == "Example CA"
