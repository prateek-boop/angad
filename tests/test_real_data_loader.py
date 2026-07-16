import io
import os
import time
import urllib.error
import zipfile

import pytest

from ml_engine.real_data_loader import (
    FeedFetchError,
    RealDatasetError,
    fetch_feed,
    load_real_dataset,
    load_threat_blocklists,
    parse_labeled_csv,
    parse_openphish,
    parse_phishtank,
    parse_tranco,
    parse_urlhaus,
)


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, *, status: int = 200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_urlhaus_supports_plain_text_and_csv_and_deduplicates():
    source = io.BytesIO(
        b"# URLhaus online URLs\n"
        b"http://evil.example/a.exe\n"
        b'1,"2026-01-01","http://evil.example/b.exe","online"\n'
        b"javascript:alert(1)\n"
        b"http://evil.example/a.exe\n"
    )

    assert parse_urlhaus(source) == [
        ("http://evil.example/a.exe", "malware"),
        ("http://evil.example/b.exe", "malware"),
    ]


def test_feed_parsers_skip_malformed_rows_and_honor_limit():
    openphish = io.StringIO(
        "# generated feed\nhttps://one.example/login\nnot-a-url\nhttps://two.example/login\n"
    )
    phishtank = io.StringIO(
        "phish_id,url,verified\n1,http://phish.example/a,yes\n2,file:///etc/passwd,yes\n"
    )
    tranco = io.StringIO(
        "rank,domain\n1,example.com\nbad,row\n2,example.org/path\n3,example.net\n"
    )

    assert parse_openphish(openphish, limit=1) == [
        ("https://one.example/login", "phishing")
    ]
    assert parse_phishtank(phishtank) == [("http://phish.example/a", "phishing")]
    assert parse_tranco(tranco) == [
        ("https://example.com", "safe"),
        ("https://example.com/", "safe"),
        ("https://www.example.com/", "safe"),
        ("https://example.net", "safe"),
        ("https://example.net/", "safe"),
        ("https://www.example.net/", "safe"),
    ]


def test_tranco_emits_url_form_variants_so_safe_is_not_one_shape():
    # Regression: a safe corpus made only of bare "https://domain" rows
    # teaches the model that surface form instead of safeness, so any URL
    # with a slash or www prefix gets classified as a threat.
    rows = parse_tranco(io.StringIO("1,google.com\n2,en.wikipedia.org\n"))
    urls = [url for url, _ in rows]
    assert "https://google.com" in urls
    assert "https://google.com/" in urls
    assert "https://www.google.com/" in urls
    # subdomains get slash variants but no fabricated www.<subdomain> form
    assert "https://en.wikipedia.org/" in urls
    assert "https://www.en.wikipedia.org/" not in urls
    assert all(label == "safe" for _, label in rows)


def test_generic_labeled_csv_maps_aliases_and_rejects_unknown_labels():
    source = io.StringIO(
        "URL,Category\n"
        "https://good.example,benign\n"
        "http://bad.example,phish\n"
        "https://unknown.example,maybe\n"
    )

    assert parse_labeled_csv(source) == [
        ("https://good.example", "safe"),
        ("http://bad.example", "phishing"),
    ]
    assert (
        parse_labeled_csv(io.StringIO("url,label\nhttps://x.example,safe\n"), limit=0)
        == []
    )


def test_threat_blocklists_are_exact_sets_and_isolate_empty_provider():
    blocklists = load_threat_blocklists(
        sources={
            "urlhaus": io.StringIO("http://malware.example/a.exe\n"),
            "openphish": io.StringIO("# empty\n"),
        },
    )

    assert blocklists == {"urlhaus": {"http://malware.example/a.exe"}}


def test_fetch_feed_reuses_fresh_cache_without_network(tmp_path):
    destination = tmp_path / "openphish_feed.cache"
    destination.write_text("https://cached.example/login\n")

    def unexpected(*args, **kwargs):
        raise AssertionError("fresh cache should avoid network")

    result = fetch_feed("openphish", cache_dir=tmp_path, ttl_s=3600, opener=unexpected)

    assert result == str(destination)


def test_fetch_feed_unpacks_zip_and_writes_atomically(tmp_path):
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("top-1m.csv", "1,example.com\n2,example.org\n")

    calls = []

    def opener(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse(archive_bytes.getvalue())

    destination = fetch_feed("tranco", cache_dir=tmp_path, ttl_s=0, opener=opener)

    assert calls and calls[0][1] == 15
    assert open(destination, "rb").read() == b"1,example.com\n2,example.org\n"
    assert not list(tmp_path.glob(".shieldnet-feed-*"))


def test_fetch_feed_uses_stale_cache_on_provider_failure(tmp_path):
    destination = tmp_path / "openphish_feed.cache"
    destination.write_text("https://stale.example/login\n")
    old = time.time() - 7200
    os.utime(destination, (old, old))

    def failed(*args, **kwargs):
        raise urllib.error.URLError("offline")

    result = fetch_feed(
        "openphish",
        cache_dir=tmp_path,
        ttl_s=60,
        opener=failed,
        allow_stale=True,
    )

    assert result == str(destination)
    assert destination.read_text() == "https://stale.example/login\n"


def test_fetch_feed_rejects_oversized_or_http_error_without_cache(tmp_path):
    def oversized(request, timeout):
        return FakeResponse(b"12345", headers={"Content-Length": "5"})

    with pytest.raises(FeedFetchError, match="exceeds"):
        fetch_feed(
            "openphish",
            cache_dir=tmp_path,
            ttl_s=0,
            max_bytes=4,
            opener=oversized,
        )

    def server_error(request, timeout):
        return FakeResponse(b"failure", status=503)

    with pytest.raises(FeedFetchError, match="HTTP 503"):
        fetch_feed("openphish", cache_dir=tmp_path, ttl_s=0, opener=server_error)


def test_fetch_feed_enforces_total_deadline(tmp_path):
    def stalled(request, timeout):
        time.sleep(0.2)
        return FakeResponse(b"https://late.example/login\n")

    started = time.monotonic()
    with pytest.raises(FeedFetchError):
        fetch_feed(
            "openphish",
            cache_dir=tmp_path,
            ttl_s=0,
            timeout_s=0.01,
            opener=stalled,
        )

    assert time.monotonic() - started < 0.15


def test_real_dataset_survives_partial_feed_failure_and_resolves_label_conflict():
    urls, labels = load_real_dataset(
        feed_names=["tranco", "urlhaus", "openphish"],
        sources={
            "tranco": io.StringIO("1,example.com\n"),
            "urlhaus": io.StringIO("# empty\n"),
            "openphish": io.StringIO(
                "https://EXAMPLE.com/#fragment\nhttps://phish.example/login\n"
            ),
        },
    )

    # example.com's bare/slash tranco variants collapse to one canonical key
    # and lose the label conflict to openphish; www.example.com is a distinct
    # host and keeps its safe label.
    assert urls == [
        "https://EXAMPLE.com/#fragment",
        "https://www.example.com/",
        "https://phish.example/login",
    ]
    assert labels == ["phishing", "safe", "phishing"]


def test_real_dataset_strict_mode_reports_partial_failure():
    with pytest.raises(RealDatasetError, match="urlhaus"):
        load_real_dataset(
            feed_names=["openphish", "urlhaus"],
            sources={
                "openphish": io.StringIO("https://phish.example/login\n"),
                "urlhaus": io.StringIO("# empty\n"),
            },
            strict=True,
        )


def test_real_dataset_raises_when_every_source_is_unusable():
    with pytest.raises(RealDatasetError, match="no usable real records"):
        load_real_dataset(
            sources={"openphish": io.StringIO("not-a-url\n")},
        )


def test_real_dataset_can_include_local_labeled_sources():
    urls, labels = load_real_dataset(
        feed_names=[],
        local_sources=[
            io.StringIO(
                "url,label\nhttps://safe.example,legitimate\nhttp://leak.example,data_leak\n"
            ),
        ],
    )

    assert urls == ["https://safe.example", "http://leak.example"]
    assert labels == ["safe", "data_leak"]
