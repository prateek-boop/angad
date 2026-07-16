"""Robust ingestion for free URL threat-intelligence and benign-domain feeds.

Parsers accept paths, text streams, or binary streams. Remote refreshes are
explicit, bounded, atomically cached, and fall back to a stale cache during a
temporary provider outage. This module only downloads configured feed files; it
never visits a URL contained in a feed.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import queue
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from urllib.parse import urlsplit, urlunsplit

import config

_UA = "ShieldNet/0.1 (+security-research)"
_DOWNLOAD_TIMEOUT_S = 15
_MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_RECORDS_PER_FEED = 100_000
_READ_CHUNK_BYTES = 64 * 1024
_LOGGER = logging.getLogger(__name__)
_DOWNLOAD_SLOTS = threading.BoundedSemaphore(2)


class FeedError(RuntimeError):
    """Base class for actionable feed ingestion failures."""


class FeedFetchError(FeedError):
    """A configured remote feed could not be downloaded safely."""


class FeedParseError(FeedError):
    """A feed was downloaded/read but contained no usable records."""


class RealDatasetError(FeedError):
    """No usable real records could be assembled, or strict loading failed."""


def _iter_text_lines(source) -> Iterator[str]:
    close_stream = False
    if hasattr(source, "read"):
        stream = source
    else:
        stream = open(os.fspath(source), "rb")
        close_stream = True
    try:
        for raw_line in stream:
            if isinstance(raw_line, bytes):
                line = raw_line.decode("utf-8", errors="replace")
            else:
                line = str(raw_line)
            yield line.rstrip("\r\n")
    finally:
        if close_stream:
            stream.close()


def _valid_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    url = value.strip().strip('"').strip("'")
    if not url or len(url) > 8192 or "\x00" in url or any(c.isspace() for c in url):
        return None
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in config.ALLOWED_SCHEMES or not parts.hostname:
            return None
        parts.hostname.encode("idna")
        parts.port  # validate malformed/non-numeric ports
    except (UnicodeError, ValueError):
        return None
    return url


def _dedupe(
    records: Iterable[tuple[str, str]], limit: int | None = None
) -> list[tuple[str, str]]:
    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative or None")
    if limit == 0:
        return []
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url, label in records:
        if url in seen:
            continue
        seen.add(url)
        output.append((url, label))
        if limit is not None and len(output) >= limit:
            break
    return output


def parse_urlhaus(source, limit: int | None = None) -> list[tuple[str, str]]:
    """Parse both URLhaus ``text_online`` and historical CSV exports."""

    def records():
        for line in _iter_text_lines(source):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                fields = next(csv.reader([stripped]))
            except csv.Error:
                continue
            # text_online is one URL per line; CSV exports place it in a later
            # column. Finding the first valid URL supports both without guessing
            # a provider-specific column count.
            for field in fields:
                url = _valid_url(field)
                if url is not None:
                    yield url, "malware"
                    break

    return _dedupe(records(), limit)


def parse_openphish(source, limit: int | None = None) -> list[tuple[str, str]]:
    """Parse OpenPhish's free one-URL-per-line feed."""

    records = (
        (url, "phishing")
        for line in _iter_text_lines(source)
        if line.strip() and not line.lstrip().startswith("#")
        for url in [_valid_url(line)]
        if url is not None
    )
    return _dedupe(records, limit)


def parse_phishtank(source, limit: int | None = None) -> list[tuple[str, str]]:
    """Parse a locally downloaded PhishTank CSV export."""

    if limit == 0:
        return []
    lines = _iter_text_lines(source)
    try:
        reader = csv.DictReader(lines)
        records = []
        for row in reader:
            lowered = {
                str(key).strip().lower(): value for key, value in row.items() if key
            }
            url = _valid_url(lowered.get("url"))
            if url is not None:
                records.append((url, "phishing"))
                if limit is not None and len(records) >= limit:
                    break
        return _dedupe(records, limit)
    except csv.Error as exc:
        raise FeedParseError("invalid PhishTank CSV") from exc


def parse_tranco(source, limit: int | None = None) -> list[tuple[str, str]]:
    """Parse Tranco's ``rank,domain`` CSV into HTTPS safe examples.

    Each domain is emitted in several real URL surface forms (bare, trailing
    slash, and www-prefixed for registered domains). A safe corpus with only
    one surface form teaches the model that *form*, not safeness: trained on
    bare ``https://domain`` rows alone, the model classifies any URL with a
    path, trailing slash, or www prefix as a threat regardless of the domain.
    """

    def records():
        for line in _iter_text_lines(source):
            try:
                row = next(csv.reader([line]))
            except csv.Error:
                continue
            if len(row) < 2:
                continue
            try:
                int(row[0].strip())
            except ValueError:
                continue
            domain = row[1].strip().rstrip(".")
            if "/" in domain or "@" in domain or not domain:
                continue
            variants = [f"https://{domain}", f"https://{domain}/"]
            if domain.count(".") == 1 and not domain.startswith("www."):
                variants.append(f"https://www.{domain}/")
            for candidate in variants:
                url = _valid_url(candidate)
                if url is not None:
                    yield url, "safe"

    return _dedupe(records(), limit)


_LABEL_ALIASES = {
    "safe": "safe",
    "benign": "safe",
    "legitimate": "safe",
    "legit": "safe",
    "phishing": "phishing",
    "phish": "phishing",
    "malware": "malware",
    "malicious": "malware",
    "data_leak": "data_leak",
    "data leak": "data_leak",
    "leak": "data_leak",
    "scam": "scam",
    "fraud": "scam",
}


def parse_labeled_csv(
    source,
    limit: int | None = None,
    *,
    url_columns: tuple[str, ...] = ("url", "link", "uri"),
    label_columns: tuple[str, ...] = ("label", "class", "category", "type"),
) -> list[tuple[str, str]]:
    """Parse common local/Kaggle CSV layouts with explicit label validation."""

    if limit == 0:
        return []
    try:
        reader = csv.DictReader(_iter_text_lines(source))
        records = []
        for row in reader:
            lowered = {
                str(key).strip().lower(): value for key, value in row.items() if key
            }
            raw_url = next(
                (lowered[name] for name in url_columns if lowered.get(name)), None
            )
            raw_label = next(
                (lowered[name] for name in label_columns if lowered.get(name)), None
            )
            url = _valid_url(raw_url)
            label = (
                _LABEL_ALIASES.get(str(raw_label).strip().lower())
                if raw_label is not None
                else None
            )
            if url is None or label not in config.THREAT_CLASSES:
                continue
            records.append((url, label))
            if limit is not None and len(records) >= limit:
                break
        return _dedupe(records, limit)
    except csv.Error as exc:
        raise FeedParseError("invalid labeled CSV") from exc


_PARSERS = {
    "urlhaus": parse_urlhaus,
    "openphish": parse_openphish,
    "phishtank": parse_phishtank,
    "tranco": parse_tranco,
}


def _read_bounded(stream, max_bytes: int) -> bytes:
    content_length = None
    headers = getattr(stream, "headers", None)
    if headers is not None:
        try:
            content_length = headers.get("Content-Length")
        except AttributeError:
            content_length = None
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise FeedFetchError(f"feed exceeds {max_bytes} bytes")
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(_READ_CHUNK_BYTES, max_bytes - total + 1))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if total > max_bytes:
            raise FeedFetchError(f"feed exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _run_with_deadline(function, timeout_s: float):
    """Enforce a wall-clock bound around urllib, including system DNS time."""

    started = time.monotonic()
    if not _DOWNLOAD_SLOTS.acquire(timeout=timeout_s):
        raise TimeoutError("feed download worker capacity exhausted")
    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result_queue.put((True, function()))
        except Exception as exc:
            result_queue.put((False, exc))
        finally:
            _DOWNLOAD_SLOTS.release()

    worker = threading.Thread(target=run, name="shieldnet-feed-download", daemon=True)
    worker.start()
    worker.join(max(0.0, timeout_s - (time.monotonic() - started)))
    if worker.is_alive():
        raise TimeoutError(f"feed download exceeded {timeout_s:g}s")
    succeeded, value = result_queue.get_nowait()
    if succeeded:
        return value
    raise value


def _unpack_zip(raw: bytes, max_bytes: int) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            csv_members = [
                item
                for item in members
                if item.filename.lower().endswith((".csv", ".txt"))
            ]
            if not csv_members:
                raise FeedFetchError("feed ZIP contains no CSV/text file")
            member = csv_members[0]
            if member.flag_bits & 0x1:
                raise FeedFetchError("encrypted feed ZIP is unsupported")
            if member.file_size > max_bytes:
                raise FeedFetchError(f"unpacked feed exceeds {max_bytes} bytes")
            with archive.open(member) as stream:
                return _read_bounded(stream, max_bytes)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        if isinstance(exc, FeedFetchError):
            raise
        raise FeedFetchError("invalid feed ZIP") from exc


def _atomic_write(path: str, raw: bytes) -> None:
    descriptor, temp_path = tempfile.mkstemp(
        prefix=".shieldnet-feed-", dir=os.path.dirname(path)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def fetch_feed(
    name: str,
    cache_dir: str | os.PathLike | None = None,
    ttl_s: int | None = None,
    *,
    timeout_s: float = _DOWNLOAD_TIMEOUT_S,
    max_bytes: int = _MAX_DOWNLOAD_BYTES,
    allow_stale: bool = True,
    opener=None,
    clock=time.time,
) -> str:
    """Refresh a configured feed and return its local cache path.

    Cache writes are atomic. If refresh fails and a non-empty stale cache exists,
    it is returned by default so a provider outage does not take training or
    inference down with it.
    """

    if name not in config.BLOCKLIST_URLS:
        raise ValueError(f"unknown or unconfigured feed: {name}")
    if max_bytes <= 0 or timeout_s <= 0:
        raise ValueError("timeout_s and max_bytes must be positive")
    ttl_s = config.BLOCKLIST_CACHE_TTL_S if ttl_s is None else int(ttl_s)
    if ttl_s < 0:
        raise ValueError("ttl_s must be non-negative")

    cache_root = os.fspath(cache_dir or config.DATA_DIR)
    os.makedirs(cache_root, exist_ok=True)
    destination = os.path.join(cache_root, f"{name}_feed.cache")
    has_stale_cache = os.path.isfile(destination) and os.path.getsize(destination) > 0
    if has_stale_cache and clock() - os.path.getmtime(destination) < ttl_s:
        return destination

    url = config.BLOCKLIST_URLS[name]
    request = urllib.request.Request(
        url,
        headers={"Accept": "text/plain, text/csv, application/zip", "User-Agent": _UA},
    )
    open_url = opener or urllib.request.urlopen
    try:

        def download():
            with open_url(request, timeout=timeout_s) as response:
                status = getattr(response, "status", None)
                if status is None and hasattr(response, "getcode"):
                    status = response.getcode()
                if status is not None and not 200 <= int(status) < 300:
                    raise FeedFetchError(f"feed server returned HTTP {status}")
                return _read_bounded(response, max_bytes)

        raw = _run_with_deadline(download, timeout_s)
        if not raw:
            raise FeedFetchError("feed response is empty")
        if url.lower().endswith(".zip") or raw.startswith(b"PK\x03\x04"):
            raw = _unpack_zip(raw, max_bytes)
        if not raw:
            raise FeedFetchError("unpacked feed is empty")
        _atomic_write(destination, raw)
        return destination
    except Exception as exc:
        if has_stale_cache and allow_stale:
            _LOGGER.warning(
                "feed refresh failed; using stale %s cache: %s",
                name,
                type(exc).__name__,
            )
            return destination
        if isinstance(exc, FeedError):
            raise
        if isinstance(exc, (urllib.error.URLError, TimeoutError, OSError)):
            raise FeedFetchError(f"could not refresh {name} feed") from exc
        raise FeedFetchError(f"invalid response from {name} feed") from exc


def load_feed(
    name: str,
    source=None,
    *,
    limit: int | None = None,
    cache_dir: str | os.PathLike | None = None,
) -> list[tuple[str, str]]:
    """Load one named feed from an injected source or the managed cache."""

    if name not in _PARSERS:
        raise ValueError(f"unknown feed: {name}")
    if source is None:
        source = fetch_feed(name, cache_dir=cache_dir)
    records = _PARSERS[name](source, limit=limit)
    if not records:
        raise FeedParseError(f"{name} feed contained no valid URLs")
    return records


def load_threat_blocklists(
    feed_names: Iterable[str] = ("urlhaus", "openphish"),
    *,
    sources: Mapping[str, object] | None = None,
    cache_dir: str | os.PathLike | None = None,
    limit: int | None = None,
    strict: bool = False,
) -> dict[str, set[str]]:
    """Load exact malicious-URL sets suitable for ``ReputationChecker``.

    Benign records are discarded defensively. Provider failures are isolated by
    default so reputation checks continue with the remaining feeds.
    """

    sources = sources or {}
    output: dict[str, set[str]] = {}
    failures = []
    for name in feed_names:
        try:
            records = load_feed(
                name,
                source=sources.get(name),
                limit=limit,
                cache_dir=cache_dir,
            )
            urls = {url for url, label in records if label != "safe"}
            if urls:
                output[name] = urls
        except (FeedError, OSError, ValueError, TypeError):
            failures.append(name)
            _LOGGER.warning("skipping unavailable threat blocklist %s", name)
    if strict and failures:
        raise RealDatasetError(
            f"failed to load threat blocklists: {', '.join(sorted(failures))}"
        )
    return output


def _dataset_key(url: str) -> str:
    """Canonicalize only enough to remove trivial duplicates across providers."""

    parts = urlsplit(url)
    hostname = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    port = parts.port
    default_port = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    return urlunsplit(
        (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
    )


_LABEL_PRIORITY = {"safe": 0, "scam": 1, "data_leak": 2, "phishing": 3, "malware": 4}


def load_real_dataset(
    feed_names: Iterable[str] | None = None,
    *,
    sources: Mapping[str, object] | None = None,
    local_sources: Iterable[object] | None = None,
    cache_dir: str | os.PathLike | None = None,
    max_per_feed: int | None = _DEFAULT_MAX_RECORDS_PER_FEED,
    strict: bool = False,
) -> tuple[list[str], list[str]]:
    """Assemble a de-duplicated real dataset with graceful provider failures.

    ``sources`` injects named feed streams/paths and avoids network access for
    those names. When it is supplied without ``feed_names``, only its keys are
    loaded. In normal operation all configured free feeds are attempted; one
    provider failure does not discard healthy providers. ``strict=True`` makes
    any provider failure fatal for reproducible data-refresh jobs.
    """

    sources = sources or {}
    if feed_names is None:
        names = (
            list(sources)
            if sources
            else [name for name in config.BLOCKLIST_URLS if name in _PARSERS]
        )
    else:
        names = list(feed_names)
    if not names and not local_sources:
        raise RealDatasetError("no real-data sources were selected")

    records_by_key: dict[str, tuple[str, str]] = {}
    ordered_keys: list[str] = []
    failures: dict[str, Exception] = {}

    def add_records(records: Iterable[tuple[str, str]]) -> None:
        for url, label in records:
            key = _dataset_key(url)
            current = records_by_key.get(key)
            if current is None:
                ordered_keys.append(key)
                records_by_key[key] = (url, label)
            elif _LABEL_PRIORITY[label] > _LABEL_PRIORITY[current[1]]:
                # Threat labels win over an accidental benign-list overlap.
                records_by_key[key] = (url, label)

    for name in names:
        try:
            add_records(
                load_feed(
                    name,
                    source=sources.get(name),
                    limit=max_per_feed,
                    cache_dir=cache_dir,
                )
            )
        except (FeedError, OSError, ValueError, TypeError) as exc:
            failures[name] = exc
            _LOGGER.warning(
                "skipping unavailable real-data feed %s: %s", name, type(exc).__name__
            )

    for index, source in enumerate(local_sources or ()):
        source_name = f"local[{index}]"
        try:
            records = parse_labeled_csv(source, limit=None)
            if not records:
                raise FeedParseError("local CSV contained no valid labeled URLs")
            add_records(records)
        except (FeedError, OSError, ValueError, TypeError) as exc:
            failures[source_name] = exc
            _LOGGER.warning(
                "skipping unavailable real-data source %s: %s",
                source_name,
                type(exc).__name__,
            )

    if strict and failures:
        failed_names = ", ".join(sorted(failures))
        raise RealDatasetError(f"failed to load real-data sources: {failed_names}")
    if not records_by_key:
        failed_names = ", ".join(sorted(failures)) or "none"
        raise RealDatasetError(
            f"no usable real records; failed sources: {failed_names}"
        )

    rows = [records_by_key[key] for key in ordered_keys]
    return [url for url, _ in rows], [label for _, label in rows]


def demo():
    urlhaus = io.StringIO(
        "# comment\nhttp://evil.example/a.exe\n"
        '1,"2026-01-01","http://evil.example/b.exe","online"\n'
    )
    openphish = io.StringIO("http://phish.example/login\n")
    tranco = io.StringIO("1,example.com\n")
    urls, labels = load_real_dataset(
        sources={"urlhaus": urlhaus, "openphish": openphish, "tranco": tranco},
    )
    assert len(urls) == 4
    assert {"safe", "phishing", "malware"}.issubset(labels)
    print("real_data_loader: all checks passed")


if __name__ == "__main__":
    demo()
