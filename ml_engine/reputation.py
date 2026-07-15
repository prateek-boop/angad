"""Tier 1 domain reputation signals with bounded, SSRF-aware lookups.

The checker intentionally does not fetch the submitted web page. RDAP is queried
through the fixed public ``rdap.org`` endpoint, DNS is resolved with a bounded
worker, and a TLS handshake is attempted only against a pinned public IP address.
Network results are best-effort and cached in SQLite; a missing signal is never
treated as proof that a URL is malicious.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

import tldextract

import config

_UA = "ShieldNet/0.1 (+security-research)"
RDAP_URL = "https://rdap.org/domain/{domain}"
_TLD_EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home", ".lan")
_LOCAL_NAMES = {"localhost", "local", "internal", "home", "lan"}
_LOOKUP_SLOTS = threading.BoundedSemaphore(8)


class LookupTimeout(TimeoutError):
    """Raised when a best-effort reputation lookup exceeds its time budget."""


def _bounded_call(function: Callable, timeout_s: float, *args):
    """Run a potentially blocking stdlib lookup without blocking the request.

    CPython's ``socket.getaddrinfo`` has no portable per-call timeout. A bounded
    number of daemon workers contains both latency and resource use if the system
    resolver becomes unresponsive. The underlying OS call may finish later, but
    at most eight such calls can remain outstanding in this process.
    """

    timeout_s = max(0.001, float(timeout_s))
    started = time.monotonic()
    if not _LOOKUP_SLOTS.acquire(timeout=timeout_s):
        raise LookupTimeout("lookup worker capacity exhausted")

    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result_queue.put((True, function(*args)))
        except (
            Exception
        ) as exc:  # the caller turns individual failures into missing signals
            result_queue.put((False, exc))
        finally:
            _LOOKUP_SLOTS.release()

    worker = threading.Thread(target=run, name="shieldnet-reputation", daemon=True)
    worker.start()
    remaining = max(0.0, timeout_s - (time.monotonic() - started))
    worker.join(remaining)
    if worker.is_alive():
        raise LookupTimeout(f"lookup exceeded {timeout_s:g}s")

    succeeded, value = result_queue.get_nowait()
    if succeeded:
        return value
    raise value


def _default_rdap_fetch(domain: str) -> dict:
    encoded_domain = urllib.parse.quote(domain, safe=".-")
    request = urllib.request.Request(
        RDAP_URL.format(domain=encoded_domain),
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": _UA,
        },
    )
    with urllib.request.urlopen(request, timeout=config.WHOIS_TIMEOUT_S) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("RDAP response exceeds 2 MiB")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("RDAP response is not an object")
    return parsed


def _default_dns_resolve(hostname: str):
    return socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)


def _default_tls_connect(
    hostname: str, addresses: Iterable[str], port: int = 443
) -> dict:
    """Return a peer certificate while pinning the connection to a vetted IP."""

    context = ssl.create_default_context()
    last_error: Exception | None = None
    for address in addresses:
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(address).version == 6
            else socket.AF_INET
        )
        raw_socket = socket.socket(family, socket.SOCK_STREAM)
        raw_socket.settimeout(config.TLS_TIMEOUT_S)
        try:
            raw_socket.connect((address, port))
            with context.wrap_socket(
                raw_socket, server_hostname=hostname
            ) as tls_socket:
                return tls_socket.getpeercert()
        except Exception as exc:
            last_error = exc
            raw_socket.close()
    if last_error is not None:
        raise last_error
    raise OSError("hostname has no public address")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_rdap_registration_age_days(
    rdap: dict,
    now: datetime | None = None,
) -> float | None:
    now = now or _utc_now()
    dates = []
    for event in rdap.get("events", []):
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        if action not in {"registration", "registered"}:
            continue
        parsed = _parse_datetime(event.get("eventDate"))
        if parsed is not None:
            dates.append(parsed)
    if not dates:
        return None
    registered = min(dates)
    return max(0.0, (now - registered).total_seconds() / 86400)


def _parse_rdap_expiry_days(rdap: dict, now: datetime | None = None) -> float | None:
    now = now or _utc_now()
    expirations = []
    for event in rdap.get("events", []):
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).lower() not in {"expiration", "expiry"}:
            continue
        parsed = _parse_datetime(event.get("eventDate"))
        if parsed is not None:
            expirations.append(parsed)
    if not expirations:
        return None
    return (max(expirations) - now).total_seconds() / 86400


def _parse_rdap_registrar(rdap: dict) -> str | None:
    for entity in rdap.get("entities", []):
        if not isinstance(entity, dict):
            continue
        roles = {str(role).lower() for role in entity.get("roles", [])}
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            values = {}
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4:
                    values[str(field[0]).lower()] = field[3]
            name = values.get("org") or values.get("fn")
            if isinstance(name, list):
                name = " ".join(str(item) for item in name)
            if name:
                return str(name)
        if entity.get("handle"):
            return str(entity["handle"])
    return None


def _parse_rdap_nameservers(rdap: dict) -> list[str]:
    nameservers = []
    for entry in rdap.get("nameservers", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("ldhName") or entry.get("unicodeName")
        if isinstance(name, str) and name.strip():
            normalized = name.strip().rstrip(".").lower()
            if normalized not in nameservers:
                nameservers.append(normalized)
        if len(nameservers) >= 16:
            break
    return nameservers


def _parse_tls_age_days(cert: dict, now: datetime | None = None) -> float | None:
    not_before = cert.get("notBefore")
    if not isinstance(not_before, str):
        return None
    try:
        issued = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_before), timezone.utc
        )
    except (TypeError, ValueError, OverflowError):
        return None
    return max(0.0, ((now or _utc_now()) - issued).total_seconds() / 86400)


def _parse_tls_expiry_days(cert: dict, now: datetime | None = None) -> float | None:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return None
    try:
        expires = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after), timezone.utc
        )
    except (TypeError, ValueError, OverflowError):
        return None
    return (expires - (now or _utc_now())).total_seconds() / 86400


def _tls_issuer(cert: dict) -> str | None:
    values: dict[str, str] = {}
    for relative_name in cert.get("issuer", ()):
        for item in relative_name:
            if isinstance(item, tuple) and len(item) == 2:
                values[str(item[0])] = str(item[1])
    return values.get("organizationName") or values.get("commonName")


def _target(url: str) -> tuple[str, str] | None:
    if not isinstance(url, str) or not url.strip() or "\x00" in url:
        return None
    candidate = url.strip()
    try:
        parts = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        if parts.scheme and parts.scheme.lower() not in config.ALLOWED_SCHEMES:
            return None
        hostname = (parts.hostname or "").rstrip(".").lower()
        if not hostname or any(character.isspace() for character in hostname):
            return None
        hostname = hostname.encode("idna").decode("ascii")
        if len(hostname) > 253:
            return None
        ipaddress.ip_address(hostname)
        return hostname, hostname
    except ValueError:
        pass
    except UnicodeError:
        return None

    labels = hostname.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    extracted = _TLD_EXTRACT(hostname)
    registered = extracted.top_domain_under_public_suffix
    if not registered:
        registered = ".".join(labels[-2:]) if len(labels) > 1 else hostname
    return hostname, registered.lower()


def _is_local_hostname(hostname: str) -> bool:
    if hostname in _LOCAL_NAMES or hostname.endswith(_LOCAL_SUFFIXES):
        return True
    try:
        return not ipaddress.ip_address(hostname).is_global
    except ValueError:
        return False


def _addresses(records) -> tuple[list[str], list[str]]:
    public: list[str] = []
    non_public: list[str] = []
    for record in records or ():
        candidate = record if isinstance(record, str) else None
        if isinstance(record, tuple) and len(record) >= 5:
            sockaddr = record[4]
            if isinstance(sockaddr, tuple) and sockaddr:
                candidate = sockaddr[0]
        if not candidate:
            continue
        try:
            address = str(ipaddress.ip_address(candidate.split("%", 1)[0]))
        except ValueError:
            continue
        target = public if ipaddress.ip_address(address).is_global else non_public
        if address not in target:
            target.append(address)
    return public, non_public


def _normalize_url(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip())
        if parts.scheme.lower() not in config.ALLOWED_SCHEMES or not parts.hostname:
            return None
        hostname = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parts.port
    except (AttributeError, UnicodeError, ValueError):
        return None
    default_port = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


class _SQLiteCache:
    def __init__(self, path: str | None, ttl_s: int, clock: Callable[[], float]):
        self.path = path
        self.ttl_s = max(0, int(ttl_s))
        self.clock = clock
        self._initialized = False
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        if self.path is None:
            raise sqlite3.OperationalError("cache disabled")
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=2)
        if not self._initialized:
            with self._lock:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS reputation_cache ("
                    "cache_key TEXT PRIMARY KEY, fetched_at REAL NOT NULL, "
                    "expires_at REAL NOT NULL, payload TEXT NOT NULL)"
                )
                connection.commit()
                self._initialized = True
        return connection

    def get(self, key: str) -> dict | None:
        if self.path is None or self.ttl_s == 0:
            return None
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT payload FROM reputation_cache WHERE cache_key = ? AND expires_at > ?",
                    (key, self.clock()),
                ).fetchone()
            if row is None:
                return None
            value = json.loads(row[0])
            return value if isinstance(value, dict) else None
        except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            return None

    def put(self, key: str, payload: dict) -> None:
        if self.path is None or self.ttl_s == 0:
            return
        now = self.clock()
        # Cache failed/negative lookups briefly so outages do not poison signals
        # for the full positive TTL.
        degraded = not payload.get("dns_resolves") or bool(payload.get("lookup_errors"))
        ttl = min(self.ttl_s, 300) if degraded else self.ttl_s
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO reputation_cache(cache_key, fetched_at, expires_at, payload) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET "
                    "fetched_at=excluded.fetched_at, expires_at=excluded.expires_at, "
                    "payload=excluded.payload",
                    (key, now, now + ttl, json.dumps(payload, separators=(",", ":"))),
                )
        except (OSError, sqlite3.Error, TypeError, ValueError):
            return


class ReputationChecker:
    """Collect free/no-key domain signals without fetching attacker content.

    Lookup callables are injectable for deterministic tests. Custom TLS callables
    receive only ``hostname`` for backwards compatibility; the built-in TLS path
    additionally receives and pins vetted public DNS addresses.
    """

    def __init__(
        self,
        rdap_fetch=None,
        dns_resolve=None,
        tls_connect=None,
        blocklists: dict[str, set] | None = None,
        *,
        cache_path: str | None = config.REPUTATION_CACHE_DB,
        cache_ttl_s: int = config.REPUTATION_CACHE_TTL_S,
        rdap_timeout_s: float = config.WHOIS_TIMEOUT_S,
        dns_timeout_s: float = config.DNS_TIMEOUT_S,
        tls_timeout_s: float = config.TLS_TIMEOUT_S,
        clock: Callable[[], float] = time.time,
        now: Callable[[], datetime] = _utc_now,
    ):
        self.rdap_fetch = rdap_fetch or _default_rdap_fetch
        self.dns_resolve = dns_resolve or _default_dns_resolve
        self.tls_connect = tls_connect or _default_tls_connect
        self._uses_default_tls = tls_connect is None
        self.blocklists = blocklists if blocklists is not None else {}
        self._blocklist_index = {
            feed_name: {
                normalized
                for entry in entries
                for entry_url in [
                    entry[0] if isinstance(entry, tuple) and entry else entry
                ]
                for normalized in [
                    _normalize_url(entry_url) if isinstance(entry_url, str) else None
                ]
                if normalized is not None
            }
            for feed_name, entries in self.blocklists.items()
        }
        self.rdap_timeout_s = rdap_timeout_s
        self.dns_timeout_s = dns_timeout_s
        self.tls_timeout_s = tls_timeout_s
        self.now = now
        self.cache = _SQLiteCache(cache_path, cache_ttl_s, clock)

    @staticmethod
    def _empty_result(hostname: str = "", registered_domain: str = "") -> dict:
        return {
            "hostname": hostname,
            "registered_domain": registered_domain,
            "domain_age_days": None,
            "domain_expires_in_days": None,
            "registrar": None,
            "nameservers": [],
            "dns_resolves": False,
            "dns_addresses": [],
            "has_non_public_address": False,
            "tls_issuer": None,
            "tls_age_days": None,
            "tls_expires_in_days": None,
            "tls_expired": None,
            "blocklist_hit": None,
            "lookup_errors": {},
            "cache_hit": False,
        }

    def _blocklist_hit(self, url: str) -> str | None:
        candidate = _normalize_url(url)
        if candidate is None:
            return None
        for feed_name, entries in self._blocklist_index.items():
            if candidate in entries:
                return feed_name
        return None

    def _network_check(self, hostname: str, registered_domain: str) -> dict:
        result = self._empty_result(hostname, registered_domain)
        errors = result["lookup_errors"]

        if _is_local_hostname(hostname):
            result["has_non_public_address"] = True
            errors["target"] = "non_public_hostname"
            return result

        public_addresses: list[str] = []
        try:
            records = _bounded_call(self.dns_resolve, self.dns_timeout_s, hostname)
            public_addresses, non_public_addresses = _addresses(records)
            result["dns_resolves"] = bool(public_addresses or non_public_addresses)
            result["dns_addresses"] = public_addresses
            result["has_non_public_address"] = bool(non_public_addresses)
            if non_public_addresses:
                errors["target"] = "dns_contains_non_public_address"
        except LookupTimeout:
            errors["dns"] = "timeout"
        except Exception:
            errors["dns"] = "lookup_failed"

        if registered_domain and not _is_local_hostname(registered_domain):
            try:
                rdap = _bounded_call(
                    self.rdap_fetch, self.rdap_timeout_s, registered_domain
                )
                result["domain_age_days"] = _parse_rdap_registration_age_days(
                    rdap, self.now()
                )
                result["domain_expires_in_days"] = _parse_rdap_expiry_days(
                    rdap, self.now()
                )
                result["registrar"] = _parse_rdap_registrar(rdap)
                result["nameservers"] = _parse_rdap_nameservers(rdap)
            except LookupTimeout:
                errors["rdap"] = "timeout"
            except Exception:
                errors["rdap"] = "lookup_failed"

        # A mixed public/private answer is treated as unsafe because following it
        # would permit DNS rebinding. Only the built-in connector is used for real
        # traffic; custom connectors are test/embedding seams.
        if public_addresses and not result["has_non_public_address"]:
            try:
                if self._uses_default_tls:
                    cert = _bounded_call(
                        self.tls_connect,
                        self.tls_timeout_s,
                        hostname,
                        public_addresses,
                    )
                else:
                    cert = _bounded_call(self.tls_connect, self.tls_timeout_s, hostname)
                result["tls_issuer"] = _tls_issuer(cert)
                result["tls_age_days"] = _parse_tls_age_days(cert, self.now())
                result["tls_expires_in_days"] = _parse_tls_expiry_days(cert, self.now())
                if result["tls_expires_in_days"] is not None:
                    result["tls_expired"] = result["tls_expires_in_days"] < 0
            except LookupTimeout:
                errors["tls"] = "timeout"
            except Exception:
                errors["tls"] = "handshake_failed"

        return result

    def check(self, url: str) -> dict:
        parsed_target = _target(url)
        if parsed_target is None:
            result = self._empty_result()
            result["lookup_errors"]["target"] = "invalid_url"
            return result
        hostname, registered_domain = parsed_target

        result = self.cache.get(hostname)
        if result is None:
            result = self._network_check(hostname, registered_domain)
            self.cache.put(hostname, result)
        else:
            # Defensive defaults allow cache schema additions without migrations.
            result = {**self._empty_result(hostname, registered_domain), **result}
            result["cache_hit"] = True

        result["blocklist_hit"] = self._blocklist_hit(url)
        return result

    def check_blocklists(self, url: str) -> dict:
        """Return cached exact-feed evidence without performing network lookups."""
        parsed_target = _target(url)
        hostname, registered_domain = parsed_target or ("", "")
        result = self._empty_result(hostname, registered_domain)
        result["blocklist_hit"] = self._blocklist_hit(url)
        result["lookup_errors"]["network"] = "disabled"
        return result


def demo():
    fake_rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-07-14T00:00:00Z"}
        ],
    }
    fake_cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "notBefore": "Jun  1 00:00:00 2026 GMT",
    }
    checker = ReputationChecker(
        rdap_fetch=lambda domain: fake_rdap,
        dns_resolve=lambda host: ["8.8.8.8"],
        tls_connect=lambda host: fake_cert,
        blocklists={"urlhaus": {"http://evil.example/payload.exe"}},
        cache_path=None,
    )
    result = checker.check("https://brand-new-domain.example/login")
    assert result["dns_resolves"] is True
    assert result["tls_issuer"] == "Let's Encrypt"
    assert (
        checker.check("http://evil.example/payload.exe")["blocklist_hit"] == "urlhaus"
    )
    assert ReputationChecker(cache_path=None).check("http://127.0.0.1")[
        "has_non_public_address"
    ]
    print("reputation: all checks passed")


if __name__ == "__main__":
    demo()
