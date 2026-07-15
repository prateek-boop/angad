"""Strict URL and DNS validation for attacker-controlled fetch targets.

The validator is intentionally fail-closed. Call :func:`validate_url` before
opening a socket, then connect to one of the returned IP addresses rather than
resolving the hostname a second time. Redirect targets require a fresh call.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import queue
import re
import socket
import threading
from urllib.parse import SplitResult, urlsplit, urlunsplit

import config


_MAX_URL_LENGTH = 8192
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_DNS_LABEL_RE = re.compile(r"[a-z0-9-]+", re.IGNORECASE)
_AMBIGUOUS_NUMERIC_HOST_RE = re.compile(
    r"(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+))*",
    re.IGNORECASE,
)
_DEFAULT_PORTS = {"http": 80, "https": 443}
_WELL_KNOWN_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_DNS_LOOKUP_SLOTS = threading.BoundedSemaphore(16)
_BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
}
_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".cluster.local",
)


class SSRFBlocked(ValueError):
    """Raised when a target cannot safely cross the network boundary."""


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    """A parsed URL and the public IP addresses approved for its next request."""

    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]
    request_target: str
    host_header: str


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Only globally routable addresses are valid outbound fetch targets."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _is_blocked_ip(ip.ipv4_mapped)
    if ip.version == 6 and ip.sixtofour is not None and _is_blocked_ip(ip.sixtofour):
        return True
    if ip.version == 6 and ip.teredo is not None:
        server, client = ip.teredo
        if _is_blocked_ip(server) or _is_blocked_ip(client):
            return True
    if ip.version == 6 and ip in _WELL_KNOWN_NAT64:
        embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if _is_blocked_ip(embedded):
            return True
    return (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _normalise_hostname(raw_hostname: str) -> str:
    if "%" in raw_hostname:
        raise SSRFBlocked("IPv6 zone identifiers are not allowed")

    candidate = raw_hostname.rstrip(".")
    if not candidate:
        raise SSRFBlocked("URL has no hostname")

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SSRFBlocked("hostname is not valid IDNA") from exc

    labels = hostname.split(".")
    if len(hostname) > 253 or any(not label or len(label) > 63 for label in labels):
        raise SSRFBlocked("hostname has invalid DNS label lengths")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise SSRFBlocked("hostname contains an invalid DNS label")
    if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise SSRFBlocked("hostname contains invalid DNS characters")
    if len(labels) == 1:
        raise SSRFBlocked("single-label hostnames are not allowed")
    if _AMBIGUOUS_NUMERIC_HOST_RE.fullmatch(hostname):
        raise SSRFBlocked("ambiguous numeric host notation is not allowed")
    if hostname in _BLOCKED_HOSTS or hostname.endswith(_BLOCKED_HOST_SUFFIXES):
        raise SSRFBlocked(f"local or metadata hostname is blocked: {hostname}")
    return hostname


def resolve_and_check(
    hostname: str,
    resolver=None,
    *,
    port: int | None = None,
) -> list[str]:
    """Resolve ``hostname`` and require every result to be globally routable.

    Rejecting a mixed public/private answer prevents an attacker from relying on
    address-selection differences later in the HTTP stack. ``resolver`` is a
    two-argument ``getaddrinfo``-compatible test hook.
    """
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if _is_blocked_ip(literal):
            raise SSRFBlocked(f"target is in a blocked address range: {literal}")
        return [str(literal)]

    if resolver is None:
        addrinfo = _bounded_system_resolve(hostname, port)
    else:
        try:
            addrinfo = resolver(hostname, port)
        except (OSError, UnicodeError, ValueError) as exc:
            raise SSRFBlocked(f"could not resolve host: {hostname}") from exc

    ips: list[str] = []
    for result in addrinfo:
        try:
            family, _socktype, _proto, _canonname, sockaddr = result
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            ip = ipaddress.ip_address(sockaddr[0])
        except (IndexError, TypeError, ValueError) as exc:
            raise SSRFBlocked(
                f"resolver returned an invalid address for: {hostname}"
            ) from exc
        if _is_blocked_ip(ip):
            # Do not expose an internal address learned from split-horizon DNS
            # through an API error response.
            raise SSRFBlocked(f"{hostname} resolves to a blocked address range")
        value = str(ip)
        if value not in ips:
            ips.append(value)

    if not ips:
        raise SSRFBlocked(f"{hostname} resolved to no usable addresses")
    return ips


def _bounded_system_resolve(hostname: str, port: int | None):
    """Put a portable deadline and concurrency cap around ``getaddrinfo``."""
    timeout_s = max(0.001, float(config.DNS_TIMEOUT_S))
    if not _DNS_LOOKUP_SLOTS.acquire(timeout=timeout_s):
        raise SSRFBlocked("DNS resolver capacity exhausted")

    outcome: queue.Queue = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            outcome.put((True, socket.getaddrinfo(hostname, port)))
        except Exception as exc:  # socket resolver failures vary by platform
            outcome.put((False, exc))
        finally:
            _DNS_LOOKUP_SLOTS.release()

    try:
        threading.Thread(target=run, name="shieldnet-dns", daemon=True).start()
    except Exception as exc:
        _DNS_LOOKUP_SLOTS.release()
        raise SSRFBlocked("could not start DNS resolver") from exc

    try:
        ok, value = outcome.get(timeout=timeout_s)
    except queue.Empty as exc:
        raise SSRFBlocked(f"DNS resolution timed out for: {hostname}") from exc
    if not ok:
        raise SSRFBlocked(f"could not resolve host: {hostname}") from value
    return value


def _parse_url(url: str) -> tuple[SplitResult, str, int]:
    if not isinstance(url, str) or not url:
        raise SSRFBlocked("URL must be a non-empty string")
    if len(url) > _MAX_URL_LENGTH:
        raise SSRFBlocked(f"URL exceeds {_MAX_URL_LENGTH} characters")
    if _CONTROL_OR_SPACE_RE.search(url) or "\\" in url:
        raise SSRFBlocked("URL contains whitespace, control characters, or backslashes")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SSRFBlocked("URL authority is malformed") from exc

    scheme = parts.scheme.lower()
    if scheme not in config.ALLOWED_SCHEMES or scheme not in _DEFAULT_PORTS:
        raise SSRFBlocked(f"disallowed scheme: {parts.scheme!r}")
    if not parts.netloc or not parts.hostname:
        raise SSRFBlocked("URL has no hostname")
    if parts.username is not None or parts.password is not None:
        raise SSRFBlocked("credentials in URLs are not allowed")

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise SSRFBlocked("URL has an invalid port") from exc
    if parts.netloc.endswith(":"):
        raise SSRFBlocked("URL has an empty port")

    port = _DEFAULT_PORTS[scheme] if explicit_port is None else explicit_port
    if port != _DEFAULT_PORTS[scheme]:
        raise SSRFBlocked(f"port {port} is not allowed for {scheme}")
    return parts, scheme, port


def validate_url(url: str, resolver=None) -> ValidatedURL:
    """Validate syntax and DNS, returning data suitable for a pinned request."""
    parts, scheme, port = _parse_url(url)
    hostname = _normalise_hostname(parts.hostname or "")
    resolved_ips = tuple(resolve_and_check(hostname, resolver=resolver, port=port))

    is_ipv6 = ":" in hostname
    authority = f"[{hostname}]" if is_ipv6 else hostname
    host_header = authority
    request_target = parts.path or "/"
    if parts.query:
        request_target = f"{request_target}?{parts.query}"

    # Fragments are client-side only. Removing them gives redirect-loop checks a
    # stable representation and ensures they never enter an HTTP request target.
    normalised_url = urlunsplit((scheme, authority, parts.path or "/", parts.query, ""))
    return ValidatedURL(
        url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=resolved_ips,
        request_target=request_target,
        host_header=host_header,
    )


def check_url(url: str, resolver=None) -> str:
    """Compatibility wrapper returning the approved, IDNA-normalised hostname."""
    return validate_url(url, resolver=resolver).hostname


def demo() -> None:
    def public_resolver(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    assert check_url("https://example.com/", resolver=public_resolver) == "example.com"
    for target in (
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "https://user:pass@example.com/",
        "http://example.com:22/",
        "file:///etc/passwd",
    ):
        try:
            check_url(target, resolver=public_resolver)
            raise AssertionError(f"expected SSRFBlocked for {target}")
        except SSRFBlocked:
            pass


if __name__ == "__main__":
    demo()
