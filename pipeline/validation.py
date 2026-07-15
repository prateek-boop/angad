"""Input validation shared by API, CLI, and the scan orchestrator."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import tldextract

import config

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


class InvalidURL(ValueError):
    pass


def validate_url(url: str, *, network: bool = False) -> str:
    if not isinstance(url, str):
        raise InvalidURL("URL must be a string")
    value = url.strip()
    if not value:
        raise InvalidURL("URL cannot be empty")
    if len(value) > config.MAX_URL_INPUT_LENGTH:
        raise InvalidURL(f"URL exceeds {config.MAX_URL_INPUT_LENGTH} characters")
    if _CONTROL_RE.search(value):
        raise InvalidURL("URL contains control characters")

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise InvalidURL(f"invalid URL authority: {exc}") from exc
    if parts.scheme.lower() not in config.ALLOWED_SCHEMES:
        raise InvalidURL("URL scheme must be http or https")
    if not parts.hostname:
        raise InvalidURL("URL must include a hostname")
    try:
        ascii_hostname = parts.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidURL("hostname is not valid IDNA") from exc
    if len(ascii_hostname) > 253 or any(
        len(label) > 63 for label in ascii_hostname.split(".")
    ):
        raise InvalidURL("hostname exceeds DNS length limits")
    if network and (parts.username is not None or parts.password is not None):
        raise InvalidURL("live analysis does not fetch URLs containing credentials")
    if network:
        effective_port = port or (443 if parts.scheme.lower() == "https" else 80)
        if effective_port not in config.ALLOWED_FETCH_PORTS:
            raise InvalidURL(f"live analysis does not allow port {effective_port}")
    return value


def registered_domain(url: str) -> str:
    extracted = _TLD_EXTRACT(url)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return extracted.domain.lower()
