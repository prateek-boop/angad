"""Small DNS-pinned HTTP transport used by the redirect and HTML fetchers."""

from __future__ import annotations

import socket
import time
from typing import Iterator

import requests
import urllib3
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util import Timeout

import config
from ml_engine.fetch.ssrf_guard import ValidatedURL


USER_AGENT = "ShieldNet/0.2 (+security-research)"
REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
}


class FetchTransportError(RuntimeError):
    """Normalised network failure exposed to the security pipeline."""


class PinnedResponse:
    """Requests-like facade that owns an urllib3 response and its IP pool."""

    def __init__(self, response, pool) -> None:
        self._response = response
        self._pool = pool
        self.status_code = response.status
        self.headers = response.headers

    def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
        yield from self._response.stream(chunk_size, decode_content=True)

    def close(self) -> None:
        try:
            self._response.close()
            self._response.release_conn()
        finally:
            self._pool.close()


def _timeout_for(remaining_s: float) -> Timeout:
    if remaining_s <= 0:
        raise FetchTransportError("request deadline exceeded")
    return Timeout(
        total=remaining_s,
        connect=min(config.FETCH_CONNECT_TIMEOUT_S, remaining_s),
        read=min(config.FETCH_READ_TIMEOUT_S, remaining_s),
    )


def _pinned_request(validated: ValidatedURL, timeout_s: float) -> PinnedResponse:
    """Connect directly to a prevalidated IP while preserving Host and TLS SNI."""
    deadline = time.monotonic() + timeout_s
    failures: list[str] = []

    for ip in validated.resolved_ips:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        pool = None
        try:
            common = {
                "host": ip,
                "port": validated.port,
                "maxsize": 1,
                "block": True,
                "retries": False,
            }
            if validated.scheme == "https":
                pool = HTTPSConnectionPool(
                    **common,
                    cert_reqs="CERT_REQUIRED",
                    assert_hostname=validated.hostname,
                    server_hostname=validated.hostname,
                )
            else:
                pool = HTTPConnectionPool(**common)

            headers = {**REQUEST_HEADERS, "Host": validated.host_header}
            response = pool.request(
                "GET",
                validated.request_target,
                headers=headers,
                redirect=False,
                preload_content=False,
                retries=False,
                timeout=_timeout_for(remaining),
            )
            return PinnedResponse(response, pool)
        except (urllib3.exceptions.HTTPError, OSError, socket.error) as exc:
            failures.append(f"{ip}: {exc}")
            if pool is not None:
                pool.close()

    detail = failures[-1] if failures else "request deadline exceeded"
    raise FetchTransportError(f"request failed: {detail}")


def open_response(
    validated: ValidatedURL,
    *,
    requester=None,
    timeout_s: float,
):
    """Open a non-redirecting streaming response.

    The injectable ``requester`` is solely a no-network test seam. Production
    calls use the pinned transport so the HTTP stack cannot perform a second,
    attacker-controlled DNS lookup after validation.
    """
    if requester is None:
        return _pinned_request(validated, timeout_s)

    timeout = (
        min(config.FETCH_CONNECT_TIMEOUT_S, timeout_s),
        min(config.FETCH_READ_TIMEOUT_S, timeout_s),
    )
    try:
        return requester(
            validated.url,
            allow_redirects=False,
            stream=True,
            timeout=timeout,
            headers=REQUEST_HEADERS.copy(),
        )
    except (requests.RequestException, OSError, urllib3.exceptions.HTTPError) as exc:
        raise FetchTransportError(f"request failed: {exc}") from exc


def close_response(response) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except (OSError, urllib3.exceptions.HTTPError, requests.RequestException):
            pass
