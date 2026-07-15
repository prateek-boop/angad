"""Resolve redirects one request at a time across the SSRF trust boundary."""

from __future__ import annotations

import time
from urllib.parse import urljoin

import config
from ml_engine.fetch.http_client import (
    FetchTransportError,
    close_response,
    open_response,
)
from ml_engine.fetch.ssrf_guard import SSRFBlocked, ValidatedURL, validate_url


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _result(
    *,
    chain: list[str],
    final_url: str,
    initial_hostname: str | None,
    final_hostname: str | None,
    redirect_count: int,
    https_downgrade: bool,
    blocked: bool,
    block_reason: str | None,
    status_code: int | None,
) -> dict:
    return {
        "chain": chain,
        "final_url": final_url,
        "domain_changed": bool(
            initial_hostname and final_hostname and initial_hostname != final_hostname
        ),
        "redirect_count": redirect_count,
        "https_downgrade": https_downgrade,
        "status_code": status_code,
        "blocked": blocked,
        "block_reason": block_reason,
    }


def resolve_chain(url: str, requester=None, resolver=None) -> dict:
    """Follow at most ``MAX_REDIRECTS`` redirects with a single time budget.

    Each target is resolved, range-checked, and (for production requests)
    connected through its approved IP. Responses are streamed and immediately
    closed, so resolving a chain never buffers page bodies.
    """
    chain: list[str] = []
    seen: set[str] = set()
    current = url
    pending_validation: ValidatedURL | None = None
    initial_hostname: str | None = None
    final_hostname: str | None = None
    redirect_count = 0
    https_downgrade = False
    status_code: int | None = None
    deadline = time.monotonic() + config.FETCH_TOTAL_TIMEOUT_S

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _result(
                chain=chain,
                final_url=current,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason="redirect resolution deadline exceeded",
                status_code=status_code,
            )

        if pending_validation is None:
            try:
                validated = validate_url(current, resolver=resolver)
            except SSRFBlocked as exc:
                return _result(
                    chain=chain,
                    final_url=current,
                    initial_hostname=initial_hostname,
                    final_hostname=final_hostname,
                    redirect_count=redirect_count,
                    https_downgrade=https_downgrade,
                    blocked=True,
                    block_reason=str(exc),
                    status_code=status_code,
                )
        else:
            validated = pending_validation
            pending_validation = None

        if initial_hostname is None:
            initial_hostname = validated.hostname
        final_hostname = validated.hostname

        if validated.url in seen:
            return _result(
                chain=chain,
                final_url=validated.url,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason="redirect loop detected",
                status_code=status_code,
            )
        seen.add(validated.url)
        chain.append(validated.url)

        response = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchTransportError("redirect resolution deadline exceeded")
            response = open_response(
                validated,
                requester=requester,
                timeout_s=remaining,
            )
            status_code = int(response.status_code)
            location = response.headers.get("Location")
        except (FetchTransportError, ValueError, TypeError) as exc:
            return _result(
                chain=chain,
                final_url=validated.url,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason=str(exc),
                status_code=status_code,
            )
        finally:
            if response is not None:
                close_response(response)

        if status_code not in _REDIRECT_STATUSES or location is None:
            return _result(
                chain=chain,
                final_url=validated.url,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=False,
                block_reason=None,
                status_code=status_code,
            )

        if not isinstance(location, str) or not location:
            return _result(
                chain=chain,
                final_url=validated.url,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason="redirect has an invalid Location header",
                status_code=status_code,
            )
        if redirect_count >= config.MAX_REDIRECTS:
            return _result(
                chain=chain,
                final_url=validated.url,
                initial_hostname=initial_hostname,
                final_hostname=final_hostname,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason=f"exceeded {config.MAX_REDIRECTS} redirect hops",
                status_code=status_code,
            )

        next_url = urljoin(validated.url, location)
        redirect_count += 1
        try:
            next_validated = validate_url(next_url, resolver=resolver)
        except SSRFBlocked as exc:
            return _result(
                chain=chain,
                final_url=next_url,
                initial_hostname=initial_hostname,
                final_hostname=None,
                redirect_count=redirect_count,
                https_downgrade=https_downgrade,
                blocked=True,
                block_reason=str(exc),
                status_code=status_code,
            )

        https_downgrade = https_downgrade or (
            validated.scheme == "https" and next_validated.scheme == "http"
        )
        current = next_validated.url
        pending_validation = next_validated


def demo() -> None:
    class FakeResponse:
        def __init__(self, status_code, headers=None):
            self.status_code = status_code
            self.headers = headers or {}

        def close(self):
            pass

    def public_resolver(host, port):
        return [(2, 1, 6, "", ("8.8.8.8", port))]

    responses = iter(
        [
            FakeResponse(301, {"Location": "https://destination.example/page"}),
            FakeResponse(200),
        ]
    )
    result = resolve_chain(
        "https://short.example/a",
        requester=lambda *args, **kwargs: next(responses),
        resolver=public_resolver,
    )
    assert result["blocked"] is False
    assert result["redirect_count"] == 1
    assert result["domain_changed"] is True


if __name__ == "__main__":
    demo()
