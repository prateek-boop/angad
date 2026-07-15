"""Bounded, DNS-pinned HTML fetcher for attacker-controlled URLs."""

from __future__ import annotations

from email.message import Message
import time

import requests
import urllib3

import config
from ml_engine.fetch.http_client import (
    FetchTransportError,
    close_response,
    open_response,
)
from ml_engine.fetch.ssrf_guard import SSRFBlocked, validate_url


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}


def _failure(error: str, *, status_code=None, content_type=None) -> dict:
    return {
        "ok": False,
        "status_code": status_code,
        "content_type": content_type,
        "body": None,
        "truncated": False,
        "bytes_read": 0,
        "error": error,
    }


def _content_metadata(raw_value) -> tuple[str | None, str | None, str]:
    if raw_value is None:
        return None, None, "utf-8"
    value = str(raw_value).strip()
    message = Message()
    message["content-type"] = value
    media_type = message.get_content_type().lower()
    charset = message.get_content_charset() or "utf-8"
    return value, media_type, charset


def fetch(url: str, requester=None, resolver=None) -> dict:
    """Fetch one URL without following redirects or executing page content.

    ``requester`` and ``resolver`` are no-network test hooks. The production
    transport connects to a DNS result approved by :func:`validate_url`, caps
    decompressed output, disables redirects, and applies one wall-clock budget.
    """
    deadline = time.monotonic() + config.FETCH_TOTAL_TIMEOUT_S
    try:
        validated = validate_url(url, resolver=resolver)
    except SSRFBlocked as exc:
        return _failure(str(exc))

    response = None
    status_code = None
    raw_content_type = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _failure("fetch deadline exceeded during URL validation")
        response = open_response(
            validated,
            requester=requester,
            timeout_s=remaining,
        )
        status_code = int(response.status_code)
        raw_content_type, media_type, charset = _content_metadata(
            response.headers.get("Content-Type")
        )

        if status_code in _REDIRECT_STATUSES:
            return _failure(
                "unexpected redirect; resolve and validate the chain before fetching HTML",
                status_code=status_code,
                content_type=raw_content_type,
            )
        if media_type is not None and media_type not in _HTML_MEDIA_TYPES:
            return _failure(
                f"unsupported content type: {media_type}",
                status_code=status_code,
                content_type=raw_content_type,
            )

        declared_length = response.headers.get("Content-Length")
        declared_oversize = False
        if declared_length is not None:
            try:
                declared_oversize = int(declared_length) > config.MAX_FETCH_BYTES
            except (TypeError, ValueError):
                pass

        chunks: list[bytes] = []
        bytes_read = 0
        truncated = declared_oversize
        for chunk in response.iter_content(chunk_size=8192):
            if time.monotonic() > deadline:
                return _failure(
                    "fetch deadline exceeded while reading response body",
                    status_code=status_code,
                    content_type=raw_content_type,
                )
            if not chunk:
                continue
            if not isinstance(chunk, bytes):
                raise TypeError("response yielded a non-bytes body chunk")

            remaining = config.MAX_FETCH_BYTES - bytes_read
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                bytes_read += remaining
                truncated = True
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if declared_oversize and bytes_read >= config.MAX_FETCH_BYTES:
                break

        body_bytes = b"".join(chunks)
        try:
            body = body_bytes.decode(charset, errors="replace")
        except LookupError:
            body = body_bytes.decode("utf-8", errors="replace")

        return {
            "ok": True,
            "status_code": status_code,
            "content_type": raw_content_type,
            "body": body,
            "truncated": truncated,
            "bytes_read": bytes_read,
            "error": None,
        }
    except (
        FetchTransportError,
        requests.RequestException,
        urllib3.exceptions.HTTPError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        return _failure(
            str(exc), status_code=status_code, content_type=raw_content_type
        )
    finally:
        if response is not None:
            close_response(response)


def demo() -> None:
    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "text/html; charset=utf-8"}

        def iter_content(self, chunk_size=8192):
            yield b"<html><body>ok</body></html>"

        def close(self):
            pass

    def public_resolver(host, port):
        return [(2, 1, 6, "", ("8.8.8.8", port))]

    result = fetch(
        "https://example.com/",
        requester=lambda *args, **kwargs: FakeResponse(),
        resolver=public_resolver,
    )
    assert result["ok"] is True
    assert "ok" in result["body"]


if __name__ == "__main__":
    demo()
