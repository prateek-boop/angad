"""SSRF-guarded, optional Playwright screenshot capture for Tier 4.

The browser is an untrusted-content execution boundary. This module keeps an
ephemeral context, disables downloads/service workers/WebSockets, validates
the initial and final URLs, and routes every browser HTTP request through the
same SSRF guard used by Tier 2/3. Host/container network isolation is still
required in production to eliminate DNS-rebinding and browser-exploit risk.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from numbers import Real
from typing import Callable

import config
from ml_engine.fetch.ssrf_guard import SSRFBlocked, check_url


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_USER_AGENT = "ShieldNet/0.1 visual-analyzer (+security-research)"
_CHROMIUM_ARGS = [
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-extensions",
    "--disable-quic",
    "--disable-sync",
    "--dns-prefetch-disable",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--metrics-recording-only",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
]
_BLOCK_ACTIVE_EGRESS_SCRIPT = """
(() => {
  const blocked = class {
    constructor() { throw new DOMException('Blocked by ShieldNet visual sandbox', 'SecurityError'); }
  };
  for (const name of ['WebSocket', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection']) {
    try {
      Object.defineProperty(globalThis, name, {
        value: blocked, configurable: false, enumerable: false, writable: false
      });
    } catch (_) {}
  }
})();
"""


class ScreenshotUnavailable(RuntimeError):
    """Raised when Playwright or its Chromium executable is unavailable."""


class ScreenshotCaptureError(RuntimeError):
    """Raised when Chromium is installed but screenshot capture fails."""


class ScreenshotTimeout(ScreenshotCaptureError):
    """Raised when navigation or rendering exceeds the configured deadline."""


@dataclass(frozen=True)
class _PlaywrightAPI:
    sync_playwright: Callable
    error: type[Exception]
    timeout_error: type[Exception]


def _load_playwright_api() -> _PlaywrightAPI:
    try:
        from playwright.sync_api import Error, TimeoutError, sync_playwright
    except ImportError as exc:
        raise ScreenshotUnavailable(
            "Tier 4 screenshots require Playwright and its Chromium browser; "
            "install both to enable visual analysis"
        ) from exc
    return _PlaywrightAPI(sync_playwright, Error, TimeoutError)


def _timeout_ms(timeout_s: Real | None) -> int:
    selected = config.SCREENSHOT_TIMEOUT_S if timeout_s is None else timeout_s
    if isinstance(selected, bool) or not isinstance(selected, Real):
        raise TypeError("timeout_s must be a positive number")
    if not math.isfinite(float(selected)) or selected <= 0:
        raise ValueError("timeout_s must be a positive finite number")
    return max(1, round(float(selected) * 1000))


def _looks_like_missing_browser(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "executable doesn't exist",
            "executable does not exist",
            "browser executable",
            "playwright install chromium",
            "failed to launch chromium because executable doesn't exist",
        )
    )


def _safe_close(resource) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        # Cleanup must not obscure the navigation/security failure being raised.
        pass


def _capture_with_browser(playwright, url: str, timeout_ms: int) -> bytes:
    browser = context = page = None
    blocked_requests: list[SSRFBlocked] = []

    def guard_route(route) -> None:
        request_url = route.request.url
        try:
            check_url(request_url)
        except SSRFBlocked as exc:
            blocked_requests.append(exc)
            route.abort(error_code="blockedbyclient")
            return
        route.continue_()

    try:
        # Chromium's own sandbox remains enabled: never add --no-sandbox here.
        browser = playwright.chromium.launch(headless=True, args=list(_CHROMIUM_ARGS))
        context = browser.new_context(
            viewport=dict(config.SCREENSHOT_VIEWPORT),
            device_scale_factor=1,
            color_scheme="light",
            reduced_motion="reduce",
            locale="en-US",
            timezone_id="UTC",
            user_agent=_USER_AGENT,
            accept_downloads=False,
            service_workers="block",
        )
        context.clear_permissions()
        context.route("**/*", guard_route)
        context.add_init_script(script=_BLOCK_ACTIVE_EGRESS_SCRIPT)

        # WebSocket handshakes are an otherwise unguarded egress/SSRF path.
        if not hasattr(context, "route_web_socket"):
            raise ScreenshotUnavailable(
                "the installed Playwright version cannot guard WebSocket traffic; "
                "upgrade Playwright before enabling Tier 4"
            )
        context.route_web_socket("**/*", lambda socket: socket.close())

        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        page.set_default_navigation_timeout(timeout_ms)
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("popup", lambda popup: popup.close())

        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception:
            if blocked_requests:
                raise blocked_requests[0]
            raise
        if blocked_requests:
            raise blocked_requests[0]

        final_url = getattr(page, "url", None)
        if final_url:
            check_url(final_url)
        response_url = getattr(response, "url", None)
        if response_url and response_url != final_url:
            check_url(response_url)

        try:
            png = page.screenshot(
                type="png",
                full_page=False,
                animations="disabled",
                caret="hide",
                timeout=timeout_ms,
            )
        except Exception:
            if blocked_requests:
                raise blocked_requests[0]
            raise
        if blocked_requests:
            raise blocked_requests[0]
        if not isinstance(png, (bytes, bytearray)) or not bytes(png).startswith(
            _PNG_SIGNATURE
        ):
            raise ScreenshotCaptureError("browser returned invalid PNG screenshot data")
        return bytes(png)
    finally:
        _safe_close(page)
        _safe_close(context)
        _safe_close(browser)


def capture(url: str, timeout_s: Real | None = None) -> bytes:
    """Capture a guarded 1280x800 PNG screenshot of ``url``.

    ``SSRFBlocked`` is intentionally preserved so callers can distinguish a
    security decision from an unavailable backend or operational failure.
    """
    timeout_ms = _timeout_ms(timeout_s)
    check_url(url)  # Reject unsafe destinations before a browser is launched.
    api = _load_playwright_api()
    try:
        with api.sync_playwright() as playwright:
            return _capture_with_browser(playwright, url, timeout_ms)
    except SSRFBlocked:
        raise
    except api.timeout_error as exc:
        raise ScreenshotTimeout(f"screenshot timed out after {timeout_ms} ms") from exc
    except api.error as exc:
        if _looks_like_missing_browser(exc):
            raise ScreenshotUnavailable(
                "Playwright is installed but Chromium is unavailable; install the "
                "Playwright Chromium browser to enable Tier 4 visual analysis"
            ) from exc
        raise ScreenshotCaptureError(f"browser screenshot failed: {exc}") from exc
    except OSError as exc:
        raise ScreenshotUnavailable(
            f"could not start the Playwright browser: {exc}"
        ) from exc


def demo() -> None:
    try:
        capture("http://127.0.0.1/")
    except SSRFBlocked:
        pass
    else:
        raise AssertionError("loopback URL should be blocked before browser startup")
    print("screenshotter: SSRF preflight check passed")


if __name__ == "__main__":
    demo()
