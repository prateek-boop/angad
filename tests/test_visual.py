"""Tier 4 tests use generated images and fake browser objects: no network."""

from __future__ import annotations

import io
import json

import pytest

from ml_engine.fetch.ssrf_guard import SSRFBlocked
from ml_engine.visual import perceptual_hash, screenshotter
from ml_engine.visual.reference_store import ReferenceStore, ReferenceStoreError


try:
    from PIL import Image, ImageDraw
    import imagehash as _imagehash  # noqa: F401
except ImportError:
    Image = ImageDraw = None


requires_hash_backend = pytest.mark.skipif(
    Image is None, reason="Pillow and ImageHash are optional Tier 4 dependencies"
)


def _pattern_png(inverted: bool = False) -> bytes:
    background, foreground = (
        ((0, 0, 0), (255, 255, 255)) if inverted else ((255, 255, 255), (0, 0, 0))
    )
    image = Image.new("RGB", (96, 64), background)
    draw = ImageDraw.Draw(image)
    draw.rectangle((8, 8, 42, 54), fill=foreground)
    draw.ellipse((55, 12, 88, 45), fill=foreground)
    draw.line((50, 58, 92, 52), fill=foreground, width=3)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


@requires_hash_backend
def test_perceptual_hash_is_deterministic_and_validates_input():
    raw = _pattern_png()
    first = perceptual_hash.hash_image_bytes(raw)
    second = perceptual_hash.hash_image_bytes(memoryview(raw))

    assert perceptual_hash.serialize_hash(first) == perceptual_hash.serialize_hash(
        second
    )
    assert perceptual_hash.hash_distance(first, second) == 0
    assert perceptual_hash.is_visual_match(first, second, threshold=0)
    assert len(perceptual_hash.serialize_hash(first)) == 16

    with pytest.raises(perceptual_hash.InvalidImageError):
        perceptual_hash.hash_image_bytes(b"not an image")
    with pytest.raises(ValueError):
        perceptual_hash.parse_hash("not-a-hash")
    with pytest.raises(ValueError):
        perceptual_hash.is_visual_match(first, second, threshold=65)


@requires_hash_backend
def test_reference_store_round_trip_matching_and_deterministic_tie(tmp_path):
    path = tmp_path / "references.json"
    store = ReferenceStore(path)
    store.add("Zeta.Example.", "ffffffffffffffff")
    store.add("alpha.example", "ffffffffffffffff")
    store.add("other.example", "0000000000000000")
    store.save()

    reloaded = ReferenceStore(path)
    assert reloaded.domains == ("alpha.example", "other.example", "zeta.example")
    assert reloaded.nearest_match("fffffffffffffffe", threshold=1) == (
        "alpha.example",
        1,
    )
    assert reloaded.nearest_match("f0f0f0f0f0f0f0f0", threshold=0) is None
    assert reloaded.remove("ALPHA.EXAMPLE") is True
    assert reloaded.remove("alpha.example") is False

    stored_json = json.loads(path.read_text(encoding="utf-8"))
    assert list(stored_json) == sorted(stored_json)


@requires_hash_backend
def test_reference_store_rejects_malformed_content_and_domains(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        '{"https://paypal.com/login": "ffffffffffffffff"}', encoding="utf-8"
    )
    with pytest.raises(ReferenceStoreError, match="invalid visual reference entry"):
        ReferenceStore(path)

    path.write_text('{"paypal.com": "xyz"}', encoding="utf-8")
    with pytest.raises(ReferenceStoreError, match="invalid visual reference entry"):
        ReferenceStore(path)


class _FakePlaywrightError(Exception):
    pass


class _FakePlaywrightTimeout(_FakePlaywrightError):
    pass


class _FakeRequest:
    def __init__(self, url):
        self.url = url


class _FakeRoute:
    def __init__(self, url, events):
        self.request = _FakeRequest(url)
        self.events = events

    def continue_(self):
        self.events.append(("continue", self.request.url))

    def abort(self, error_code=None):
        self.events.append(("abort", self.request.url, error_code))


class _FakePage:
    def __init__(self, context, events, subresource=None):
        self.context = context
        self.events = events
        self.subresource = subresource
        self.url = "about:blank"

    def set_default_timeout(self, timeout):
        self.events.append(("default_timeout", timeout))

    def set_default_navigation_timeout(self, timeout):
        self.events.append(("navigation_timeout", timeout))

    def on(self, event, handler):
        self.events.append(("page_handler", event))

    def goto(self, url, **kwargs):
        self.events.append(("goto", url, kwargs))
        self.context.route_handler(_FakeRoute(url, self.events))
        if self.subresource:
            self.context.route_handler(_FakeRoute(self.subresource, self.events))
            if any(
                isinstance(event, tuple) and event[:2] == ("abort", self.subresource)
                for event in self.events
            ):
                raise _FakePlaywrightError("navigation aborted by route handler")
        self.url = url
        return type("Response", (), {"url": url})()

    def screenshot(self, **kwargs):
        self.events.append(("screenshot", kwargs))
        return b"\x89PNG\r\n\x1a\nmocked"

    def close(self):
        self.events.append("page.close")


class _FakeContext:
    def __init__(self, events, subresource=None):
        self.events = events
        self.subresource = subresource
        self.route_handler = None

    def clear_permissions(self):
        self.events.append("permissions.clear")

    def route(self, pattern, handler):
        self.events.append(("route", pattern))
        self.route_handler = handler

    def add_init_script(self, script):
        self.events.append(("init_script", script))

    def route_web_socket(self, pattern, handler):
        self.events.append(("websocket.route", pattern))

    def new_page(self):
        self.events.append("page.new")
        return _FakePage(self, self.events, self.subresource)

    def close(self):
        self.events.append("context.close")


class _FakeBrowser:
    def __init__(self, events, subresource=None):
        self.events = events
        self.subresource = subresource

    def new_context(self, **kwargs):
        self.events.append(("context.new", kwargs))
        return _FakeContext(self.events, self.subresource)

    def close(self):
        self.events.append("browser.close")


class _FakeChromium:
    def __init__(self, events, subresource=None):
        self.events = events
        self.subresource = subresource

    def launch(self, **kwargs):
        self.events.append(("browser.launch", kwargs))
        return _FakeBrowser(self.events, self.subresource)


class _FakeManager:
    def __init__(self, events, subresource=None):
        self.events = events
        self.playwright = type("FakePlaywright", (), {})()
        self.playwright.chromium = _FakeChromium(events, subresource)

    def __enter__(self):
        self.events.append("playwright.enter")
        return self.playwright

    def __exit__(self, exc_type, exc, traceback):
        self.events.append("playwright.exit")


def _fake_api(events, subresource=None):
    return screenshotter._PlaywrightAPI(
        sync_playwright=lambda: _FakeManager(events, subresource),
        error=_FakePlaywrightError,
        timeout_error=_FakePlaywrightTimeout,
    )


def test_screenshot_capture_has_guarded_mocked_lifecycle(monkeypatch):
    events = []
    checked = []

    def allow(url):
        checked.append(url)
        return "public.example"

    monkeypatch.setattr(screenshotter, "check_url", allow)
    monkeypatch.setattr(
        screenshotter, "_load_playwright_api", lambda: _fake_api(events)
    )

    png = screenshotter.capture("https://public.example/login", timeout_s=2.5)

    assert png.startswith(b"\x89PNG")
    assert checked.count("https://public.example/login") >= 3
    launch = next(
        event
        for event in events
        if isinstance(event, tuple) and event[0] == "browser.launch"
    )
    assert "--no-sandbox" not in launch[1]["args"]
    context = next(
        event
        for event in events
        if isinstance(event, tuple) and event[0] == "context.new"
    )
    assert context[1]["accept_downloads"] is False
    assert context[1]["service_workers"] == "block"
    assert any(
        isinstance(event, tuple) and event[0] == "init_script" for event in events
    )
    assert ("default_timeout", 2500) in events
    assert "page.close" in events
    assert "context.close" in events
    assert "browser.close" in events
    assert events[-1] == "playwright.exit"


def test_screenshot_blocked_request_never_captures_and_still_closes(monkeypatch):
    events = []
    internal = "http://169.254.169.254/latest/meta-data"

    def guard(url):
        if url == internal:
            raise SSRFBlocked("blocked metadata endpoint")
        return "public.example"

    monkeypatch.setattr(screenshotter, "check_url", guard)
    monkeypatch.setattr(
        screenshotter,
        "_load_playwright_api",
        lambda: _fake_api(events, subresource=internal),
    )

    with pytest.raises(SSRFBlocked, match="metadata"):
        screenshotter.capture("https://public.example/")

    assert not any(
        isinstance(event, tuple) and event[0] == "screenshot" for event in events
    )
    assert ("abort", internal, "blockedbyclient") in events
    assert "page.close" in events
    assert "context.close" in events
    assert "browser.close" in events


def test_screenshot_preflight_blocks_before_loading_browser(monkeypatch):
    def blocked(url):
        raise SSRFBlocked("loopback blocked")

    monkeypatch.setattr(screenshotter, "check_url", blocked)
    monkeypatch.setattr(
        screenshotter,
        "_load_playwright_api",
        lambda: (_ for _ in ()).throw(AssertionError("browser loader must not run")),
    )

    with pytest.raises(SSRFBlocked, match="loopback"):
        screenshotter.capture("http://127.0.0.1/")


def test_screenshot_reports_missing_optional_backend(monkeypatch):
    monkeypatch.setattr(screenshotter, "check_url", lambda url: "public.example")

    def unavailable():
        raise screenshotter.ScreenshotUnavailable("Playwright is absent")

    monkeypatch.setattr(screenshotter, "_load_playwright_api", unavailable)
    with pytest.raises(screenshotter.ScreenshotUnavailable, match="absent"):
        screenshotter.capture("https://public.example/")
