"""Extract bounded phishing signals from fetched HTML without executing it."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import tldextract

from ml_engine.brands import KNOWN_BRANDS

_MAX_REFERENCES = 4096
_MAX_TITLE_CHARS = 512
_UNSAFE_REFERENCE_RE = re.compile(r"[\x00-\x20\x7f\\]")
_META_REFRESH_URL_RE = re.compile(
    r"(?:^|;)\s*url\s*=\s*(['\"]?)(.*?)\1\s*$", re.IGNORECASE
)
_TLD_EXTRACT = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def _normalise_hostname(hostname: str) -> str:
    value = hostname.rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def _registered_domain(hostname: str) -> str:
    hostname = _normalise_hostname(hostname)
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    extracted = _TLD_EXTRACT(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return hostname


def _registrable_label(hostname: str) -> str:
    domain = _registered_domain(hostname)
    return domain.split(".", 1)[0].replace("-", "").lower()


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_actions: list[str] = []
        self.script_srcs: list[str] = []
        self.iframe_srcs: list[str] = []
        self.favicon_hrefs: list[str] = []
        self.meta_refresh_targets: list[str] = []
        self.base_href: str | None = None
        self.form_count = 0
        self.password_field_count = 0
        self.hidden_input_count = 0
        self.script_count = 0
        self.iframe_count = 0
        self.title_parts: list[str] = []
        self._title_chars = 0
        self._in_title = False

    @staticmethod
    def _attrs(attrs) -> dict[str, str]:
        return {str(key).lower(): value or "" for key, value in attrs if key}

    def handle_starttag(self, tag, attrs) -> None:
        tag = tag.lower()
        attr = self._attrs(attrs)
        if tag == "form":
            self.form_count += 1
            if "action" in attr and len(self.form_actions) < _MAX_REFERENCES:
                self.form_actions.append(attr["action"])
        elif tag == "input":
            input_type = attr.get("type", "text").strip().lower()
            self.password_field_count += int(input_type == "password")
            self.hidden_input_count += int(input_type == "hidden")
        elif tag == "script":
            self.script_count += 1
            if attr.get("src") and len(self.script_srcs) < _MAX_REFERENCES:
                self.script_srcs.append(attr["src"])
        elif tag == "iframe":
            self.iframe_count += 1
            if attr.get("src") and len(self.iframe_srcs) < _MAX_REFERENCES:
                self.iframe_srcs.append(attr["src"])
        elif tag == "base" and self.base_href is None and attr.get("href"):
            self.base_href = attr["href"]
        elif tag == "link" and "icon" in attr.get("rel", "").lower().split():
            if attr.get("href") and len(self.favicon_hrefs) < _MAX_REFERENCES:
                self.favicon_hrefs.append(attr["href"])
        elif tag == "meta" and attr.get("http-equiv", "").strip().lower() == "refresh":
            match = _META_REFRESH_URL_RE.search(attr.get("content", ""))
            if match and len(self.meta_refresh_targets) < _MAX_REFERENCES:
                self.meta_refresh_targets.append(match.group(2).strip())
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data) -> None:
        if not self._in_title or self._title_chars >= _MAX_TITLE_CHARS:
            return
        part = data[: _MAX_TITLE_CHARS - self._title_chars]
        self.title_parts.append(part)
        self._title_chars += len(part)


def _resolve_reference(base_url: str, reference: str) -> tuple[str | None, bool]:
    """Return an HTTP(S) hostname and whether the reference uses an unsafe scheme."""
    if _UNSAFE_REFERENCE_RE.search(reference):
        return None, True
    try:
        resolved = urljoin(base_url, reference.strip())
        parts = urlsplit(resolved)
    except (TypeError, ValueError):
        return None, True
    if parts.scheme.lower() not in {"http", "https"}:
        return None, True
    return parts.hostname, False


def _external_count(references: list[str], base_url: str, page_domain: str) -> int:
    count = 0
    for reference in references:
        hostname, unsafe = _resolve_reference(base_url, reference)
        if not unsafe and hostname and _registered_domain(hostname) != page_domain:
            count += 1
    return count


def _unsafe_count(references: list[str], base_url: str) -> int:
    return sum(_resolve_reference(base_url, reference)[1] for reference in references)


def _mentions_brand(title: str, brand: str) -> bool:
    pattern = rf"(?<![a-z0-9]){re.escape(brand.lower())}(?![a-z0-9])"
    return re.search(pattern, title.lower()) is not None


def extract(html: str, page_url: str) -> dict:
    """Return structural and brand-mismatch signals for a fetched HTML page."""
    if not isinstance(html, str) or not isinstance(page_url, str):
        raise TypeError("html and page_url must be strings")

    parser = _PageParser()
    parser.feed(html)
    parser.close()

    page_parts = urlsplit(page_url)
    page_hostname = page_parts.hostname or ""
    page_domain = _registered_domain(page_hostname)
    effective_base = page_url
    base_domain_mismatch = False
    unsafe_base_href = False
    if parser.base_href:
        base_hostname, base_unsafe = _resolve_reference(page_url, parser.base_href)
        unsafe_base_href = base_unsafe
        if not base_unsafe:
            effective_base = urljoin(page_url, parser.base_href)
            base_domain_mismatch = bool(
                base_hostname and _registered_domain(base_hostname) != page_domain
            )

    form_domain_mismatch = False
    unsafe_form_action = False
    for action in parser.form_actions:
        if not action.strip():
            continue
        action_hostname, unsafe = _resolve_reference(effective_base, action)
        unsafe_form_action = unsafe_form_action or unsafe
        if action_hostname and _registered_domain(action_hostname) != page_domain:
            form_domain_mismatch = True

    refresh_domain_mismatch = False
    unsafe_meta_refresh = False
    for target in parser.meta_refresh_targets:
        refresh_hostname, unsafe = _resolve_reference(effective_base, target)
        unsafe_meta_refresh = unsafe_meta_refresh or unsafe
        if refresh_hostname and _registered_domain(refresh_hostname) != page_domain:
            refresh_domain_mismatch = True

    title = "".join(parser.title_parts).strip()
    page_brand = _registrable_label(page_hostname)
    title_brand_mismatch = any(
        _mentions_brand(title, brand) and brand.replace("-", "").lower() != page_brand
        for brand in KNOWN_BRANDS
    )

    return {
        "form_domain_mismatch": form_domain_mismatch,
        "unsafe_form_action": unsafe_form_action,
        "form_count": parser.form_count,
        "has_password_field": parser.password_field_count > 0,
        "password_field_count": parser.password_field_count,
        "hidden_input_count": parser.hidden_input_count,
        "script_count": parser.script_count,
        "external_script_count": _external_count(
            parser.script_srcs, effective_base, page_domain
        ),
        "unsafe_script_source_count": _unsafe_count(parser.script_srcs, effective_base),
        "iframe_count": parser.iframe_count,
        "external_iframe_count": _external_count(
            parser.iframe_srcs, effective_base, page_domain
        ),
        "unsafe_iframe_source_count": _unsafe_count(parser.iframe_srcs, effective_base),
        "base_domain_mismatch": base_domain_mismatch,
        "unsafe_base_href": unsafe_base_href,
        "external_favicon": _external_count(
            parser.favicon_hrefs, effective_base, page_domain
        )
        > 0,
        "has_meta_refresh": bool(parser.meta_refresh_targets),
        "meta_refresh_domain_mismatch": refresh_domain_mismatch,
        "unsafe_meta_refresh": unsafe_meta_refresh,
        "title": title,
        "title_brand_mismatch": title_brand_mismatch,
    }


def demo() -> None:
    html = """
    <html><head><title>PayPal - Secure Login</title></head>
    <body><form action="https://collector.example.net/harvest">
      <input type="hidden"><input type="password">
    </form><script src="https://cdn.example.net/a.js"></script>
    <iframe src="/local"></iframe></body></html>
    """
    result = extract(html, "https://fake-login.example.com/account")
    assert result["form_domain_mismatch"] is True
    assert result["has_password_field"] is True
    assert result["hidden_input_count"] == 1
    assert result["external_script_count"] == 1
    assert result["external_iframe_count"] == 0
    assert result["title_brand_mismatch"] is True


if __name__ == "__main__":
    demo()
