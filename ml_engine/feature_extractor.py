"""Converts a URL into the 41 engineered risk features. See MODEL_BRAIN.md
sec 5 for the feature index table — order here MUST match that table exactly,
it is part of the system contract.

Domain/subdomain/TLD splitting uses tldextract (not hand-rolled dot-splitting)
because multi-part TLDs like "co.uk" break naive splitting and would corrupt
subdomain_depth, tld_length, excessive_subdomains, and misleading_tld.
"""

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

import tldextract

from config import MODEL_CONFIG
from ml_engine.brands import (
    ACCOUNT_KEYWORDS,
    BANK_KEYWORDS,
    KNOWN_BRANDS,
    LOGIN_KEYWORDS,
    MISLEADING_TLDS,
    SECURE_KEYWORDS,
    SUSPICIOUS_FILE_EXTENSIONS,
    SUSPICIOUS_TLDS,
    UPDATE_KEYWORDS,
    URL_SHORTENER_DOMAINS,
    VERIFY_KEYWORDS,
)

NUM_FEATURES = MODEL_CONFIG["num_features"]

# Use tldextract's bundled Public Suffix List. Feature extraction is on the
# hot inference path and must never depend on a writable home directory or a
# network refresh during process startup.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_VOWELS = set("aeiouAEIOU")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
_STRUCTURAL_CHARS = set(":/.-_?&=%#@~+")
_HEX_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
_NESTED_URL_RE = re.compile(r"(url|redirect|next|dest|continue)=https?", re.IGNORECASE)
# Non-ASCII letters from scripts commonly used in homoglyph attacks against
# Latin-script brand names (Cyrillic, Greek).
_HOMOGLYPH_SCRIPT_RE = re.compile(r"[Ѐ-ӿͰ-Ͽ]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _max_consecutive_consonants(s: str) -> int:
    best = run = 0
    for c in s:
        if c in _CONSONANTS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _brand_impersonation_score(url_lower: str, registered_domain: str) -> float:
    hits = 0
    for brand in KNOWN_BRANDS:
        if brand in url_lower and brand != registered_domain:
            hits += 1
    return min(hits / 3.0, 1.0)  # cap so one URL can't blow the scale


def _random_looking_domain_score(domain_label: str) -> float:
    if len(domain_label) < 4:
        return 0.0
    entropy = _shannon_entropy(domain_label)
    consonant_run = _max_consecutive_consonants(domain_label)
    digit_ratio = _digit_ratio(domain_label)
    score = 0.0
    if entropy > 3.5:
        score += 0.4
    if consonant_run >= 5:
        score += 0.3
    if digit_ratio > 0.3:
        score += 0.3
    return min(score, 1.0)


def _homoglyph_score(hostname: str) -> float:
    matches = _HOMOGLYPH_SCRIPT_RE.findall(hostname)
    has_ascii_letters = any(c.isascii() and c.isalpha() for c in hostname)
    if matches and has_ascii_letters:
        return min(len(matches) / 5.0, 1.0)
    return 0.0


class FeatureExtractor:
    def extract(self, url: str) -> list[float]:
        url_lower = url.lower()
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        hostname = parts.hostname or ""
        path = parts.path or ""
        query = parts.query or ""
        fragment = parts.fragment or ""

        ext = _TLD_EXTRACT(url)
        registered_domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        tld = ext.suffix.lower()
        subdomain_labels = [s for s in subdomain.split(".") if s]

        query_params = parse_qsl(query, keep_blank_values=True)
        path_segments = [s for s in path.split("/") if s]

        port_is_standard = True
        has_port = parts.port is not None
        if has_port:
            port_is_standard = parts.port in (80, 443)

        features = [0.0] * NUM_FEATURES
        features[0] = float(len(url))
        features[1] = float(url.count("."))
        features[2] = float(url.count("-"))
        features[3] = float(url.count("_"))
        features[4] = float(sum(c.isdigit() for c in url))
        features[5] = float(
            sum(1 for c in url if not c.isalnum() and c not in _STRUCTURAL_CHARS)
        )
        features[6] = 1.0 if "@" in url else 0.0
        features[7] = float(len(path_segments))
        features[8] = float(len(query_params))
        features[9] = 1.0 if fragment else 0.0
        features[10] = _shannon_entropy(url)
        features[11] = float(_max_consecutive_consonants(url))
        features[12] = float(len(hostname))
        features[13] = float(len(subdomain_labels))
        features[14] = 1.0 if _is_ip_address(hostname) else 0.0
        features[15] = (
            1.0
            if any(
                hostname == d or hostname.endswith("." + d)
                for d in URL_SHORTENER_DOMAINS
            )
            else 0.0
        )
        features[16] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        features[17] = 1.0 if "xn--" in hostname else 0.0
        features[18] = _digit_ratio(registered_domain)
        features[19] = float(len(tld))
        features[20] = 1.0 if scheme == "https" else 0.0
        features[21] = 1.0 if has_port else 0.0
        features[22] = 1.0 if port_is_standard else 0.0
        features[23] = 1.0 if "//" in path else 0.0
        features[24] = float(len(_HEX_ENCODED_RE.findall(url)))
        features[25] = (
            1.0
            if path.rsplit(".", 1)[-1].lower() in SUSPICIOUS_FILE_EXTENSIONS
            and "." in path
            else 0.0
        )
        features[26] = 1.0 if any(k in url_lower for k in LOGIN_KEYWORDS) else 0.0
        features[27] = 1.0 if any(k in url_lower for k in SECURE_KEYWORDS) else 0.0
        features[28] = 1.0 if any(k in url_lower for k in ACCOUNT_KEYWORDS) else 0.0
        features[29] = 1.0 if any(k in url_lower for k in UPDATE_KEYWORDS) else 0.0
        features[30] = 1.0 if any(k in url_lower for k in VERIFY_KEYWORDS) else 0.0
        features[31] = 1.0 if any(k in url_lower for k in BANK_KEYWORDS) else 0.0
        features[32] = _brand_impersonation_score(url_lower, registered_domain)
        features[33] = 1.0 if _NESTED_URL_RE.search(query) else 0.0
        features[34] = 1.0 if len(subdomain_labels) > 3 else 0.0
        features[35] = _random_looking_domain_score(registered_domain)
        features[36] = 1.0 if any(len(lbl) > 20 for lbl in subdomain_labels) else 0.0
        features[37] = (len(path) / len(url)) if url else 0.0
        features[38] = (
            1.0
            if any(b in subdomain for b in KNOWN_BRANDS)
            and registered_domain not in KNOWN_BRANDS
            else 0.0
        )
        features[39] = 1.0 if tld in MISLEADING_TLDS else 0.0
        features[40] = _homoglyph_score(hostname)

        return features


def demo():
    fx = FeatureExtractor()

    safe = fx.extract("https://www.google.com/search?q=test")
    assert len(safe) == 41
    assert safe[20] == 1.0  # is_https

    phishing = fx.extract("http://paypal.secure-login.verify-account.xyz/login")
    assert phishing[16] == 1.0  # suspicious_tld (.xyz)
    assert phishing[26] == 1.0  # has_login_keyword
    assert phishing[30] == 1.0  # has_verify_keyword
    assert phishing[38] == 1.0  # known_brand_in_subdomain

    ip_url = fx.extract("http://192.168.1.1/admin")
    assert ip_url[14] == 1.0  # is_ip_address

    multi_tld = fx.extract("https://mail.example.co.uk/inbox")
    assert multi_tld[19] == len("co.uk")  # tld_length handles multi-part TLD

    at_symbol = fx.extract("http://real-bank.com@evil.com/")
    assert at_symbol[6] == 1.0  # has_at_symbol

    print("feature_extractor: all checks passed")


if __name__ == "__main__":
    demo()
