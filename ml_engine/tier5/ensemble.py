"""Evidence-level ensemble for URL, reputation, page, and visual signals.

This module deliberately does not claim that hand-authored evidence weights
are a learned production model. They provide a conservative, inspectable
fusion policy until enough labeled multimodal feedback exists to train and
validate a replacement meta-classifier.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import idna
import numpy as np
import tldextract

import config

_EPSILON = 1e-7
_CLASS_INDEX = {name: index for index, name in enumerate(config.THREAT_CLASSES)}
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_HOMOGLYPHS = {
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "к": "k",
    "о": "o", "р": "p", "ѕ": "s", "у": "y", "х": "x", "ë": "e",
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

_PIRACY_GRAYWARE_NETWORKS = {
    "cineby",
    "netmirror",
    "fmovies",
    "soap2day",
    "123movies",
    "lookmovie",
    "flixtor",
    "solarmovie",
    "putlocker",
    "hurawatch",
    "bflix",
    "streamtape",
    "vidcloud",
    "myflixer",
    "goku",
    "gomovies",
    "cuevana",
    "pelisplus",
    "repelis",
    "onionplay",
    # Torrent and piracy warez trackers
    "thepiratebay",
    "piratebay",
    "1337x",
    "yts",
    "rarbg",
    "torrentgalaxy",
    "nyaa",
    "rutracker",
    "eztv",
    "kickasstorrents",
    "katcr",
    "limetorrents",
    "torrentday",
    "zamunda",
    "torlock",
    "torrentz",
}

_MULTI_TENANT_HOSTS = {
    "pages.dev", "workers.dev", "vercel.app", "web.app", "firebaseapp.com",
    "github.io", "gitlab.io", "render.com", "railway.app", "fly.dev",
    "ngrok-free.app", "loca.lt", "onrender.com", "netlify.app",
}

_TRUSTED_STREAMING_DOMAINS = {
    "netflix.com",
    "hulu.com",
    "disneyplus.com",
    "hbomax.com",
    "max.com",
    "primevideo.com",
    "amazon.com",
    "apple.com",
    "youtube.com",
    "twitch.tv",
    "vimeo.com",
    "peacocktv.com",
    "paramountplus.com",
    "crunchyroll.com",
    "cinemark.com",
    "cineplex.com",
    "streamlabs.com",
    "livestream.com",
    "roku.com",
    "tubitv.com",
    "pluto.tv",
    "dailymotion.com",
    "imdb.com",
    "metacritic.com",
    "rottentomatoes.com",
    "criterionchannel.com",
    "mubi.com",
}

_DISPOSABLE_GRAYWARE_TLDS = {
    "to", "vip", "cc", "ru", "is", "su", "pw", "top", "xyz", "lat", "icu",
    "buzz", "tech", "app", "link", "click", "cx", "ws", "tv", "re", "gs",
    "ph", "ms", "st", "cfd", "sbs", "lol", "party", "mx",
}

_STREAMING_STEM_RE = re.compile(
    r"^(cine|flix|stream|watch|movie|mirror|video|series|anime|torrent)[a-z0-9\-]*$",
    re.IGNORECASE,
)

_DATA_HARVEST_HOST_KEYWORDS = {
    "mobiledetect",
    "deviceleak",
    "imeitrack",
    "phonecheck",
    "apptelemetry",
    "trackdevice",
    "telemetry-collect",
    "analytics-forward",
    "telemetry-harvest",
    "stats-collector",
    "telemetry-tracker",
    "device-check",
    "device-collect",
    "device-sync",
    "analytics-sync",
}

_DATA_HARVEST_PARAM_RE = re.compile(
    r"(?:^|[?&])(imei|imsi|android_id|device_id|mac_address|sim_serial|iccid|"
    r"serial_number|hardware_id|phone_number|msisdn|wifi_bssid|ssid|clipboard|"
    r"contacts|call_log|sms_dump|sms_body|keystrokes|screen_capture|location_data|"
    r"telemetry_data|system_info|gps|location_coords)=",
    re.IGNORECASE,
)

_EXECUTABLE_EXTS = {".apk", ".exe", ".scr", ".bat", ".vbs", ".ps1", ".msi", ".dll", ".dmg"}

_SCAM_LURE_RE = re.compile(
    r"(claim-free|winner|vip-access|free-gift|prize-reward|giveaway|bonus-spin|survey-reward|congratulations)",
    re.IGNORECASE,
)

_KNOWN_IMPERSONATED_BRANDS = {
    "netflix", "paypal", "google", "apple", "amazon", "facebook", "instagram", "microsoft", "bank"
}


@dataclass(slots=True)
class EvidenceContribution:
    source: str
    reason: str
    logit_delta: dict[str, float] = field(default_factory=dict)
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "reason": self.reason,
            "severity": self.severity,
            "logit_delta": self.logit_delta,
        }


@dataclass(slots=True)
class FusionResult:
    probabilities: dict[str, float]
    contributions: list[EvidenceContribution]
    policy_blocked: bool = False
    policy_reason: str | None = None

    @property
    def category(self) -> str:
        return max(self.probabilities, key=self.probabilities.get)

    @property
    def confidence(self) -> float:
        return float(self.probabilities[self.category])

    @property
    def risk_score(self) -> float:
        return float(1.0 - self.probabilities["safe"])


class EvidenceEnsemble:
    """Fuse independent evidence by adding explainable log-probability deltas."""

    def _base_vector(self, probabilities: dict[str, float]) -> np.ndarray:
        if set(probabilities) != set(config.THREAT_CLASSES):
            raise ValueError(
                "base probabilities do not match the ShieldNet class contract"
            )
        vector = np.asarray(
            [probabilities[name] for name in config.THREAT_CLASSES], dtype=np.float64
        )
        if np.any(~np.isfinite(vector)) or np.any(vector < 0) or vector.sum() <= 0:
            raise ValueError(
                "base probabilities must be finite, non-negative, and non-empty"
            )
        return vector / vector.sum()

    @staticmethod
    def _add(
        contributions: list[EvidenceContribution],
        source: str,
        reason: str,
        delta: dict[str, float],
        severity: str,
    ) -> None:
        contributions.append(EvidenceContribution(source, reason, delta, severity))

    def _analyze_url_intelligence(
        self, url: str, contributions: list[EvidenceContribution]
    ) -> None:
        try:
            parts = urllib.parse.urlsplit(url)
            host = (parts.hostname or "").lower()
            path = parts.path.lower()
            query = parts.query.lower()
        except Exception:
            return

        if not host:
            return

        extracted = _TLD_EXTRACT(url)
        domain_label = extracted.domain.lower() if extracted.domain else ""
        tld = extracted.suffix.lower() if extracted.suffix else ""
        reg_domain = f"{domain_label}.{tld}" if tld else domain_label

        # Decode IDNA / Punycode to handle internationalized / homoglyph domains
        decoded_host = host
        is_punycode = "xn--" in host
        if is_punycode:
            try:
                decoded_host = idna.decode(host)
            except Exception:
                decoded_host = host

        # Extract normalized labels (stripping hyphens and resolving leetspeak/homoglyphs)
        decoded_ext = _TLD_EXTRACT(f"https://{decoded_host}")
        d_label = decoded_ext.domain.lower() if decoded_ext.domain else domain_label
        raw_label = "".join(ch for ch in d_label if ch.isalnum())
        leet_label = "".join(_HOMOGLYPHS.get(ch, ch) for ch in d_label if ch.isalnum())

        # Subdomain extraction
        subdomains = (
            host[: -len(reg_domain) - 1]
            if reg_domain and host.endswith(f".{reg_domain}")
            else ""
        )

        q_params = urllib.parse.parse_qs(query)

        # 1. Base64 encoded telemetry payloads in query parameters
        for b64_key in ("payload", "data", "report", "log", "json", "d", "b64", "body"):
            if b64_key in q_params:
                for raw_val in q_params[b64_key]:
                    if len(raw_val) >= 12:
                        try:
                            padded = raw_val + "=" * ((4 - len(raw_val) % 4) % 4)
                            b_dec = base64.b64decode(padded, validate=True)
                            s_dec = b_dec.decode("utf-8", errors="ignore").lower()
                            if any(
                                k in s_dec
                                for k in (
                                    "imei", "imsi", "device_id", "android_id",
                                    "sim_serial", "hardware_id", "gps", "location"
                                )
                            ):
                                self._add(
                                    contributions,
                                    "heuristic_intelligence",
                                    (
                                        "Query payload contains base64-encoded unauthorized "
                                        "device telemetry."
                                    ),
                                    {
                                        "safe": -9.0, "phishing": -6.0,
                                        "scam": -4.0, "data_leak": 18.0
                                    },
                                    "critical",
                                )
                                break
                        except Exception:
                            pass

        # 2. Open redirect cloaking detection
        for r_key in ("url", "target", "dest", "destination", "redirect", "goto", "link", "next"):
            if r_key in q_params:
                for target in q_params[r_key]:
                    target_clean = urllib.parse.unquote(target).strip()
                    if target_clean.startswith(("http://", "https://")):
                        try:
                            t_parts = urllib.parse.urlsplit(target_clean)
                            t_host = (t_parts.hostname or "").lower()
                            t_ext = _TLD_EXTRACT(target_clean)
                            t_label = t_ext.domain.lower() if t_ext.domain else ""
                            t_leet = "".join(
                                _HOMOGLYPHS.get(c, c) for c in t_label if c.isalnum()
                            )
                            if (
                                any(net in t_host for net in _PIRACY_GRAYWARE_NETWORKS)
                                or t_label in _PIRACY_GRAYWARE_NETWORKS
                                or t_leet in _PIRACY_GRAYWARE_NETWORKS
                            ):
                                self._add(
                                    contributions,
                                    "heuristic_intelligence",
                                    (
                                        f"URL query contains open redirect cloaking target "
                                        f"to grayware network: {t_host}"
                                    ),
                                    {"safe": -8.0, "scam": 8.0, "malware": 4.0},
                                    "high",
                                )
                                break
                        except Exception:
                            pass

        # 3. Telemetry / data-harvesting endpoints
        is_telemetry_host = any(k in host for k in _DATA_HARVEST_HOST_KEYWORDS)
        is_telemetry_sub = any(k in subdomains for k in _DATA_HARVEST_HOST_KEYWORDS)
        has_telemetry_param = bool(_DATA_HARVEST_PARAM_RE.search(query or path))
        if is_telemetry_host or is_telemetry_sub or has_telemetry_param:
            self._add(
                contributions,
                "heuristic_intelligence",
                (
                    "URL endpoint pattern matches unauthorized device telemetry "
                    "/ data-harvesting signature."
                ),
                {"safe": -9.0, "phishing": -6.0, "scam": -4.0, "data_leak": 18.0},
                "critical",
            )

        # 4. Executable / APK payloads from untrusted sources
        has_executable_ext = any(path.endswith(ext) for ext in _EXECUTABLE_EXTS)
        has_double_ext = any(
            f"{ext}." in path for ext in (".apk", ".exe", ".msi", ".scr")
        )
        is_dropper_keyword = any(
            k in path
            for k in ("player-update", "flash-update", "codec-pack", "download-player")
        )
        if has_executable_ext or has_double_ext or is_dropper_keyword:
            if reg_domain not in _TRUSTED_STREAMING_DOMAINS:
                self._add(
                    contributions,
                    "heuristic_intelligence",
                    (
                        "URL serves an executable or application installer payload "
                        "from an untrusted domain."
                    ),
                    {"safe": -9.0, "phishing": -5.0, "malware": 18.0},
                    "critical",
                )

        # 5. Fraudulent prize / scam lure keywords
        if _SCAM_LURE_RE.search(path or query):
            self._add(
                contributions,
                "heuristic_intelligence",
                "URL contains fraudulent prize lure, VIP reward, or scam lure keywords.",
                {"safe": -9.0, "phishing": -5.0, "scam": 18.0},
                "critical",
            )

        # 6. Brand impersonation / credential portal
        if subdomains:
            has_brand = any(brand in subdomains for brand in _KNOWN_IMPERSONATED_BRANDS)
            has_auth_intent = any(
                w in subdomains
                for w in ("login", "verify", "account", "secure", "auth", "portal")
            )
            if (
                has_brand
                and has_auth_intent
                and not any(brand in reg_domain for brand in _KNOWN_IMPERSONATED_BRANDS)
            ):
                self._add(
                    contributions,
                    "heuristic_intelligence",
                    (
                        f"Subdomain '{subdomains}' impersonates a brand/login portal "
                        "on an unauthorized host."
                    ),
                    {"safe": -9.0, "scam": -5.0, "phishing": 18.0},
                    "critical",
                )

        # 7. Punycode / IDN obfuscation on disposable/grayware TLDs
        if is_punycode and tld in _DISPOSABLE_GRAYWARE_TLDS:
            self._add(
                contributions,
                "heuristic_intelligence",
                f"Domain '{host}' uses punycode/IDN obfuscation on a disposable TLD.",
                {"safe": -8.0, "scam": 8.0, "malware": 4.0},
                "high",
            )

        # 8. Legitimate trusted domains boost
        if reg_domain in _TRUSTED_STREAMING_DOMAINS:
            self._add(
                contributions,
                "reputation",
                f"Domain '{reg_domain}' is a verified legitimate platform domain.",
                {"safe": 3.5, "phishing": -3.0},
                "info",
            )
            return

        # 9. Unauthorized streaming / piracy grayware distribution networks
        is_known_grayware = (
            raw_label in _PIRACY_GRAYWARE_NETWORKS
            or leet_label in _PIRACY_GRAYWARE_NETWORKS
            or any(net in host for net in _PIRACY_GRAYWARE_NETWORKS)
            or any(net in raw_label for net in _PIRACY_GRAYWARE_NETWORKS)
            or any(net in leet_label for net in _PIRACY_GRAYWARE_NETWORKS)
        )
        is_streaming_pattern = (
            bool(_STREAMING_STEM_RE.match(raw_label))
            or bool(_STREAMING_STEM_RE.match(leet_label))
        ) and (
            tld in _DISPOSABLE_GRAYWARE_TLDS
            or "stream" in host
            or "cine" in host
            or "flix" in host
        )

        if is_known_grayware or is_streaming_pattern:
            self._add(
                contributions,
                "heuristic_intelligence",
                (
                    f"Domain '{host}' matches unauthorized streaming / grayware piracy "
                    "clone network signature."
                ),
                {"safe": -8.0, "scam": 8.0, "malware": 4.0},
                "high",
            )

    def fuse(
        self,
        base_probabilities: dict[str, float],
        *,
        reputation: dict | None = None,
        redirects: dict | None = None,
        html: dict | None = None,
        visual: dict | None = None,
        url: str | None = None,
    ) -> FusionResult:
        base = self._base_vector(base_probabilities)
        contributions: list[EvidenceContribution] = []
        policy_blocked = False
        policy_reason = None

        if url:
            self._analyze_url_intelligence(url, contributions)

        reputation = reputation or {}
        feed = reputation.get("blocklist_hit")
        if feed:
            feed_name = str(feed).lower()
            target_class = "malware" if "urlhaus" in feed_name else "phishing"
            self._add(
                contributions,
                "reputation",
                f"Exact URL match in the {feed} threat feed.",
                {"safe": -9.0, target_class: 9.0},
                "critical",
            )

        age = reputation.get("domain_age_days")
        if isinstance(age, (int, float)) and age >= 0:
            if age < 2:
                self._add(
                    contributions,
                    "reputation",
                    "Domain was registered less than two days ago.",
                    {"safe": -0.8, "phishing": 0.7, "scam": 0.5},
                    "medium",
                )
            elif age < 14:
                self._add(
                    contributions,
                    "reputation",
                    "Domain was registered less than two weeks ago.",
                    {"safe": -0.35, "phishing": 0.3, "scam": 0.2},
                    "low",
                )
            elif age >= 365:
                self._add(
                    contributions,
                    "reputation",
                    "Domain has a long-standing registration history.",
                    {"safe": 0.35},
                    "info",
                )

        if reputation.get("tls_expired") is True:
            self._add(
                contributions,
                "reputation",
                "The site's TLS certificate is expired.",
                {"safe": -0.5, "phishing": 0.35, "scam": 0.2},
                "medium",
            )
        elif reputation.get("tls_issuer"):
            self._add(
                contributions,
                "reputation",
                "TLS certificate is valid and issued by a recognized CA.",
                {"safe": 0.25},
                "info",
            )

        redirects = redirects or {}
        if redirects.get("blocked"):
            policy_blocked = True
            policy_reason = (
                redirects.get("block_reason")
                or "Redirect target violated the fetch policy."
            )
            self._add(
                contributions,
                "redirect",
                f"Redirect analysis stopped: {policy_reason}",
                {},
                "critical",
            )
        chain = redirects.get("chain") or []
        if redirects.get("domain_changed") and len(chain) >= 2:
            self._add(
                contributions,
                "redirect",
                "Redirect chain crosses to a different registered domain.",
                {"safe": -0.25, "phishing": 0.25},
                "low",
            )
        if len(chain) >= 4:
            self._add(
                contributions,
                "redirect",
                "URL uses an unusually long redirect chain.",
                {"safe": -0.4, "phishing": 0.3, "malware": 0.2},
                "medium",
            )
        elif not redirects.get("blocked") and len(chain) == 1:
            self._add(
                contributions,
                "redirect",
                "URL does not redirect; the final destination is the submitted URL.",
                {"safe": 0.15},
                "info",
            )

        html = html or {}
        password = html.get("has_password_field") is True
        form_mismatch = html.get("form_domain_mismatch") is True
        brand_mismatch = html.get("title_brand_mismatch") is True
        if password and form_mismatch:
            self._add(
                contributions,
                "html",
                "Password form submits to a different registered domain.",
                {"safe": -3.0, "phishing": 3.8},
                "critical",
            )
        elif form_mismatch:
            self._add(
                contributions,
                "html",
                "Form submits to a different registered domain.",
                {"safe": -1.0, "phishing": 1.2},
                "high",
            )
        if password and brand_mismatch:
            self._add(
                contributions,
                "html",
                "Login page title names a brand that does not match the page domain.",
                {"safe": -1.8, "phishing": 2.2},
                "high",
            )
        elif brand_mismatch:
            self._add(
                contributions,
                "html",
                "Page title names a brand that does not match the page domain.",
                {"safe": -0.5, "phishing": 0.6},
                "medium",
            )
        if int(html.get("external_iframe_count") or 0) >= 3:
            self._add(
                contributions,
                "html",
                "Page embeds several cross-domain frames.",
                {"safe": -0.25, "phishing": 0.2, "malware": 0.15},
                "low",
            )

        visual = visual or {}
        matched_brand = visual.get("matched_brand") or visual.get("brand_domain")
        domain_matches = visual.get("domain_matches")
        if matched_brand and domain_matches is False:
            self._add(
                contributions,
                "visual",
                f"Page closely matches the {matched_brand} visual reference on another domain.",
                {"safe": -4.0, "phishing": 4.8},
                "critical",
            )
        elif matched_brand and domain_matches is True:
            self._add(
                contributions,
                "visual",
                f"Page visually matches the {matched_brand} reference on the expected domain.",
                {"safe": 1.0},
                "info",
            )

        logits = np.log(np.clip(base, _EPSILON, 1.0))
        for contribution in contributions:
            for class_name, delta in contribution.logit_delta.items():
                logits[_CLASS_INDEX[class_name]] += float(delta)
        logits -= logits.max()
        fused = np.exp(logits)
        fused /= fused.sum()

        return FusionResult(
            probabilities={
                name: float(fused[index])
                for index, name in enumerate(config.THREAT_CLASSES)
            },
            contributions=contributions,
            policy_blocked=policy_blocked,
            policy_reason=policy_reason,
        )
