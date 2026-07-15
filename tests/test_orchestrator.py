import config
from ml_engine.tier5.calibration import TemperatureCalibrator
from pipeline.orchestrator import ScanOrchestrator


class FakeModel:
    def __init__(self, probabilities=None):
        self.probabilities = probabilities or {
            "safe": 0.8,
            "phishing": 0.05,
            "malware": 0.05,
            "data_leak": 0.05,
            "scam": 0.05,
        }

    def predict_with_confidence(self, url_ids, features):
        category = max(self.probabilities, key=self.probabilities.get)
        return [
            {
                "category": category,
                "confidence": self.probabilities[category],
                "probabilities": self.probabilities,
            }
        ]


class FakeReputation:
    def __init__(self, result=None):
        self.result = result or {"domain_age_days": 1000, "blocklist_hit": None}

    def check(self, url):
        return self.result


def _orchestrator(**kwargs):
    return ScanOrchestrator(
        model=kwargs.pop("model", FakeModel()),
        calibrator=TemperatureCalibrator(),
        reputation_checker=kwargs.pop("reputation_checker", FakeReputation()),
        persist=False,
        **kwargs,
    )


def test_tier0_scan_preserves_contract():
    result = _orchestrator().scan("https://example.com/path", depth="tier0")
    assert result["category"] == "safe"
    assert result["decision"] == "allow"
    assert result["blocked"] is False
    assert set(result["probabilities"]) == set(config.THREAT_CLASSES)
    assert result["tier_results"]["tiers_run"] == ["tier0"]
    assert result["scan_id"]


def test_exact_blocklist_hit_overrides_safe_model():
    reputation = FakeReputation({"domain_age_days": 1, "blocklist_hit": "urlhaus"})
    result = _orchestrator(reputation_checker=reputation).scan(
        "https://example.com/payload", depth="tier1"
    )
    assert result["category"] == "malware"
    assert result["decision"] == "block"
    assert any(
        "URLhaus" in reason or "urlhaus" in reason for reason in result["reasons"]
    )


def test_live_tiers_use_final_url_and_html_evidence():
    observed = {}

    def redirects(url):
        return {
            "chain": [url, "https://landing.example.net/login"],
            "final_url": "https://landing.example.net/login",
            "domain_changed": True,
            "redirect_count": 1,
            "blocked": False,
            "block_reason": None,
        }

    def fetcher(url):
        observed["fetched"] = url
        return {
            "ok": True,
            "status_code": 200,
            "content_type": "text/html",
            "body": "<html></html>",
            "truncated": False,
            "bytes_read": 13,
            "error": None,
        }

    def html_extractor(body, url):
        observed["html_url"] = url
        return {
            "has_password_field": True,
            "form_domain_mismatch": True,
            "title_brand_mismatch": True,
            "external_iframe_count": 0,
        }

    result = _orchestrator(
        live_fetch_enabled=True,
        redirect_resolver=redirects,
        html_fetcher=fetcher,
        html_extractor=html_extractor,
    ).scan("https://short.example.com/a", depth="tier3")
    assert observed["fetched"] == "https://landing.example.net/login"
    assert observed["html_url"] == observed["fetched"]
    assert result["category"] == "phishing"
    assert result["decision"] == "block"
    assert result["tier_results"]["tiers_run"] == ["tier0", "tier1", "tier2", "tier3"]


def test_redirect_policy_violation_blocks_without_fabricating_category():
    def redirects(url):
        return {
            "chain": [url],
            "final_url": "http://169.254.169.254/latest/meta-data",
            "domain_changed": False,
            "redirect_count": 1,
            "blocked": True,
            "block_reason": "target is in a blocked address range",
        }

    result = _orchestrator(live_fetch_enabled=True, redirect_resolver=redirects).scan(
        "https://example.com/a", depth="tier3"
    )
    assert result["category"] == "safe"
    assert result["decision"] == "block"
    assert result["tier_results"]["tier3"]["reason"] == "redirect_policy_block"


def test_visual_match_on_other_domain_is_phishing():
    result = _orchestrator(
        live_fetch_enabled=True,
        visual_analysis_enabled=True,
        redirect_resolver=lambda url: {
            "chain": [url],
            "final_url": url,
            "domain_changed": False,
            "redirect_count": 0,
            "blocked": False,
            "block_reason": None,
        },
        html_fetcher=lambda url: {"ok": False, "body": None, "error": "not html"},
        visual_analyzer=lambda url, timeout_s: {
            "captured": True,
            "matched_brand": "paypal.com",
            "distance": 2,
            "domain_matches": False,
        },
    ).scan("https://lookalike.example.com/login", depth="tier4")
    assert result["category"] == "phishing"
    assert result["decision"] == "block"
