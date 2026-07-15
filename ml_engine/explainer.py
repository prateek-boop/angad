"""Explains predictions via feature thresholds, not neural-net attribution.
See MODEL_BRAIN.md sec 10 — this is heuristic, not deep model explainability.
Feature indices below MUST match ml_engine/feature_extractor.py exactly."""

# (feature_index, predicate, reason_text)
_RULES = [
    (14, lambda v: v == 1.0, "URL uses an IP address instead of a domain name."),
    (15, lambda v: v == 1.0, "URL uses a link shortener, hiding the real destination."),
    (16, lambda v: v == 1.0, "URL uses a TLD commonly abused for abuse/phishing."),
    (17, lambda v: v == 1.0, "URL uses punycode, which can disguise the real domain."),
    (20, lambda v: v == 0.0, "URL does not use HTTPS."),
    (
        6,
        lambda v: v == 1.0,
        "URL contains an '@' symbol, which can hide the real destination.",
    ),
    (25, lambda v: v == 1.0, "URL points to an executable/archive file extension."),
    (26, lambda v: v == 1.0, "URL contains login-related keywords."),
    (30, lambda v: v == 1.0, "URL contains verification-related keywords."),
    (31, lambda v: v == 1.0, "URL contains banking-related keywords."),
    (32, lambda v: v >= 0.34, "URL appears to impersonate a known brand."),
    (
        38,
        lambda v: v == 1.0,
        "A known brand name appears in the subdomain, not the real domain.",
    ),
    (39, lambda v: v == 1.0, "URL uses a TLD designed to look like a trusted one."),
    (34, lambda v: v == 1.0, "URL has an excessive number of subdomains."),
    (35, lambda v: v >= 0.5, "URL's domain name looks randomly generated."),
    (
        40,
        lambda v: v > 0.0,
        "URL contains characters that visually mimic a legitimate domain (homoglyphs).",
    ),
    (
        33,
        lambda v: v == 1.0,
        "URL query string appears to chain to another redirect target.",
    ),
]


class ThreatExplainer:
    def has_specific_reasons(self, features: list[float]) -> bool:
        """Whether any of the 41 hand-picked feature rules actually fired.

        Used by callers (e.g. the orchestrator) to detect when ``explain()``
        fell back to a generic filler message, so it can be dropped in favor
        of real evidence reasons instead of being shown alongside them.
        """
        return any(pred(features[idx]) for idx, pred, _ in _RULES)

    def explain(self, features: list[float], category: str) -> list[str]:
        reasons = [text for idx, pred, text in _RULES if pred(features[idx])]
        if reasons:
            return reasons
        if category == "safe":
            return ["No suspicious URL patterns detected."]
        return [
            f"Classified as {category} based on overall URL pattern, "
            f"no single dominant heuristic triggered."
        ]

    def recommendation(self, category: str) -> str:
        if category == "safe":
            return "No action needed."
        return {
            "phishing": "Do not enter credentials. Verify the sender/domain "
            "independently before proceeding.",
            "malware": "Do not download or execute files from this URL.",
            "data_leak": "Do not submit personal data. This URL may expose or "
            "harvest sensitive information.",
            "scam": "Do not proceed. This URL matches patterns commonly used in scams.",
        }.get(category, "Proceed with caution.")


def demo():
    explainer = ThreatExplainer()
    features = [0.0] * 41
    features[16] = 1.0  # suspicious_tld
    features[26] = 1.0  # has_login_keyword

    reasons = explainer.explain(features, "phishing")
    assert any("TLD" in r for r in reasons)
    assert any("login" in r for r in reasons)
    assert explainer.has_specific_reasons(features) is True

    safe_features = [0.0] * 41
    safe_features[20] = 1.0  # is_https
    safe_reasons = explainer.explain(safe_features, "safe")
    assert safe_reasons == ["No suspicious URL patterns detected."]
    assert explainer.has_specific_reasons(safe_features) is False

    generic_features = [0.0] * 41
    generic_features[20] = 1.0  # is_https, avoid triggering the not-HTTPS rule
    generic_reasons = explainer.explain(generic_features, "malware")
    assert generic_reasons == [
        "Classified as malware based on overall URL pattern, "
        "no single dominant heuristic triggered."
    ]
    assert explainer.has_specific_reasons(generic_features) is False

    assert "Do not" in explainer.recommendation("malware")
    print("explainer: all checks passed")


if __name__ == "__main__":
    demo()
