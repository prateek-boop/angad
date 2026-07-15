"""Evidence-level ensemble for URL, reputation, page, and visual signals.

This module deliberately does not claim that hand-authored evidence weights
are a learned production model. They provide a conservative, inspectable
fusion policy until enough labeled multimodal feedback exists to train and
validate a replacement meta-classifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

import config

_EPSILON = 1e-7
_CLASS_INDEX = {name: index for index, name in enumerate(config.THREAT_CLASSES)}


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

    def fuse(
        self,
        base_probabilities: dict[str, float],
        *,
        reputation: dict | None = None,
        redirects: dict | None = None,
        html: dict | None = None,
        visual: dict | None = None,
    ) -> FusionResult:
        base = self._base_vector(base_probabilities)
        contributions: list[EvidenceContribution] = []
        policy_blocked = False
        policy_reason = None

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

        if reputation.get("tls_expired") is True:
            self._add(
                contributions,
                "reputation",
                "The site's TLS certificate is expired.",
                {"safe": -0.5, "phishing": 0.35, "scam": 0.2},
                "medium",
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
