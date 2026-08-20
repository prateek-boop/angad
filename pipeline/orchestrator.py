"""Depth-aware ShieldNet inference and evidence orchestration."""

from __future__ import annotations

import math
import os
import time
import uuid
from typing import Any

import numpy as np

import config
from ml_engine.explainer import ThreatExplainer
from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.model import ThreatDetectionModel
from ml_engine.tier5.calibration import TemperatureCalibrator
from ml_engine.tier5.drift import DriftMonitor
from ml_engine.tier5.ensemble import EvidenceEnsemble
from ml_engine.tier5.feedback import FeedbackStore, redact_url
from ml_engine.url_tokenizer import URLTokenizer
from pipeline.validation import registered_domain, validate_url_format

DEPTH_ORDER = {"tier0": 0, "tier1": 1, "tier2": 2, "tier3": 3, "tier4": 4}


def _load_cached_blocklists() -> dict[str, set[str]]:
    """Load local feed caches only; refreshing feeds is an explicit CLI job."""
    from ml_engine.real_data_loader import load_threat_blocklists

    sources = {}
    for name in ("urlhaus", "openphish"):
        path = os.path.join(config.DATA_DIR, f"{name}_feed.cache")
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            sources[name] = path
    if not sources:
        return {}
    return load_threat_blocklists(feed_names=sources, sources=sources, strict=False)


def _default_reputation_checker():
    from ml_engine.reputation import ReputationChecker

    return ReputationChecker(blocklists=_load_cached_blocklists())


def _safe_tier_result(value: dict) -> dict:
    """Strip raw bodies and redact URL query values before returning/storing."""
    output = {}
    for key, item in value.items():
        if key == "body":
            continue
        if key in {"url", "final_url"} and isinstance(item, str):
            output[key] = redact_url(item)
        elif key == "chain" and isinstance(item, list):
            output[key] = [
                redact_url(entry) for entry in item if isinstance(entry, str)
            ]
        else:
            output[key] = item
    return output


class ScanOrchestrator:
    def __init__(
        self,
        *,
        tokenizer=None,
        extractor=None,
        explainer=None,
        model=None,
        calibrator=None,
        ensemble=None,
        reputation_checker=None,
        redirect_resolver=None,
        html_fetcher=None,
        html_extractor=None,
        visual_analyzer=None,
        feedback_store=None,
        drift_monitor=None,
        persist: bool = True,
        live_fetch_enabled: bool | None = None,
        visual_analysis_enabled: bool | None = None,
    ):
        self.tokenizer = tokenizer or URLTokenizer()
        self.extractor = extractor or FeatureExtractor()
        self.explainer = explainer or ThreatExplainer()
        self.model = model or ThreatDetectionModel.load(config.MODEL_PATH)
        self.calibrator = calibrator or TemperatureCalibrator.load(
            config.CALIBRATION_PATH
        )
        self.ensemble = ensemble or EvidenceEnsemble()
        self.reputation_checker = reputation_checker or _default_reputation_checker()
        if redirect_resolver is None:
            from ml_engine.fetch.redirect_resolver import resolve_chain

            redirect_resolver = resolve_chain
        if html_fetcher is None:
            from ml_engine.fetch.sandboxed_fetcher import fetch

            html_fetcher = fetch
        if html_extractor is None:
            from ml_engine.fetch.html_features import extract as extract_html

            html_extractor = extract_html
        self.redirect_resolver = redirect_resolver
        self.html_fetcher = html_fetcher
        self.html_extractor = html_extractor
        self.visual_analyzer = visual_analyzer or self._visual_evidence
        self.persist = persist
        self.feedback_store = (
            feedback_store
            if feedback_store is not None
            else (FeedbackStore() if persist else None)
        )
        self.drift_monitor = (
            drift_monitor
            if drift_monitor is not None
            else (DriftMonitor() if persist else None)
        )
        self.live_fetch_enabled = (
            config.LIVE_FETCH_ENABLED
            if live_fetch_enabled is None
            else live_fetch_enabled
        )
        self.visual_analysis_enabled = (
            config.VISUAL_ANALYSIS_ENABLED
            if visual_analysis_enabled is None
            else visual_analysis_enabled
        )

    @staticmethod
    def _remaining_seconds(deadline: float) -> float:
        return max(0.0, deadline - time.monotonic())

    @staticmethod
    def _probability_dict(row: np.ndarray) -> dict[str, float]:
        return {
            name: float(row[index]) for index, name in enumerate(config.THREAT_CLASSES)
        }

    def _visual_evidence(self, final_url: str, timeout_s: float) -> dict:
        from ml_engine.visual.perceptual_hash import hash_image_bytes
        from ml_engine.visual.reference_store import ReferenceStore
        from ml_engine.visual.screenshotter import capture

        png = capture(final_url, timeout_s=timeout_s)
        page_hash = hash_image_bytes(png)
        store = ReferenceStore()
        match = store.nearest_match(page_hash)
        if match is None:
            return {
                "captured": True,
                "reference_count": len(store),
                "matched_brand": None,
            }
        brand_domain, distance = match
        return {
            "captured": True,
            "reference_count": len(store),
            "matched_brand": brand_domain,
            "distance": distance,
            "domain_matches": registered_domain(final_url) == brand_domain,
        }

    def scan(
        self, url: str, *, depth: str = "tier0", timeout_ms: int | None = None
    ) -> dict:
        if depth not in DEPTH_ORDER:
            raise ValueError(f"unsupported scan depth: {depth}")
        value = validate_url_format(url)
        selected_timeout_ms = timeout_ms or config.DEFAULT_SCAN_TIMEOUT_MS
        if (
            selected_timeout_ms < 100
            or selected_timeout_ms > config.MAX_SCAN_TIMEOUT_MS
        ):
            raise ValueError(
                f"timeout_ms must be between 100 and {config.MAX_SCAN_TIMEOUT_MS}"
            )

        started = time.perf_counter()
        deadline = time.monotonic() + selected_timeout_ms / 1000.0
        scan_id = str(uuid.uuid4())
        warnings: list[str] = []
        tiers_run = ["tier0"]

        features = self.extractor.extract(value)
        url_ids = self.tokenizer.encode_batch([value])
        feature_array = np.asarray([features], dtype=np.float32)
        raw = self.model.predict_with_confidence(url_ids, feature_array)[0]
        calibrated_row = self.calibrator.transform(
            [[raw["probabilities"][name] for name in config.THREAT_CLASSES]]
        )[0]
        calibrated = self._probability_dict(calibrated_row)
        tier_results: dict[str, Any] = {
            "tiers_run": tiers_run,
            "tier0": {
                "status": "ok",
                "model": getattr(
                    getattr(self.model, "model", None), "name", "ShieldNet"
                ),
                "calibration_temperature": self.calibrator.temperature,
                "calibration_samples": self.calibrator.fitted_samples,
                "raw_probabilities": raw["probabilities"],
            },
        }

        reputation = redirects = html = visual = None
        if DEPTH_ORDER[depth] >= 1:
            if self._remaining_seconds(deadline) <= 0:
                warnings.append(
                    "Scan deadline reached before Tier 1 reputation analysis."
                )
                tier_results["tier1"] = {"status": "skipped", "reason": "deadline"}
            elif not config.REPUTATION_NETWORK_ENABLED:
                warnings.append(
                    "Tier 1 metadata lookups are disabled; cached feed matching still ran."
                )
                reputation = self.reputation_checker.check_blocklists(value)
                tiers_run.append("tier1")
                tier_results["tier1"] = {
                    "status": "offline_only",
                    **_safe_tier_result(reputation),
                }
            else:
                try:
                    reputation = self.reputation_checker.check(value)
                    tiers_run.append("tier1")
                    tier_results["tier1"] = {
                        "status": "ok",
                        **_safe_tier_result(reputation),
                    }
                except Exception as exc:
                    warnings.append(
                        f"Tier 1 reputation unavailable: {type(exc).__name__}."
                    )
                    tier_results["tier1"] = {
                        "status": "error",
                        "error": type(exc).__name__,
                    }

        final_url = value
        if DEPTH_ORDER[depth] >= 2:
            if not self.live_fetch_enabled:
                warnings.append("Live target fetching is disabled by configuration.")
                tier_results["tier2"] = {"status": "disabled"}
            elif self._remaining_seconds(deadline) <= 0:
                warnings.append("Scan deadline reached before redirect analysis.")
                tier_results["tier2"] = {"status": "skipped", "reason": "deadline"}
            else:
                try:
                    redirects = self.redirect_resolver(value)
                    tiers_run.append("tier2")
                    tier_results["tier2"] = {
                        "status": "ok",
                        **_safe_tier_result(redirects),
                    }
                    if not redirects.get("blocked"):
                        final_url = redirects.get("final_url") or value
                except Exception as exc:
                    warnings.append(
                        f"Tier 2 redirect analysis unavailable: {type(exc).__name__}."
                    )
                    tier_results["tier2"] = {
                        "status": "error",
                        "error": type(exc).__name__,
                    }

        if DEPTH_ORDER[depth] >= 3:
            if not self.live_fetch_enabled:
                tier_results["tier3"] = {"status": "disabled"}
            elif redirects and redirects.get("blocked"):
                tier_results["tier3"] = {
                    "status": "skipped",
                    "reason": "redirect_policy_block",
                }
            elif self._remaining_seconds(deadline) <= 0:
                warnings.append("Scan deadline reached before HTML analysis.")
                tier_results["tier3"] = {"status": "skipped", "reason": "deadline"}
            else:
                try:
                    fetched = self.html_fetcher(final_url)
                    if fetched.get("ok") and fetched.get("body") is not None:
                        html = self.html_extractor(fetched["body"], final_url)
                        tiers_run.append("tier3")
                        tier_results["tier3"] = {
                            "status": "ok",
                            "fetch": _safe_tier_result(fetched),
                            "features": html,
                        }
                    else:
                        tier_results["tier3"] = {
                            "status": "unavailable",
                            "fetch": _safe_tier_result(fetched),
                        }
                except Exception as exc:
                    warnings.append(
                        f"Tier 3 HTML analysis unavailable: {type(exc).__name__}."
                    )
                    tier_results["tier3"] = {
                        "status": "error",
                        "error": type(exc).__name__,
                    }

        if DEPTH_ORDER[depth] >= 4:
            if not self.live_fetch_enabled or not self.visual_analysis_enabled:
                warnings.append("Visual analysis is disabled by configuration.")
                tier_results["tier4"] = {"status": "disabled"}
            elif redirects and redirects.get("blocked"):
                tier_results["tier4"] = {
                    "status": "skipped",
                    "reason": "redirect_policy_block",
                }
            elif self._remaining_seconds(deadline) <= 0:
                warnings.append("Scan deadline reached before visual analysis.")
                tier_results["tier4"] = {"status": "skipped", "reason": "deadline"}
            else:
                try:
                    visual = self.visual_analyzer(
                        final_url, self._remaining_seconds(deadline)
                    )
                    tiers_run.append("tier4")
                    tier_results["tier4"] = {"status": "ok", **visual}
                except Exception as exc:
                    warnings.append(
                        f"Tier 4 visual analysis unavailable: {type(exc).__name__}."
                    )
                    tier_results["tier4"] = {
                        "status": "unavailable",
                        "error": type(exc).__name__,
                    }

        fused = self.ensemble.fuse(
            calibrated,
            reputation=reputation,
            redirects=redirects,
            html=html,
            visual=visual,
        )
        category = fused.category
        risk_score = fused.risk_score
        critical_evidence = any(
            contribution.severity == "critical" for contribution in fused.contributions
        )
        corroborating_sources = {
            contribution.source
            for contribution in fused.contributions
            if contribution.severity in {"high", "critical"}
        }
        calibrated_for_enforcement = self.calibrator.fitted_samples > 0
        if not calibrated_for_enforcement:
            warnings.append(
                "Model calibration is not fitted; model-only threats require review."
            )
        if fused.policy_blocked or (critical_evidence and category != "safe"):
            decision = "block"
        elif (
            calibrated_for_enforcement
            and category != "safe"
            and risk_score >= config.BLOCK_RISK_THRESHOLD
            and corroborating_sources
        ):
            decision = "block"
        elif category != "safe" or risk_score >= config.REVIEW_RISK_THRESHOLD:
            decision = "review"
        else:
            decision = "allow"

        evidence_reasons = [item.reason for item in fused.contributions]
        model_reasons = self.explainer.explain(features, category)
        if evidence_reasons and not self.explainer.has_specific_reasons(features):
            # Generic heuristic filler reads as noise next to concrete evidence.
            model_reasons = []
        reasons = list(dict.fromkeys(evidence_reasons + model_reasons))[:12]
        if not reasons:
            reasons = ["No suspicious URL or external-evidence patterns detected."]

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        entropy = float(
            -sum(
                probability * math.log(probability + 1e-12)
                for probability in fused.probabilities.values()
            )
            / math.log(len(config.THREAT_CLASSES))
        )
        if fused.policy_blocked:
            recommendation = "Do not access this target; it violated the live-analysis network policy."
        elif decision == "review":
            recommendation = (
                "Treat this URL as unverified and obtain independent reputation, "
                "content, or analyst evidence before blocking it."
            )
        else:
            recommendation = self.explainer.recommendation(category)
        result = {
            "scan_id": scan_id,
            "category": category,
            "confidence": fused.confidence,
            "risk_score": risk_score,
            "uncertainty": entropy,
            "threat_level": self._threat_level(risk_score),
            "decision": decision,
            "reasons": reasons,
            "recommendation": recommendation,
            "blocked": decision == "block",
            "probabilities": fused.probabilities,
            "scan_time_ms": elapsed_ms,
            "depth_requested": depth,
            "warnings": warnings,
            "tier_results": tier_results,
            "evidence": [
                contribution.to_dict() for contribution in fused.contributions
            ],
        }

        if self.persist:
            persistence_evidence = {
                "tier_results": tier_results,
                "contributions": result["evidence"],
                "warnings": warnings,
            }
            try:
                if self.feedback_store is not None:
                    self.feedback_store.record_scan(
                        scan_id=scan_id,
                        url=value,
                        depth=depth,
                        predicted_label=category,
                        probabilities=fused.probabilities,
                        evidence=persistence_evidence,
                    )
                if self.drift_monitor is not None:
                    self.drift_monitor.record(
                        scan_id=scan_id,
                        predicted_label=category,
                        risk_score=risk_score,
                        features=features,
                        probabilities=fused.probabilities,
                    )
            except Exception as exc:
                warnings.append(
                    f"Scan telemetry could not be persisted: {type(exc).__name__}."
                )
        return result

    @staticmethod
    def _threat_level(risk_score: float) -> str:
        for level, threshold in sorted(
            config.THREAT_LEVEL_THRESHOLDS.items(), key=lambda item: -item[1]
        ):
            if risk_score >= threshold:
                return level
        return "low"
