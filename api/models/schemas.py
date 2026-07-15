"""Versioned API schemas preserving ShieldNet's original response contract."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

import config

ScanDepth = Literal["tier0", "tier1", "tier2", "tier3", "tier4"]
ThreatLevel = Literal["low", "medium", "high", "critical"]


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=config.MAX_URL_INPUT_LENGTH)
    depth: ScanDepth = "tier0"
    timeout_ms: int | None = Field(default=None, ge=100, le=config.MAX_SCAN_TIMEOUT_MS)


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=config.MAX_BATCH_SIZE)
    depth: ScanDepth = "tier0"
    timeout_ms: int | None = Field(default=None, ge=100, le=config.MAX_SCAN_TIMEOUT_MS)

    @model_validator(mode="after")
    def network_batch_is_bounded(self):
        if self.depth != "tier0" and len(self.urls) > config.MAX_NETWORK_BATCH_SIZE:
            raise ValueError(
                f"network scan batches are limited to {config.MAX_NETWORK_BATCH_SIZE} URLs"
            )
        return self


class ScanResponse(BaseModel):
    scan_id: str
    category: str
    confidence: float
    risk_score: float
    uncertainty: float
    threat_level: ThreatLevel
    decision: Literal["allow", "review", "block"]
    reasons: list[str]
    recommendation: str
    blocked: bool
    probabilities: dict[str, float]
    scan_time_ms: float
    depth_requested: ScanDepth
    warnings: list[str] = Field(default_factory=list)
    tier_results: dict = Field(default_factory=dict)
    evidence: list[dict] = Field(default_factory=list)


class BatchScanResponse(BaseModel):
    results: list[ScanResponse]


class FeedbackRequest(BaseModel):
    correct_label: str
    scan_id: str | None = None
    url: str | None = Field(default=None, max_length=config.MAX_URL_INPUT_LENGTH)
    notes: str | None = Field(default=None, max_length=2000)
    submitted_by: str | None = Field(default=None, max_length=320)

    @model_validator(mode="after")
    def validate_feedback(self):
        if self.correct_label not in config.THREAT_CLASSES:
            raise ValueError(f"correct_label must be one of {config.THREAT_CLASSES}")
        if not self.scan_id and not self.url:
            raise ValueError("scan_id or url is required")
        return self


class FeedbackResponse(BaseModel):
    feedback_id: int
    accepted: bool = True


class WebhookRegisterRequest(BaseModel):
    url: str = Field(min_length=1, max_length=config.MAX_URL_INPUT_LENGTH)
    secret: str = Field(min_length=16, max_length=512)
    min_threat_level: ThreatLevel = "high"


class WebhookRegisterResponse(BaseModel):
    webhook_id: str
    active: bool = True
