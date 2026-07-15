"""Stable JSON and CEF representations for SIEM ingestion."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _cef_header(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_extension(value) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _severity(result: dict) -> int:
    return {
        "low": 2,
        "medium": 5,
        "high": 8,
        "critical": 10,
    }.get(str(result.get("threat_level", "low")), 1)


def to_json_event(result: dict, *, observed_at: str | None = None) -> str:
    event = {
        "schema_version": 1,
        "event_type": "shieldnet.url_scan",
        "observed_at": observed_at or datetime.now(UTC).isoformat(),
        "scan_id": result.get("scan_id"),
        "category": result.get("category"),
        "confidence": result.get("confidence"),
        "risk_score": result.get("risk_score"),
        "threat_level": result.get("threat_level"),
        "decision": result.get("decision"),
        "blocked": result.get("blocked"),
        "reasons": result.get("reasons", []),
        "probabilities": result.get("probabilities", {}),
    }
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def to_cef(result: dict) -> str:
    category = str(result.get("category", "unknown"))
    extension = {
        "externalId": result.get("scan_id", ""),
        "act": result.get("decision", "unknown"),
        "cn1": result.get("risk_score", 0),
        "cn1Label": "RiskScore",
        "cn2": result.get("confidence", 0),
        "cn2Label": "Confidence",
        "cs1": result.get("threat_level", "unknown"),
        "cs1Label": "ThreatLevel",
        "msg": "; ".join(str(reason) for reason in result.get("reasons", []))[:1000],
    }
    encoded = " ".join(
        f"{key}={_cef_extension(value)}" for key, value in extension.items()
    )
    return (
        "CEF:0|ShieldNet|URL Threat Analyzer|1.0|"
        f"{_cef_header(category)}|URL classified as {_cef_header(category)}|"
        f"{_severity(result)}|{encoded}"
    )
