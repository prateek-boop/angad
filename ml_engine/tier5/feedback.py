"""Privacy-conscious SQLite store for scan context and human corrections."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import config


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def url_fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()


def redact_url(url: str) -> str:
    """Remove credentials, fragments, and query values before persistence."""
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    query_keys = sorted(
        {key for key, _value in parse_qsl(parts.query, keep_blank_values=True)}
    )
    redacted_query = urlencode([(key, "REDACTED") for key in query_keys])
    return urlunsplit(
        (
            parts.scheme.lower(),
            f"{hostname.lower()}{port}",
            parts.path,
            redacted_query,
            "",
        )
    )


def _identity_hash(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class FeedbackStore:
    def __init__(self, path: str | None = None):
        self.path = path or config.FEEDBACK_DB
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    url_sha256 TEXT NOT NULL,
                    url_redacted TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    probabilities_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
                CREATE INDEX IF NOT EXISTS idx_scans_url_sha256 ON scans(url_sha256);

                CREATE TABLE IF NOT EXISTS feedback (
                    feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    created_at TEXT NOT NULL,
                    url_sha256 TEXT NOT NULL,
                    url_redacted TEXT NOT NULL,
                    predicted_label TEXT,
                    correct_label TEXT NOT NULL,
                    notes TEXT,
                    submitted_by_hash TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);
                CREATE INDEX IF NOT EXISTS idx_feedback_correct_label ON feedback(correct_label);
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def record_scan(
        self,
        *,
        scan_id: str,
        url: str,
        depth: str,
        predicted_label: str,
        probabilities: dict[str, float],
        evidence: dict,
    ) -> None:
        if predicted_label not in config.THREAT_CLASSES:
            raise ValueError("invalid predicted label")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO scans(
                    scan_id, created_at, url_sha256, url_redacted, depth,
                    predicted_label, probabilities_json, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    _now_iso(),
                    url_fingerprint(url),
                    redact_url(url),
                    depth,
                    predicted_label,
                    json.dumps(probabilities, sort_keys=True, separators=(",", ":")),
                    json.dumps(
                        evidence, sort_keys=True, separators=(",", ":"), default=str
                    ),
                ),
            )

    def submit(
        self,
        *,
        correct_label: str,
        scan_id: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        submitted_by: str | None = None,
    ) -> int:
        if correct_label not in config.THREAT_CLASSES:
            raise ValueError("invalid correct label")
        if not scan_id and not url:
            raise ValueError("scan_id or url is required")

        predicted_label = None
        if scan_id:
            with self._connect() as connection:
                scan = connection.execute(
                    "SELECT url_sha256, url_redacted, predicted_label FROM scans WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
            if scan is None:
                raise KeyError("unknown scan_id")
            fingerprint = scan["url_sha256"]
            redacted = scan["url_redacted"]
            predicted_label = scan["predicted_label"]
        else:
            assert url is not None
            fingerprint = url_fingerprint(url)
            redacted = redact_url(url)

        clean_notes = notes.strip()[:2000] if notes and notes.strip() else None
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO feedback(
                    scan_id, created_at, url_sha256, url_redacted,
                    predicted_label, correct_label, notes, submitted_by_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    _now_iso(),
                    fingerprint,
                    redacted,
                    predicted_label,
                    correct_label,
                    clean_notes,
                    _identity_hash(submitted_by),
                ),
            )
            return int(cursor.lastrowid)

    def summary(self) -> dict:
        with self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
            corrected = connection.execute(
                """
                SELECT COUNT(*) FROM feedback
                WHERE predicted_label IS NOT NULL AND predicted_label != correct_label
                """
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT correct_label, COUNT(*) AS count FROM feedback GROUP BY correct_label"
            ).fetchall()
        return {
            "total_feedback": int(total),
            "known_corrections": int(corrected),
            "correct_labels": {row["correct_label"]: int(row["count"]) for row in rows},
        }
