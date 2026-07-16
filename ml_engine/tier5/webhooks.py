"""Persistent, signed webhook registration and bounded delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from datetime import UTC, datetime

import requests

import config
from ml_engine.fetch.ssrf_guard import SSRFBlocked, check_url

_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class WebhookStore:
    def __init__(self, path: str | None = None):
        self.path = path or getattr(
            config, "WEBHOOK_DB", os.path.join(config.DATA_DIR, "webhooks.sqlite3")
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS webhooks (
                    webhook_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    url TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    min_threat_level TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    webhook_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    success INTEGER NOT NULL,
                    status_code INTEGER,
                    error TEXT,
                    FOREIGN KEY(webhook_id) REFERENCES webhooks(webhook_id)
                );
                CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at
                    ON webhook_deliveries(created_at);
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def register(
        self,
        *,
        url: str,
        secret: str,
        min_threat_level: str = config.WEBHOOK_THREAT_LEVEL_THRESHOLD,
        resolver=None,
    ) -> str:
        if len(secret.encode("utf-8")) < 16:
            raise ValueError("webhook secret must be at least 16 bytes")
        if min_threat_level not in _LEVEL_ORDER:
            raise ValueError("invalid minimum threat level")
        check_url(url, resolver=resolver)
        webhook_id = str(uuid.uuid4())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO webhooks(
                    webhook_id, created_at, url, secret, min_threat_level, active
                ) VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    webhook_id,
                    datetime.now(UTC).isoformat(),
                    url,
                    secret,
                    min_threat_level,
                ),
            )
        return webhook_id

    def deactivate(self, webhook_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE webhooks SET active = 0 WHERE webhook_id = ? AND active = 1",
                (webhook_id,),
            )
            return cursor.rowcount > 0

    def active_for_level(self, threat_level: str) -> list[dict]:
        if threat_level not in _LEVEL_ORDER:
            return []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM webhooks WHERE active = 1"
            ).fetchall()
        return [
            dict(row)
            for row in rows
            if _LEVEL_ORDER[threat_level]
            >= _LEVEL_ORDER.get(row["min_threat_level"], 99)
        ]

    def record_delivery(
        self,
        *,
        delivery_id: str,
        webhook_id: str,
        event_type: str,
        attempts: int,
        success: bool,
        status_code: int | None,
        error: str | None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO webhook_deliveries(
                    delivery_id, webhook_id, created_at, event_type, attempts,
                    success, status_code, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id,
                    webhook_id,
                    datetime.now(UTC).isoformat(),
                    event_type,
                    attempts,
                    int(success),
                    status_code,
                    error[:1000] if error else None,
                ),
            )


class WebhookDispatcher:
    def __init__(
        self, store: WebhookStore | None = None, requester=None, resolver=None
    ):
        self.store = store or WebhookStore()
        self.requester = requester or requests.post
        self.resolver = resolver

    @staticmethod
    def _signed_body(event_type: str, payload: dict, delivery_id: str) -> bytes:
        envelope = {
            "delivery_id": delivery_id,
            "event": event_type,
            "sent_at": datetime.now(UTC).isoformat(),
            "data": payload,
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def deliver_one(self, webhook: dict, event_type: str, payload: dict) -> dict:
        delivery_id = str(uuid.uuid4())
        body = self._signed_body(event_type, payload, delivery_id)
        signature = hmac.new(
            webhook["secret"].encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ShieldNet-Webhook/1.0",
            "X-ShieldNet-Delivery": delivery_id,
            "X-ShieldNet-Event": event_type,
            "X-ShieldNet-Signature": f"sha256={signature}",
        }

        attempts = 0
        success = False
        status_code = None
        error = None
        max_attempts = int(getattr(config, "WEBHOOK_MAX_ATTEMPTS", 3))
        for attempt in range(max_attempts):
            attempts = attempt + 1
            try:
                check_url(webhook["url"], resolver=self.resolver)
                response = self.requester(
                    webhook["url"],
                    data=body,
                    headers=headers,
                    allow_redirects=False,
                    timeout=float(getattr(config, "WEBHOOK_TIMEOUT_S", 5)),
                )
                status_code = int(response.status_code)
                success = 200 <= status_code < 300
                if success:
                    break
                error = f"HTTP {status_code}"
            except (requests.RequestException, SSRFBlocked, OSError) as exc:
                error = str(exc)
            if attempt + 1 < max_attempts:
                time.sleep(min(0.25 * (2**attempt), 1.0))

        self.store.record_delivery(
            delivery_id=delivery_id,
            webhook_id=webhook["webhook_id"],
            event_type=event_type,
            attempts=attempts,
            success=success,
            status_code=status_code,
            error=error,
        )
        return {
            "delivery_id": delivery_id,
            "webhook_id": webhook["webhook_id"],
            "success": success,
            "attempts": attempts,
            "status_code": status_code,
            "error": error,
        }

    def dispatch(self, event_type: str, payload: dict, threat_level: str) -> list[dict]:
        return [
            self.deliver_one(webhook, event_type, payload)
            for webhook in self.store.active_for_level(threat_level)
        ]
