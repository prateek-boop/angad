"""Small dependency-free in-process operational counters."""

from __future__ import annotations

import threading
from collections import Counter


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = Counter()
        self._scan_time_ms = 0.0

    def record_scan(
        self, *, category: str, depth: str, decision: str, elapsed_ms: float
    ) -> None:
        with self._lock:
            self._counters["scans_total"] += 1
            self._counters[f"category:{category}"] += 1
            self._counters[f"depth:{depth}"] += 1
            self._counters[f"decision:{decision}"] += 1
            self._scan_time_ms += float(elapsed_ms)

    def record_error(self, kind: str) -> None:
        with self._lock:
            self._counters["errors_total"] += 1
            self._counters[f"error:{kind}"] += 1

    def snapshot(self) -> dict:
        with self._lock:
            scans = int(self._counters["scans_total"])
            return {
                "counters": dict(self._counters),
                "mean_scan_time_ms": self._scan_time_ms / scans if scans else 0.0,
            }


metrics = Metrics()
