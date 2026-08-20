"""
Bridge between the netguard TCP proxy and ShieldNet's URL/domain
classifier. Runs the ScanOrchestrator in-process (same Python process, no
HTTP hop) against domains observed live on the wire (TLS SNI today; HTTP
Host headers could feed the same path later).
"""

import logging
import threading
import time
from collections import OrderedDict

from pipeline.orchestrator import ScanOrchestrator
from pipeline.validation import registered_domain

logger = logging.getLogger("NETGUARD.BRIDGE")


class UrlReputationBridge:
    """Looks up ShieldNet's opinion of a domain seen by the TCP proxy."""

    def __init__(
        self,
        orchestrator: ScanOrchestrator | None = None,
        *,
        cache_ttl_s: float = 300.0,
        max_cache_entries: int = 4096,
        scan_wait_s: float = 0.05,
    ):
        self.orchestrator = orchestrator or ScanOrchestrator(persist=True)
        self.cache_ttl_s = max(0.0, float(cache_ttl_s))
        self.max_cache_entries = max(1, int(max_cache_entries))
        self.scan_wait_s = max(0.0, float(scan_wait_s))
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._cache_lock = threading.RLock()
        self._scan_gate = threading.Lock()
        self._cache_hits = 0
        self._model_scans = 0
        self._busy_skips = 0

        model = getattr(self.orchestrator, "model", None)
        warmup = getattr(model, "warmup", None)
        if callable(warmup):
            try:
                warmup()
            except Exception as exc:
                logger.warning("ShieldNet model warmup failed: %s", exc)

    def check_domain(self, sni: str) -> dict:
        """
        Run a tier0 (instant, local-only) ShieldNet scan against a domain.

        Returns a dict with `category`, `risk_score`, `decision`, `reasons`.
        On any failure, returns a neutral/safe-leaning result rather than
        raising — a domain-reputation lookup failing must never block the
        proxy's connection pipeline.
        """
        if not sni:
            return self._neutral_result()

        try:
            hostname = sni.strip().rstrip(".").lower().encode("idna").decode("ascii")
            candidate = registered_domain(f"https://{hostname}")
            canonical_domain = candidate if "." in candidate else hostname
        except Exception as exc:
            logger.warning("Invalid SNI %r: %s", sni, exc)
            return self._neutral_result()

        cached = self._get_cached(canonical_domain)
        if cached is not None:
            return cached

        if not self._scan_gate.acquire(timeout=self.scan_wait_s):
            with self._cache_lock:
                self._busy_skips += 1
            return self._neutral_result()

        try:
            # Another connection may have filled this entry while we waited.
            cached = self._get_cached(canonical_domain)
            if cached is not None:
                return cached
            with self._cache_lock:
                self._model_scans += 1
            result = self.orchestrator.scan(
                f"https://{canonical_domain}", depth="tier0"
            )
        except Exception as exc:
            logger.warning("ShieldNet scan failed for %s: %s", sni, exc)
            return self._neutral_result()
        finally:
            self._scan_gate.release()

        evidence = result.get("evidence", [])
        verified_sources = sorted(
            {
                item.get("source")
                for item in evidence
                if isinstance(item, dict)
                and item.get("severity") in {"high", "critical"}
                and item.get("source")
            }
        )
        output = {
            "category": result.get("category", "safe"),
            "risk_score": result.get("risk_score", 0.0),
            "decision": result.get("decision", "allow"),
            "reasons": result.get("reasons", []),
            "canonical_domain": canonical_domain,
            "verified_sources": verified_sources,
            "enforcement_authorized": bool(
                result.get("decision") == "block" and verified_sources
            ),
        }
        self._put_cached(canonical_domain, output)
        return dict(output)

    def _get_cached(self, domain: str) -> dict | None:
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(domain)
            if cached is None:
                return None
            expires_at, result = cached
            if expires_at <= now:
                self._cache.pop(domain, None)
                return None
            self._cache.move_to_end(domain)
            self._cache_hits += 1
            return dict(result)

    def _put_cached(self, domain: str, result: dict) -> None:
        if self.cache_ttl_s <= 0:
            return
        with self._cache_lock:
            self._cache[domain] = (
                time.monotonic() + self.cache_ttl_s,
                dict(result),
            )
            self._cache.move_to_end(domain)
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)

    def get_stats(self) -> dict:
        with self._cache_lock:
            return {
                "cache_entries": len(self._cache),
                "cache_hits": self._cache_hits,
                "model_scans": self._model_scans,
                "busy_fail_open": self._busy_skips,
            }

    @staticmethod
    def _neutral_result() -> dict:
        return {
            "category": "safe",
            "risk_score": 0.0,
            "decision": "allow",
            "reasons": [],
            "canonical_domain": None,
            "verified_sources": [],
            "enforcement_authorized": False,
        }
