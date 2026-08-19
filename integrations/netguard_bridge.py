"""
Bridge between the netguard TCP proxy and ShieldNet's URL/domain
classifier. Runs the ScanOrchestrator in-process (same Python process, no
HTTP hop) against domains observed live on the wire (TLS SNI today; HTTP
Host headers could feed the same path later).
"""

import logging

from pipeline.orchestrator import ScanOrchestrator

logger = logging.getLogger("NETGUARD.BRIDGE")


class UrlReputationBridge:
    """Looks up ShieldNet's opinion of a domain seen by the TCP proxy."""

    def __init__(self, orchestrator: ScanOrchestrator | None = None):
        self.orchestrator = orchestrator or ScanOrchestrator(persist=True)

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
            result = self.orchestrator.scan(f"https://{sni}", depth="tier0")
        except Exception as e:
            logger.warning(f"ShieldNet scan failed for {sni}: {e}")
            return self._neutral_result()

        return {
            "category": result.get("category", "safe"),
            "risk_score": result.get("risk_score", 0.0),
            "decision": result.get("decision", "allow"),
            "reasons": result.get("reasons", []),
        }

    @staticmethod
    def _neutral_result() -> dict:
        return {"category": "safe", "risk_score": 0.0, "decision": "allow", "reasons": []}
