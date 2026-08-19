"""
NetGuard - Main Entry Point
Standalone AI-powered TCP proxy / firewall.

No Android, no Shizuku/ADB: this runs as a plain Linux service under its
own privileges. Traffic is inspected as it passes through the transparent
TCP proxy, and blocking decisions are made synchronously, before a
connection is relayed - not after the fact via kernel rule races.
"""

import logging
import time

from integrations.netguard_bridge import UrlReputationBridge

from . import constants
from .ai_engine import AIEngine
from .dashboard.server import DashboardServer
from .database import ReputationDB
from .decision_engine import DecisionEngine
from .enforcement import EnforcementEngine
from .feature_extractor import FeatureExtractor
from .flow_tracker import FlowTracker
from .observer import NetworkObserver
from .proxy import TransparentProxy

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler()]
)


class NetGuard:
    """
    NetGuard - AI-Powered Standalone TCP Proxy Firewall

    Coordinates:
    - Network Observer (Netlink/ss/psutil) - host connection stats, dashboard feed
    - Transparent TCP Proxy - traffic interception, TLS/SNI/JA3 extraction,
      and the synchronous pre-relay block decision
    - Feature Extractor - 42-dim traffic feature vector
    - AI Engine - Isolation Forest + trained classifiers, blended with
      ShieldNet's domain/URL reputation
    - Decision Engine - behavioral baseline + strike-based verdicts
    - Enforcement Engine - iptables blocking (destination IP and client IP)
    - Dashboard - WebSocket + REST live view

    Usage:
        guard = NetGuard()
        guard.start()  # Blocking, runs until interrupted

        # Or for async control:
        guard.start_async()
        # ... do other things ...
        guard.stop()
    """

    def __init__(self, db_path: str = constants.DB_PATH):
        self.logger = logging.getLogger("NETGUARD")
        self.is_running = False

        self.logger.info("🚀 Initializing NetGuard...")

        self.db = ReputationDB(db_path)
        self.db.load_default_signatures()

        self.flow_tracker = FlowTracker()

        self.observer = NetworkObserver()
        self.proxy = TransparentProxy()
        self.extractor = FeatureExtractor(self.flow_tracker)
        self.ai_engine = AIEngine(self.db)
        self.decision_engine = DecisionEngine(self.db)
        self.enforcer = EnforcementEngine()
        self.dashboard = DashboardServer()
        self.url_reputation = UrlReputationBridge()

        self.proxy.set_tls_callback(self._on_tls_metadata)
        self.proxy.set_block_check(self._check_connection)

        # TLS metadata cache (populated by proxy callback, keyed by dest)
        self._tls_cache = {}

        self.logger.info("✅ NetGuard initialized")

    def _on_tls_metadata(self, metadata: dict):
        """Callback when proxy extracts TLS metadata"""
        if metadata.get("original_dst"):
            dst_ip, dst_port = metadata["original_dst"]
            key = f"{dst_ip}:{dst_port}"
            self._tls_cache[key] = metadata

    def start(self):
        """
        Start NetGuard (blocking).
        Runs the main loop until interrupted with Ctrl+C.
        """
        self.logger.info("🔥 Starting NetGuard Engine...")

        if not self.observer.start_listening():
            self.logger.error("❌ Failed to start observer")
            return

        self.proxy.start()
        self.enforcer.initialize_chains()
        self.dashboard.start()

        self.is_running = True

        self.logger.info("=" * 60)
        self.logger.info("🛡️  NETGUARD - ACTIVE")
        self.logger.info(f"📊 Dashboard: http://localhost:{self.dashboard.port}")
        self.logger.info(f"🛰️  Proxy: {self.proxy.host}:{self.proxy.port}")
        self.logger.info("=" * 60)

        try:
            self._main_loop()
        except KeyboardInterrupt:
            self.logger.info("\n🛑 Shutdown requested...")
        finally:
            self.stop()

    def start_async(self):
        """Start NetGuard in background (non-blocking)"""
        import threading
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop NetGuard and cleanup"""
        self.is_running = False

        self.observer.stop()
        self.proxy.stop()

        self.logger.info("✅ NetGuard stopped")

    def _main_loop(self):
        """
        Background loop: polls the observer for host-level connection
        visibility (dashboard feed, flow stats) and runs periodic cleanup.

        Blocking decisions are NOT made here - they happen synchronously in
        `_check_connection`, invoked by the proxy before it relays a
        connection, so a bad connection never gets a chance to talk to its
        destination in the first place.
        """
        iteration = 0

        while self.is_running:
            iteration += 1

            connections = self.observer.get_active_connections()

            if iteration % 10 == 1:
                self.logger.debug(f"📡 Active connections: {len(connections)}")

            for conn in connections:
                self.dashboard.emit_connection(conn)

            if iteration % 100 == 0:
                self.flow_tracker.cleanup_old_flows()
                self.enforcer.cleanup_expired()

            time.sleep(1)

    def _check_connection(self, conn_info: dict) -> tuple[bool, str]:
        """
        Synchronous decision point invoked by the proxy before relaying a
        connection. Runs feature extraction -> AI analysis (blended with
        ShieldNet's domain reputation) -> decision, and returns
        (blocked, reason).
        """
        client_ip = conn_info["client_ip"]
        sni = conn_info.get("sni") or ""
        dst_ip = conn_info.get("dst_ip", "")

        if self.enforcer.is_client_blocked(client_ip):
            return True, "Client is quarantined"

        if dst_ip and self.db.is_ip_blocked(dst_ip):
            return True, f"Destination IP blocked: {dst_ip}"

        if sni and self.db.is_domain_blocked(sni):
            return True, f"Domain blocked: {sni}"

        tls_metadata = {
            "sni": sni,
            "ja3": conn_info.get("ja3", ""),
            "tls_version": conn_info.get("tls_version", ""),
        }
        # No Android PackageManager on a standalone deployment - see
        # FeatureExtractor._extract_app_features.
        app_metadata = {}

        flow_conn = {
            "uid": client_ip,
            "src_ip": client_ip,
            "src_port": conn_info.get("client_port", 0),
            "dst_ip": dst_ip,
            "dst_port": conn_info.get("dst_port", 0),
            "protocol": conn_info.get("protocol", "TCP"),
            "is_system": False,
        }

        features = self.extractor.extract_features(
            flow_conn, tls_metadata=tls_metadata, app_metadata=app_metadata
        )

        url_reputation = self.url_reputation.check_domain(sni) if sni else None

        verdict = self.ai_engine.analyze(
            features,
            tls_metadata=tls_metadata,
            app_metadata=app_metadata,
            url_reputation=url_reputation,
        )

        action, reason = self.decision_engine.evaluate_verdict(
            uid=client_ip,
            verdict=verdict,
            conn={**flow_conn, "sni": sni},
            package_name=f"client:{client_ip}",
        )

        self.dashboard.emit_verdict(client_ip, verdict, action)

        target = sni or dst_ip
        if action == "BLOCK":
            self.enforcer.block_client(client_ip, reason=reason)
            self.logger.warning(
                f"🚫 BLOCKED: {client_ip} → {target} "
                f"({verdict['classification']}, risk={verdict['risk_score']:.2f})"
            )
            return True, reason

        if action == "WARN":
            self.logger.warning(f"⚠️ WARNING: {client_ip} → {target} ({reason})")
        elif verdict['risk_score'] > 0.2:
            self.logger.debug(f"✅ ALLOW: {client_ip} → {target} (risk={verdict['risk_score']:.2f})")

        return False, reason

    def get_stats(self) -> dict:
        """Get statistics from all layers"""
        return {
            "observer": self.observer.get_stats(),
            "proxy": self.proxy.get_stats(),
            "flow_tracker": self.flow_tracker.get_stats(),
            "ai_engine": self.ai_engine.get_stats(),
            "decision_engine": self.decision_engine.get_stats(),
            "enforcer": self.enforcer.get_stats(),
        }


def main():
    """Main entry point"""
    guard = NetGuard()
    guard.start()


if __name__ == "__main__":
    main()
