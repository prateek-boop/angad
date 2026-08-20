"""
NetGuard - Enforcement Engine
Kernel-level blocking via direct iptables subprocess calls.

Standalone Linux service, no Shizuku/ADB/root-workaround: the process runs
under its own privileges (root, or CAP_NET_ADMIN) and calls iptables
directly.
"""

import logging
import ipaddress
import threading
import time

from . import constants
from .shell import run_ip6tables, run_iptables


class EnforcementEngine:
    """
    Enforcement Engine

    Executes kernel-level blocking using iptables.

    Features:
    - Block by IP address (destination)
    - Block by client source IP (quarantine a device behind the proxy)
    - Temporary blocks with expiration
    - Automatic cleanup of expired rules
    - Allowlist protection for critical/infrastructure addresses
    """

    # Client IPs that must never be blocked (proxy's own address, loopback,
    # configured gateway/DNS IPs).
    PROTECTED_CLIENT_IPS = constants.PROTECTED_CLIENT_IPS

    # Chain name for our rules
    CHAIN_NAME = "NETGUARD"

    def __init__(self):
        self.logger = logging.getLogger("ENFORCER")

        # Track active blocks
        self._blocked_ips: dict[str, float] = {}       # ip -> expiry timestamp
        self._blocked_clients: dict[str, float] = {}   # client source ip -> expiry timestamp

        self.is_initialized = False
        self._lock = threading.RLock()

    def initialize_chains(self) -> bool:
        """
        Initialize iptables chains for NetGuard.
        Must be called before any blocking operations.
        """
        self.logger.info("🛠️ Initializing Enforcement Engine (iptables)...")

        success = self._init_iptables()
        self.is_initialized = success

        if success:
            self.logger.info("✅ Enforcement Engine ready")
        else:
            self.logger.warning("⚠️ Enforcement Engine in limited mode")

        return success

    def _init_iptables(self) -> bool:
        """Initialize iptables chains"""
        try:
            for family, runner in (("IPv4", run_iptables), ("IPv6", run_ip6tables)):
                # Creation may fail when an owned chain from a previous crash exists.
                runner(["-N", self.CHAIN_NAME])

                code, _, err = runner(["-F", self.CHAIN_NAME])
                if code != 0:
                    self.logger.error(f"❌ Cannot flush {family} enforcement chain: {err}")
                    self.stop()
                    return False

                code, _, _ = runner(["-C", "OUTPUT", "-j", self.CHAIN_NAME])
                if code != 0:
                    code, _, err = runner(
                        ["-I", "OUTPUT", "1", "-j", self.CHAIN_NAME]
                    )
                    if code != 0:
                        self.logger.error(
                            f"❌ Cannot attach {family} enforcement chain: {err}"
                        )
                        self.stop()
                        return False

            self.logger.info(f"✅ iptables chain '{self.CHAIN_NAME}' initialized")
            return True

        except Exception as e:
            self.logger.error(f"❌ iptables init failed: {e}")
            return False

    def block_ip(self, ip: str, reason: str = "Threat detected",
                 duration_hours: int | None = None) -> bool:
        """
        Block a specific destination IP address.

        Args:
            ip: IP address to block
            reason: Reason for blocking (logged)
            duration_hours: Optional block duration (None = permanent)

        Returns:
            True if block was successful
        """
        if not self._validate_ip(ip):
            self.logger.error(f"❌ Invalid IP format: {ip}")
            return False

        if ip in ('127.0.0.1', '0.0.0.0', '::1'):
            self.logger.warning(f"⚠️ Cannot block localhost: {ip}")
            return False

        self.logger.critical(f"🚫 BLOCKING IP: {ip} (Reason: {reason})")

        expiry = time.time() + (duration_hours * 3600) if duration_hours else float('inf')

        success = self._iptables_block_ip(ip)

        if success:
            with self._lock:
                self._blocked_ips[ip] = expiry
            self.logger.info(f"🛡️ IP {ip} blocked successfully")

        return success

    def _iptables_block_ip(self, ip: str) -> bool:
        """Block destination IP using iptables"""
        runner = self._runner_for_ip(ip)
        code, _, _ = runner(["-C", self.CHAIN_NAME, "-d", ip, "-j", "DROP"])
        if code == 0:
            return True  # Already blocked

        code, _, _ = runner(["-A", self.CHAIN_NAME, "-d", ip, "-j", "DROP"])
        return code == 0

    def block_client(self, client_ip: str, reason: str = "Suspicious behavior",
                      duration_hours: int | None = None) -> bool:
        """
        Quarantine a client (device behind the proxy) by source IP.

        Args:
            client_ip: source IP of the client to block
            reason: Reason for blocking
            duration_hours: Optional block duration

        Returns:
            True if block was successful
        """
        if client_ip in self.PROTECTED_CLIENT_IPS:
            self.logger.warning(f"⚠️ Cannot block protected client: {client_ip}")
            return False

        if not self._validate_ip(client_ip):
            self.logger.error(f"❌ Invalid client IP format: {client_ip}")
            return False

        self.logger.critical(f"🚫 QUARANTINING CLIENT: {client_ip} (Reason: {reason})")

        expiry = time.time() + (duration_hours * 3600) if duration_hours else float('inf')

        success = self._iptables_block_client(client_ip)

        if success:
            with self._lock:
                self._blocked_clients[client_ip] = expiry
            self.logger.info(f"🛡️ Client {client_ip} quarantined successfully")

        return success

    def _iptables_block_client(self, client_ip: str) -> bool:
        """Block a client's traffic by source IP"""
        runner = self._runner_for_ip(client_ip)
        code, _, _ = runner(["-C", self.CHAIN_NAME, "-s", client_ip, "-j", "DROP"])
        if code == 0:
            return True  # Already blocked

        code, _, _ = runner(["-A", self.CHAIN_NAME, "-s", client_ip, "-j", "DROP"])
        return code == 0

    def unblock_ip(self, ip: str) -> bool:
        """Remove block for a destination IP address"""
        if not self._validate_ip(ip):
            return False

        self.logger.info(f"🔓 Unblocking IP: {ip}")

        code, _, _ = self._runner_for_ip(ip)(
            ["-D", self.CHAIN_NAME, "-d", ip, "-j", "DROP"]
        )
        success = code == 0

        if success:
            with self._lock:
                self._blocked_ips.pop(ip, None)

        return success

    def unblock_client(self, client_ip: str) -> bool:
        """Remove quarantine for a client"""
        self.logger.info(f"🔓 Unblocking client: {client_ip}")

        if not self._validate_ip(client_ip):
            return False
        code, _, _ = self._runner_for_ip(client_ip)(
            ["-D", self.CHAIN_NAME, "-s", client_ip, "-j", "DROP"]
        )
        success = code == 0

        if success:
            with self._lock:
                self._blocked_clients.pop(client_ip, None)

        return success

    def cleanup_expired(self):
        """Remove expired blocks"""
        now = time.time()

        with self._lock:
            expired_ips = [ip for ip, expiry in self._blocked_ips.items() if expiry < now]
            expired_clients = [c for c, expiry in self._blocked_clients.items() if expiry < now]

        for ip in expired_ips:
            self.unblock_ip(ip)
            self.logger.info(f"⏰ Expired IP block removed: {ip}")

        for client_ip in expired_clients:
            self.unblock_client(client_ip)
            self.logger.info(f"⏰ Expired client block removed: {client_ip}")

    def flush_all_rules(self):
        """Remove all NetGuard blocking rules"""
        self.logger.warning("🧹 Flushing all NetGuard rules...")

        run_iptables(["-F", self.CHAIN_NAME])
        run_ip6tables(["-F", self.CHAIN_NAME])

        with self._lock:
            self._blocked_ips.clear()
            self._blocked_clients.clear()

        self.logger.info("✅ All rules flushed")

    def _validate_ip(self, ip: str) -> bool:
        """Validate an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _runner_for_ip(ip: str):
        return run_ip6tables if ipaddress.ip_address(ip).version == 6 else run_iptables

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if a destination IP is currently blocked"""
        with self._lock:
            return ip in self._blocked_ips

    def is_client_blocked(self, client_ip: str) -> bool:
        """Check if a client source IP is currently blocked"""
        with self._lock:
            return client_ip in self._blocked_clients

    def get_blocked_ips(self) -> list[str]:
        """Get list of currently blocked destination IPs"""
        with self._lock:
            return list(self._blocked_ips.keys())

    def get_blocked_clients(self) -> list[str]:
        """Get list of currently blocked client IPs"""
        with self._lock:
            return list(self._blocked_clients.keys())

    def get_stats(self) -> dict:
        """Get enforcement statistics"""
        with self._lock:
            return {
                "is_initialized": self.is_initialized,
                "blocked_ips": len(self._blocked_ips),
                "blocked_clients": len(self._blocked_clients),
                "chain_name": self.CHAIN_NAME,
            }

    def stop(self):
        """Detach and remove all firewall state owned by the enforcer."""
        for runner in (run_iptables, run_ip6tables):
            for _ in range(32):
                code, _, _ = runner(["-C", "OUTPUT", "-j", self.CHAIN_NAME])
                if code != 0:
                    break
                runner(["-D", "OUTPUT", "-j", self.CHAIN_NAME])
            runner(["-F", self.CHAIN_NAME])
            runner(["-X", self.CHAIN_NAME])
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_clients.clear()
            self.is_initialized = False
