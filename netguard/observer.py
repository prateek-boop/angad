"""
NetGuard - Network Observer
Real-time socket monitoring using Netlink INET_DIAG on Linux.
Falls back to `ss` (direct subprocess) or psutil for development/other platforms.
"""

import socket
import os
import logging
import platform
from typing import List, Dict, Set, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .netlink_parser import NetlinkParser, parse_ss_output
from .shell import run_ss
from .constants import NETLINK_INET_DIAG


class NetworkObserver:
    """
    Network Observer

    Real-time monitoring of network connections:
    - Linux: Netlink INET_DIAG for kernel-level socket events
    - Fallback: `ss` command (direct subprocess)
    - Any platform: psutil for development/testing

    Features:
    - Connection deduplication
    - State tracking (new, active, closed)

    Note: there is no Android PackageManager in a standalone deployment, so
    connections are identified by their local socket owner (`uid` from
    Netlink, or PID from psutil) rather than an app package name.
    """

    def __init__(self):
        self.logger = logging.getLogger("OBSERVER")
        self.platform = platform.system()
        self.is_running = False

        self.netlink_parser = NetlinkParser()

        self.netlink_sock: Optional[socket.socket] = None

        self._active_connections: Dict[str, Dict] = {}
        self._seen_keys: Set[str] = set()

        self._use_netlink = False
        self._use_ss = False
        self._use_psutil = False

    def start_listening(self) -> bool:
        """
        Initialize the observer and start monitoring.
        Automatically selects the best available method.
        """
        self.logger.info("🔌 Starting Network Observer...")

        if self._try_netlink():
            self._use_netlink = True
            self.logger.info("✅ Using Netlink INET_DIAG (real-time kernel events)")
        elif self._try_ss_command():
            self._use_ss = True
            self.logger.info("✅ Using ss command")
        elif self._try_psutil():
            self._use_psutil = True
            self.logger.info("✅ Using psutil (cross-platform fallback)")
        else:
            self.logger.error("❌ No monitoring method available!")
            return False

        self.is_running = True
        return True

    def _try_netlink(self) -> bool:
        """Try to establish Netlink socket (Linux only)"""
        if not hasattr(socket, 'AF_NETLINK'):
            return False

        try:
            self.netlink_sock = socket.socket(
                socket.AF_NETLINK,
                socket.SOCK_DGRAM,
                NETLINK_INET_DIAG
            )
            self.netlink_sock.bind((os.getpid(), 0))
            self.netlink_sock.settimeout(1.0)
            return True
        except Exception as e:
            self.logger.debug(f"Netlink not available: {e}")
            return False

    def _try_ss_command(self) -> bool:
        """Try to use the ss command directly"""
        code, output, _ = run_ss()
        return code == 0 and len(output) > 0

    def _try_psutil(self) -> bool:
        """Try to use psutil for cross-platform monitoring"""
        if not HAS_PSUTIL:
            return False

        try:
            psutil.net_connections(kind='inet')
            return True
        except (psutil.AccessDenied, RuntimeError):
            return False

    def get_active_connections(self) -> List[Dict]:
        """
        Get all currently active network connections.

        Returns:
            List of connection dictionaries with keys:
            - src_ip, dst_ip, src_port, dst_port
            - uid (local socket owner: Linux UID via Netlink, PID via psutil)
            - protocol, state
            - is_new (True if first time seeing this connection)
        """
        if not self.is_running:
            return []

        raw_connections = []

        if self._use_netlink:
            raw_connections = self._query_netlink()
        elif self._use_ss:
            raw_connections = self._query_ss()
        elif self._use_psutil:
            raw_connections = self._query_psutil()

        processed = []
        current_keys = set()

        for conn in raw_connections:
            conn_key = self._get_conn_key(conn)
            current_keys.add(conn_key)

            if conn['dst_ip'] in ('127.0.0.1', '::1', '0.0.0.0'):
                continue

            is_new = conn_key not in self._seen_keys
            if is_new:
                self._seen_keys.add(conn_key)

            uid = conn.get('uid', 0)
            conn['package_name'] = f"uid:{uid}"
            conn['is_system'] = False
            conn['is_new'] = is_new

            processed.append(conn)
            self._active_connections[conn_key] = conn

        closed_keys = set(self._active_connections.keys()) - current_keys
        for key in closed_keys:
            del self._active_connections[key]
            self._seen_keys.discard(key)

        return processed

    def _get_conn_key(self, conn: Dict) -> str:
        """Generate unique key for a connection"""
        inode = conn.get("inode", 0)
        return f"{conn['uid']}-{conn['src_ip']}:{conn['src_port']}-{conn['dst_ip']}:{conn['dst_port']}-{inode}"

    def _query_netlink(self) -> List[Dict]:
        """Query connections using Netlink INET_DIAG"""
        connections = []

        try:
            request = self.netlink_parser.build_inet_diag_request(
                family=socket.AF_INET,
                states=0xFFF  # All TCP states
            )
            self.netlink_sock.send(request)

            response = b''
            while True:
                try:
                    chunk = self.netlink_sock.recv(65536)
                    if not chunk:
                        break
                    response += chunk

                    offset = 0
                    done = False
                    while offset + 16 <= len(chunk):
                        length = int.from_bytes(chunk[offset:offset + 4], 'little')
                        if length < 16 or offset + length > len(chunk):
                            break
                        nlmsg_type = int.from_bytes(chunk[offset + 4:offset + 6], 'little')
                        if nlmsg_type == 3:  # NLMSG_DONE
                            done = True
                            break
                        offset += (length + 3) & ~3
                    if done:
                        break
                except socket.timeout:
                    break

            sockets = self.netlink_parser.parse_netlink_response(response)
            connections = [s.to_dict() for s in sockets]

        except Exception as e:
            self.logger.error(f"❌ Netlink query failed: {e}")

        return connections

    def _query_ss(self) -> List[Dict]:
        """Query connections using ss directly"""
        code, output, err = run_ss()

        if code != 0:
            self.logger.error(f"ss command failed: {err}")
            return []

        return parse_ss_output(output)

    def _query_psutil(self) -> List[Dict]:
        """Query connections using psutil"""
        connections = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED' or not conn.raddr:
                    continue

                connections.append({
                    "src_ip": conn.laddr.ip,
                    "dst_ip": conn.raddr.ip,
                    "src_port": conn.laddr.port,
                    "dst_port": conn.raddr.port,
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "uid": conn.pid or 0,  # psutil exposes PID, not owner UID
                    "state": conn.status,
                    "tx_bytes": 0,
                    "rx_bytes": 0,
                })
        except psutil.AccessDenied:
            self.logger.warning("⚠️ Access denied - run with elevated privileges for full visibility")
        except Exception as e:
            self.logger.error(f"❌ psutil query failed: {e}")

        return connections

    def get_connection_count(self) -> int:
        """Get number of currently tracked connections"""
        return len(self._active_connections)

    def get_stats(self) -> Dict:
        """Get observer statistics"""
        return {
            "is_running": self.is_running,
            "method": "netlink" if self._use_netlink else "ss" if self._use_ss else "psutil",
            "active_connections": len(self._active_connections),
            "total_seen": len(self._seen_keys),
        }

    def stop(self):
        """Stop the observer"""
        self.is_running = False
        if self.netlink_sock:
            try:
                self.netlink_sock.close()
            except Exception:
                pass
        self.logger.info("🛑 Network Observer stopped")
