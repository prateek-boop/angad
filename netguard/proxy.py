"""
NetGuard - Transparent TCP Proxy
Intercepts and inspects TCP/TLS traffic for SNI and JA3 fingerprinting.

Standalone proxy: no Shizuku/Android privilege bridge. iptables redirection
(if used) is configured with direct subprocess calls under the service's
own Linux privileges (root / CAP_NET_ADMIN).
"""

import logging
import select
import socket
import struct
import threading
from collections.abc import Callable

from .constants import PROXY_PORT
from .shell import run_ip6tables, run_iptables
from .tls_parser import TLSParser


class TransparentProxy:
    """
    Transparent TCP Proxy

    Intercepts TCP connections redirected via iptables and extracts:
    - SNI (Server Name Indication) from TLS ClientHello
    - JA3/JA4 fingerprints for malware identification

    Features:
    - Real TLS ClientHello parsing
    - SO_ORIGINAL_DST support for transparent proxying
    - Non-blocking connection handling
    - Forwards both TLS and non-TLS traffic
    - Pluggable block check consulted before relaying
    """

    CHAIN_NAME = "NETGUARD_PROXY"
    SOCKET_MARK = 0x4E47
    MAX_TLS_RECORD_SIZE = 65540

    def __init__(
        self, host: str = '127.0.0.1', port: int = PROXY_PORT, host_v6: str = '::1'
    ):
        self.host = host
        self.host_v6 = host_v6
        self.port = port
        self.logger = logging.getLogger("PROXY")
        self.tls_parser = TLSParser()

        self.server_sock: socket.socket | None = None
        self.server_sock_v6: socket.socket | None = None
        self.is_running = False

        # Callback for when TLS metadata is extracted
        self._on_tls_metadata: Callable[[dict], None] | None = None

        # Callback consulted before relaying, given the connection's info dict
        # (client_ip, client_port, dst_ip, dst_port, sni, ja3, tls_version,
        # protocol) -> (blocked, reason). This is the real enforcement point:
        # the decision runs before a single byte is relayed.
        self._block_check: Callable[[dict], tuple[bool, str]] | None = None
        self._on_traffic: Callable[[dict, int, int], None] | None = None
        self._iptables_configured = False

        # Stats
        self._connections_handled = 0
        self._connections_ipv4 = 0
        self._connections_ipv6 = 0
        self._tls_extracted = 0
        self._connections_blocked = 0

    def start(self) -> bool:
        """Start the transparent proxy server"""
        try:
            self.server_sock = self._create_listener(socket.AF_INET, self.host)
            self.server_sock_v6 = self._create_listener(socket.AF_INET6, self.host_v6)
            if not self._setup_iptables():
                self._close_listeners()
                return False

            self.is_running = True
            threading.Thread(target=self._accept_loop, daemon=True, name="ProxyAccept").start()
            self.logger.info(
                f"🛰️ Transparent Proxy listening on {self.host}:{self.port} "
                f"and [{self.host_v6}]:{self.port}"
            )
            return True

        except Exception as e:
            self.is_running = False
            self._teardown_iptables()
            self._close_listeners()
            self.logger.error(f"❌ Failed to start proxy: {e}")
            return False

    def _create_listener(self, family: int, host: str) -> socket.socket:
        server = socket.socket(family, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.bind((host, self.port))
            server.listen(100)
            server.setblocking(False)
            return server
        except Exception:
            server.close()
            raise

    def _close_listeners(self):
        for server in (self.server_sock, self.server_sock_v6):
            if server:
                try:
                    server.close()
                except OSError:
                    pass
        self.server_sock = None
        self.server_sock_v6 = None

    def _setup_iptables(self) -> bool:
        """Install an idempotent, process-owned transparent proxy chain."""
        for family, runner in (("IPv4", run_iptables), ("IPv6", run_ip6tables)):
            # Creation may fail when a chain from a previous crash already exists.
            runner(["-t", "nat", "-N", self.CHAIN_NAME])
            code, _, err = runner(["-t", "nat", "-F", self.CHAIN_NAME])
            if code != 0:
                self.logger.error(f"❌ Cannot initialize {family} proxy chain: {err}")
                self._teardown_iptables()
                return False

            rules = [
                ["-t", "nat", "-A", self.CHAIN_NAME, "-m", "mark", "--mark",
                 str(self.SOCKET_MARK), "-j", "RETURN"],
                ["-t", "nat", "-A", self.CHAIN_NAME, "-p", "tcp", "--dport", "80",
                 "-j", "REDIRECT", "--to-ports", str(self.port)],
                ["-t", "nat", "-A", self.CHAIN_NAME, "-p", "tcp", "--dport", "443",
                 "-j", "REDIRECT", "--to-ports", str(self.port)],
            ]
            for rule in rules:
                code, _, err = runner(rule)
                if code != 0:
                    self.logger.error(f"❌ {family} proxy rule failed: {err}")
                    self._teardown_iptables()
                    return False

            jump = ["OUTPUT", "-j", self.CHAIN_NAME]
            code, _, _ = runner(["-t", "nat", "-C", *jump])
            if code != 0:
                code, _, err = runner(
                    ["-t", "nat", "-I", "OUTPUT", "1", "-j", self.CHAIN_NAME]
                )
                if code != 0:
                    self.logger.error(f"❌ Cannot attach {family} proxy chain: {err}")
                    self._teardown_iptables()
                    return False

        self._iptables_configured = True
        return True

    def _teardown_iptables(self):
        """Remove only rules and chains owned by this proxy."""
        for runner in (run_iptables, run_ip6tables):
            jump = ["OUTPUT", "-j", self.CHAIN_NAME]
            for _ in range(32):
                code, _, _ = runner(["-t", "nat", "-C", *jump])
                if code != 0:
                    break
                runner(["-t", "nat", "-D", *jump])
            runner(["-t", "nat", "-F", self.CHAIN_NAME])
            runner(["-t", "nat", "-X", self.CHAIN_NAME])
        self._iptables_configured = False

    def _accept_loop(self):
        """Main loop accepting incoming connections"""
        while self.is_running:
            try:
                listeners = [
                    server for server in (self.server_sock, self.server_sock_v6) if server
                ]
                if not listeners:
                    break
                readable, _, _ = select.select(listeners, [], [], 1.0)

                for server in readable:
                    client_sock, addr = server.accept()
                    client_sock.setblocking(True)
                    client_sock.settimeout(5.0)

                    threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True
                    ).start()

            except Exception as e:
                if self.is_running:
                    self.logger.error(f"Accept error: {e}")

    def _handle_client(self, client_sock: socket.socket, addr: tuple[str, int]):
        """Process an intercepted connection"""
        self._connections_handled += 1
        if client_sock.family == socket.AF_INET6:
            self._connections_ipv6 += 1
        else:
            self._connections_ipv4 += 1
        original_dst = None
        tls_metadata = None

        try:
            original_dst = self._get_original_dst(client_sock)

            data = client_sock.recv(4096)

            if not data:
                return

            conn_info = {
                "client_ip": addr[0],
                "client_port": addr[1],
                "dst_ip": original_dst[0] if original_dst else "",
                "dst_port": original_dst[1] if original_dst else 0,
                "sni": "",
                "ja3": "",
                "tls_version": "",
                "protocol": "TCP",
                "initial_payload": data[:512],
            }

            if data[0] == 0x16:
                full_data = self._read_complete_tls_record(client_sock, data)

                hello = self.tls_parser.parse_client_hello(full_data)

                if hello:
                    self._tls_extracted += 1
                    tls_metadata = self.tls_parser.to_dict(hello)
                    tls_metadata['original_dst'] = original_dst
                    tls_metadata['client_addr'] = addr
                    conn_info.update({
                        "sni": hello.sni or "",
                        "ja3": hello.ja3_hash or "",
                        "tls_version": tls_metadata.get("tls_version", ""),
                        "cipher_count": tls_metadata.get("cipher_count", 0),
                        "extension_count": tls_metadata.get("extension_count", 0),
                    })

                    self.logger.debug(
                        f"🕵️ TLS Inspected: SNI={hello.sni} | JA3={hello.ja3_hash[:16]}..."
                    )

                    if self._on_tls_metadata:
                        try:
                            self._on_tls_metadata(tls_metadata)
                        except Exception as e:
                            self.logger.error(f"Callback error: {e}")

                if self._should_block(conn_info):
                    self._reject_client(client_sock)
                    return

                self._forward_connection(client_sock, full_data, original_dst, conn_info)
            else:
                # Non-TLS traffic (HTTP etc) - forward as-is, still block-checked
                self.logger.debug(f"📦 Non-TLS traffic from {addr}")

                if self._should_block(conn_info):
                    self._reject_client(client_sock)
                    return

                self._forward_connection(client_sock, data, original_dst, conn_info)

        except TimeoutError:
            pass
        except Exception as e:
            self.logger.debug(f"Handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _read_complete_tls_record(self, client_sock: socket.socket, data: bytes) -> bytes:
        """Read the full first TLS record even when TCP split it across reads."""
        while len(data) < 5:
            chunk = client_sock.recv(5 - len(data))
            if not chunk:
                return data
            data += chunk

        record_size = 5 + struct.unpack("!H", data[3:5])[0]
        if record_size > self.MAX_TLS_RECORD_SIZE:
            raise ValueError(f"TLS record exceeds limit: {record_size}")

        while len(data) < record_size:
            chunk = client_sock.recv(min(8192, record_size - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    def _should_block(self, conn_info: dict) -> bool:
        """Consult the block-check callback; close nothing itself, just decides."""
        if not self._block_check:
            return False

        try:
            blocked, reason = self._block_check(conn_info)
        except Exception as e:
            self.logger.error(f"Block check error: {e}")
            return False

        if blocked:
            self._connections_blocked += 1
            self.logger.warning(
                f"🚫 Refusing to relay {conn_info['client_ip']} -> "
                f"{conn_info['sni'] or conn_info['dst_ip']}: {reason}"
            )
        return blocked

    @staticmethod
    def _reject_client(client_sock: socket.socket):
        """Reset a blocked connection immediately instead of making it time out."""
        try:
            client_sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
        except OSError:
            pass

    def _get_original_dst(self, sock: socket.socket) -> tuple[str, int] | None:
        """
        Get original destination using SO_ORIGINAL_DST.
        Only works on Linux with transparent proxy iptables rules.
        """
        try:
            original_dst_option = 80
            if sock.family == socket.AF_INET6:
                dst = sock.getsockopt(socket.IPPROTO_IPV6, original_dst_option, 28)
                port = struct.unpack("!H", dst[2:4])[0]
                flowinfo = struct.unpack("!I", dst[4:8])[0]
                ip = socket.inet_ntop(socket.AF_INET6, dst[8:24])
                scope_id = struct.unpack("=I", dst[24:28])[0]
                return (ip, port, flowinfo, scope_id)

            dst = sock.getsockopt(socket.IPPROTO_IP, original_dst_option, 16)
            port = struct.unpack("!H", dst[2:4])[0]
            ip = socket.inet_ntop(socket.AF_INET, dst[4:8])
            return (ip, port)

        except Exception:
            # Not a transparent-proxy redirected connection
            return None

    def _forward_connection(self, client_sock: socket.socket, initial_data: bytes,
                             original_dst: tuple[str, int] | None,
                             conn_info: dict | None = None):
        """
        Forward the connection to its original destination.
        This enables transparent proxying while still inspecting TLS.
        """
        if not original_dst:
            return

        try:
            family = socket.AF_INET6 if len(original_dst) == 4 else socket.AF_INET
            remote_sock = socket.socket(family, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), self.SOCKET_MARK)
            remote_sock.connect(original_dst)

            remote_sock.sendall(initial_data)
            if self._on_traffic and conn_info:
                self._on_traffic(conn_info, len(initial_data), 0)

            client_sock.settimeout(None)
            remote_sock.settimeout(None)

            def forward(src, dst, outbound):
                try:
                    while True:
                        data = src.recv(8192)
                        if not data:
                            break
                        dst.sendall(data)
                        if self._on_traffic and conn_info:
                            self._on_traffic(
                                conn_info,
                                len(data) if outbound else 0,
                                0 if outbound else len(data),
                            )
                except Exception:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass

            t1 = threading.Thread(target=forward, args=(client_sock, remote_sock, True))
            t2 = threading.Thread(target=forward, args=(remote_sock, client_sock, False))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            remote_sock.close()

        except Exception as e:
            self.logger.debug(f"Forward error: {e}")

    def set_tls_callback(self, callback: Callable[[dict], None]):
        """Set callback for TLS metadata extraction"""
        self._on_tls_metadata = callback

    def set_block_check(self, callback: Callable[[dict], tuple[bool, str]]):
        """Set callback consulted before relaying: conn_info dict -> (blocked, reason)"""
        self._block_check = callback

    def set_traffic_callback(self, callback: Callable[[dict, int, int], None]):
        """Set callback for relayed client-to-server and server-to-client bytes."""
        self._on_traffic = callback

    def get_stats(self) -> dict:
        """Get proxy statistics"""
        return {
            "is_running": self.is_running,
            "connections_handled": self._connections_handled,
            "connections_ipv4": self._connections_ipv4,
            "connections_ipv6": self._connections_ipv6,
            "tls_extracted": self._tls_extracted,
            "connections_blocked": self._connections_blocked,
            "listen_address": f"{self.host}:{self.port}",
            "listen_addresses": [
                f"{self.host}:{self.port}",
                f"[{self.host_v6}]:{self.port}",
            ],
        }

    def stop(self):
        """Stop the proxy server"""
        self.is_running = False

        self._teardown_iptables()

        self._close_listeners()

        self.logger.info("🛑 Transparent Proxy stopped")


def extract_sni_quick(data: bytes) -> str | None:
    """Quick utility to extract SNI from raw packet data without a full proxy instance."""
    parser = TLSParser()
    return parser.quick_extract_sni(data)


def compute_ja3(data: bytes) -> str | None:
    """Quick utility to compute JA3 from raw TLS ClientHello."""
    parser = TLSParser()
    return parser.get_ja3_from_hello(data)
