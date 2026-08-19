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
from .shell import run_iptables
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

    def __init__(self, host: str = '127.0.0.1', port: int = PROXY_PORT):
        self.host = host
        self.port = port
        self.logger = logging.getLogger("PROXY")
        self.tls_parser = TLSParser()

        self.server_sock: socket.socket | None = None
        self.is_running = False

        # Callback for when TLS metadata is extracted
        self._on_tls_metadata: Callable[[dict], None] | None = None

        # Callback consulted before relaying, given the connection's info dict
        # (client_ip, client_port, dst_ip, dst_port, sni, ja3, tls_version,
        # protocol) -> (blocked, reason). This is the real enforcement point:
        # the decision runs before a single byte is relayed.
        self._block_check: Callable[[dict], tuple[bool, str]] | None = None

        # Stats
        self._connections_handled = 0
        self._tls_extracted = 0
        self._connections_blocked = 0

    def start(self) -> bool:
        """Start the transparent proxy server"""
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(100)
            self.server_sock.setblocking(False)

            self.is_running = True

            threading.Thread(target=self._accept_loop, daemon=True, name="ProxyAccept").start()

            self.logger.info(f"🛰️ Transparent Proxy listening on {self.host}:{self.port}")

            self._setup_iptables()

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to start proxy: {e}")
            return False

    def _setup_iptables(self):
        """Configure iptables to redirect traffic to this proxy (Linux only)"""
        run_iptables(["-t", "nat", "-N", "NETGUARD_PROXY"])

        rules = [
            ["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-ports", str(self.port)],
            ["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-ports", str(self.port)],
        ]

        for rule in rules:
            code, _, err = run_iptables(rule)
            if code == 0:
                self.logger.info(f"✅ iptables rule added: {' '.join(rule)}")
            else:
                self.logger.warning(f"⚠️ iptables rule failed: {err}")

    def _accept_loop(self):
        """Main loop accepting incoming connections"""
        while self.is_running:
            try:
                readable, _, _ = select.select([self.server_sock], [], [], 1.0)

                if readable:
                    client_sock, addr = self.server_sock.accept()
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
        original_dst = None
        tls_metadata = None

        try:
            original_dst = self._get_original_dst(client_sock)

            data = client_sock.recv(4096, socket.MSG_PEEK)

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
            }

            if data[0] == 0x16:
                full_data = client_sock.recv(4096)

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
                    return

                self._forward_connection(client_sock, full_data, original_dst)
            else:
                # Non-TLS traffic (HTTP etc) - forward as-is, still block-checked
                self.logger.debug(f"📦 Non-TLS traffic from {addr}")

                if self._should_block(conn_info):
                    return

                full_data = client_sock.recv(4096)
                self._forward_connection(client_sock, full_data, original_dst)

        except TimeoutError:
            pass
        except Exception as e:
            self.logger.debug(f"Handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

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

    def _get_original_dst(self, sock: socket.socket) -> tuple[str, int] | None:
        """
        Get original destination using SO_ORIGINAL_DST.
        Only works on Linux with transparent proxy iptables rules.
        """
        try:
            SO_ORIGINAL_DST = 80

            dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)

            # sockaddr_in: [family:2][port:2][ip:4][zero:8]
            port = struct.unpack("!H", dst[2:4])[0]
            ip = socket.inet_ntoa(dst[4:8])

            return (ip, port)

        except Exception:
            # Not a transparent-proxy redirected connection
            return None

    def _forward_connection(self, client_sock: socket.socket, initial_data: bytes,
                             original_dst: tuple[str, int] | None):
        """
        Forward the connection to its original destination.
        This enables transparent proxying while still inspecting TLS.
        """
        if not original_dst:
            return

        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect(original_dst)

            remote_sock.sendall(initial_data)

            def forward(src, dst):
                try:
                    while True:
                        data = src.recv(8192)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        src.close()
                        dst.close()
                    except Exception:
                        pass

            t1 = threading.Thread(target=forward, args=(client_sock, remote_sock))
            t2 = threading.Thread(target=forward, args=(remote_sock, client_sock))
            t1.start()
            t2.start()

        except Exception as e:
            self.logger.debug(f"Forward error: {e}")

    def set_tls_callback(self, callback: Callable[[dict], None]):
        """Set callback for TLS metadata extraction"""
        self._on_tls_metadata = callback

    def set_block_check(self, callback: Callable[[dict], tuple[bool, str]]):
        """Set callback consulted before relaying: conn_info dict -> (blocked, reason)"""
        self._block_check = callback

    def get_stats(self) -> dict:
        """Get proxy statistics"""
        return {
            "is_running": self.is_running,
            "connections_handled": self._connections_handled,
            "tls_extracted": self._tls_extracted,
            "connections_blocked": self._connections_blocked,
            "listen_address": f"{self.host}:{self.port}",
        }

    def stop(self):
        """Stop the proxy server"""
        self.is_running = False

        run_iptables(["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "80",
                      "-j", "REDIRECT", "--to-ports", str(self.port)])
        run_iptables(["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "443",
                      "-j", "REDIRECT", "--to-ports", str(self.port)])

        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

        self.logger.info("🛑 Transparent Proxy stopped")


def extract_sni_quick(data: bytes) -> str | None:
    """Quick utility to extract SNI from raw packet data without a full proxy instance."""
    parser = TLSParser()
    return parser.quick_extract_sni(data)


def compute_ja3(data: bytes) -> str | None:
    """Quick utility to compute JA3 from raw TLS ClientHello."""
    parser = TLSParser()
    return parser.get_ja3_from_hello(data)
