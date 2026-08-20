import socket
import struct
import threading

import netguard.proxy as proxy_module
from netguard.proxy import TransparentProxy, compute_ja3
from netguard.tls_parser import TLSParser

CHAIN_NAME = "NETGUARD_PROXY"
SOCKET_MARK = 0x4E47
MAX_TLS_RECORD_SIZE = 65540


def _install_proxy_constants(monkeypatch):
    monkeypatch.setattr(TransparentProxy, "CHAIN_NAME", CHAIN_NAME, raising=False)
    monkeypatch.setattr(TransparentProxy, "SOCKET_MARK", SOCKET_MARK, raising=False)
    monkeypatch.setattr(
        TransparentProxy, "MAX_TLS_RECORD_SIZE", MAX_TLS_RECORD_SIZE, raising=False
    )


def _tls_client_hello_with_sni(sni: str = "example.com") -> bytes:
    """Build a minimal-but-structurally-valid TLS 1.2 ClientHello with an SNI extension."""
    hostname = sni.encode()

    server_name_entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname  # [type][len][name]
    sni_ext_data = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data  # ext_type=SNI(0x0000)

    extensions_block = len(sni_ext).to_bytes(2, "big") + sni_ext

    random_bytes = bytes(range(1, 33))  # avoid zero bytes that could confuse naive scanners
    session_id = b"\x00"  # zero-length session id
    cipher_suites = b"\x00\x02\x00\x2f"  # length=2, one cipher (TLS_RSA_WITH_AES_128_CBC_SHA)
    compression = b"\x01\x00"  # length=1, null compression

    client_hello_body = (
        b"\x03\x03"  # client version TLS 1.2
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def test_parse_client_hello_extracts_sni():
    data = _tls_client_hello_with_sni("netguard.example")
    hello = TLSParser().parse_client_hello(data)

    assert hello is not None
    assert hello.sni == "netguard.example"


def test_compute_ja3_returns_hash_for_valid_hello():
    data = _tls_client_hello_with_sni("example.com")
    ja3 = compute_ja3(data)
    assert ja3 is not None
    assert len(ja3) == 32  # md5 hex digest


def test_proxy_configuration_constants_are_class_attributes():
    assert TransparentProxy.CHAIN_NAME == CHAIN_NAME
    assert TransparentProxy.SOCKET_MARK == SOCKET_MARK
    assert TransparentProxy.MAX_TLS_RECORD_SIZE == MAX_TLS_RECORD_SIZE


def test_read_complete_tls_record_collects_fragmented_header_and_body(monkeypatch):
    _install_proxy_constants(monkeypatch)
    record = _tls_client_hello_with_sni("fragmented.example")

    class FragmentedSocket:
        def __init__(self, fragments):
            self.fragments = list(fragments)

        def recv(self, size):
            fragment = self.fragments.pop(0)
            assert len(fragment) <= size
            return fragment

    initial = record[:2]
    fragments = [record[2:4], record[4:5], record[5:17], record[17:]]

    fragmented_socket = FragmentedSocket(fragments)
    result = TransparentProxy()._read_complete_tls_record(fragmented_socket, initial)

    assert result == record
    assert not fragmented_socket.fragments


def test_iptables_setup_uses_owned_chain_mark_exemption_and_single_jump(monkeypatch):
    _install_proxy_constants(monkeypatch)
    calls = []
    state = {"chain": False, "rules": [], "jumps": 0}

    def fake_run_iptables(args):
        calls.append(args)
        operation = args[2]
        if operation == "-N":
            if state["chain"]:
                return 1, "", "Chain already exists"
            state["chain"] = True
        elif operation == "-F":
            if not state["chain"]:
                return 1, "", "No chain"
            state["rules"].clear()
        elif operation == "-A":
            state["rules"].append(args[4:])
        elif operation == "-C":
            return (0 if state["jumps"] else 1), "", ""
        elif operation == "-I":
            state["jumps"] += 1
        return 0, "", ""

    monkeypatch.setattr(proxy_module, "run_iptables", fake_run_iptables)
    monkeypatch.setattr(proxy_module, "run_ip6tables", lambda args: (0, "", ""))
    proxy = TransparentProxy(port=18443)

    assert proxy._setup_iptables() is True
    assert proxy._setup_iptables() is True

    assert state["jumps"] == 1
    assert state["rules"] == [
        ["-m", "mark", "--mark", str(SOCKET_MARK), "-j", "RETURN"],
        ["-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "18443"],
        ["-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "18443"],
    ]
    assert calls.count(["-t", "nat", "-I", "OUTPUT", "1", "-j", CHAIN_NAME]) == 1
    assert [call for call in calls if call[2] == "-C"] == [
        ["-t", "nat", "-C", "OUTPUT", "-j", CHAIN_NAME],
        ["-t", "nat", "-C", "OUTPUT", "-j", CHAIN_NAME],
    ]


def test_iptables_teardown_removes_all_jumps_then_flushes_and_deletes_chain(monkeypatch):
    _install_proxy_constants(monkeypatch)
    calls = []
    jumps = 2

    def fake_run_iptables(args):
        nonlocal jumps
        calls.append(args)
        if args[2] == "-C":
            return (0 if jumps else 1), "", ""
        if args[2] == "-D":
            jumps -= 1
        return 0, "", ""

    monkeypatch.setattr(proxy_module, "run_iptables", fake_run_iptables)
    monkeypatch.setattr(proxy_module, "run_ip6tables", lambda args: (1, "", ""))
    proxy = TransparentProxy()
    proxy._iptables_configured = True

    proxy._teardown_iptables()

    assert calls.count(["-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAME]) == 2
    assert calls[-2:] == [
        ["-t", "nat", "-F", CHAIN_NAME],
        ["-t", "nat", "-X", CHAIN_NAME],
    ]
    assert proxy._iptables_configured is False


def test_proxy_setup_installs_ipv6_redirect_rules(monkeypatch):
    _install_proxy_constants(monkeypatch)
    calls = []

    def fake_runner(args):
        calls.append(args)
        return (1, "", "") if args[2] == "-C" else (0, "", "")

    monkeypatch.setattr(proxy_module, "run_iptables", lambda args: (0, "", ""))
    monkeypatch.setattr(proxy_module, "run_ip6tables", fake_runner)

    assert TransparentProxy(port=18443)._setup_iptables() is True
    assert [
        "-t", "nat", "-A", CHAIN_NAME, "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-ports", "18443",
    ] in calls
    assert ["-t", "nat", "-I", "OUTPUT", "1", "-j", CHAIN_NAME] in calls


def test_get_original_destination_supports_ipv6():
    raw = (
        struct.pack("=H", socket.AF_INET6)
        + struct.pack("!H", 443)
        + struct.pack("!I", 7)
        + socket.inet_pton(socket.AF_INET6, "2001:db8::123")
        + struct.pack("=I", 4)
    )

    class OriginalDestinationSocket:
        family = socket.AF_INET6

        def getsockopt(self, level, option, size):
            assert (level, option, size) == (socket.IPPROTO_IPV6, 80, 28)
            return raw

    assert TransparentProxy()._get_original_dst(OriginalDestinationSocket()) == (
        "2001:db8::123", 443, 7, 4
    )


def test_forwarding_waits_for_both_directions_and_reports_traffic(monkeypatch):
    _install_proxy_constants(monkeypatch)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client, proxy_client = socket.socketpair()
    initial = b"initial-"
    outbound = b"request"
    response = b"delayed-response"
    request_received = threading.Event()
    release_response = threading.Event()
    server_errors = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                received = bytearray()
                while chunk := connection.recv(8192):
                    received.extend(chunk)
                assert bytes(received) == initial + outbound
                request_received.set()
                assert release_response.wait(2)
                connection.sendall(response)
        except Exception as exc:
            server_errors.append(exc)
            request_received.set()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()

    real_socket = socket.socket
    marks = []

    class OutboundSocket:
        def __init__(self, wrapped_socket):
            self.socket = wrapped_socket

        def setsockopt(self, level, option, value):
            if level == socket.SOL_SOCKET and option == getattr(socket, "SO_MARK", 36):
                marks.append(value)
                return
            self.socket.setsockopt(level, option, value)

        def __getattr__(self, name):
            return getattr(self.socket, name)

    def socket_factory(*args, **kwargs):
        wrapped_socket = real_socket(*args, **kwargs)
        if kwargs.get("fileno") is not None:
            return wrapped_socket
        return OutboundSocket(wrapped_socket)

    monkeypatch.setattr(proxy_module.socket, "socket", socket_factory)
    traffic = []
    conn_info = {"client_ip": "127.0.0.1", "dst_ip": "127.0.0.1"}
    proxy = TransparentProxy()
    proxy.set_traffic_callback(lambda info, tx, rx: traffic.append((info, tx, rx)))
    relay_thread = threading.Thread(
        target=proxy._forward_connection,
        args=(proxy_client, initial, listener.getsockname(), conn_info),
        daemon=True,
    )

    try:
        relay_thread.start()
        client.sendall(outbound)
        client.shutdown(socket.SHUT_WR)

        assert request_received.wait(2)
        assert not server_errors
        assert relay_thread.is_alive()

        release_response.set()
        received = bytearray()
        while chunk := client.recv(8192):
            received.extend(chunk)

        relay_thread.join(2)
        server_thread.join(2)
        assert not relay_thread.is_alive()
        assert not server_thread.is_alive()
        assert not server_errors
        assert bytes(received) == response
        assert marks == [SOCKET_MARK]
        assert sum(tx for _, tx, _ in traffic) == len(initial) + len(outbound)
        assert sum(rx for _, _, rx in traffic) == len(response)
        assert all(info is conn_info for info, _, _ in traffic)
    finally:
        release_response.set()
        client.close()
        proxy_client.close()
        listener.close()


def test_block_check_refuses_relay_without_forwarding(monkeypatch):
    proxy = TransparentProxy()

    calls = {"forwarded": False}

    def fake_forward(self, client_sock, initial_data, original_dst):
        calls["forwarded"] = True

    monkeypatch.setattr(TransparentProxy, "_forward_connection", fake_forward)

    proxy.set_block_check(lambda conn_info: (True, "blocked for test"))

    blocked = proxy._should_block({
        "client_ip": "10.0.0.9",
        "client_port": 1234,
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "sni": "bad.example",
        "ja3": "",
        "tls_version": "",
        "protocol": "TCP",
    })

    assert blocked is True
    assert proxy.get_stats()["connections_blocked"] == 1
    assert calls["forwarded"] is False


def test_block_check_allows_relay_when_not_blocked():
    proxy = TransparentProxy()
    proxy.set_block_check(lambda conn_info: (False, "ok"))

    blocked = proxy._should_block({
        "client_ip": "10.0.0.9",
        "client_port": 1234,
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "sni": "good.example",
        "ja3": "",
        "tls_version": "",
        "protocol": "TCP",
    })

    assert blocked is False
    assert proxy.get_stats()["connections_blocked"] == 0


def test_no_block_check_set_defaults_to_allow():
    proxy = TransparentProxy()
    conn_info = {"client_ip": "10.0.0.1", "sni": "x", "dst_ip": "", "protocol": "TCP"}
    assert proxy._should_block(conn_info) is False
