from netguard.proxy import TransparentProxy, compute_ja3
from netguard.tls_parser import TLSParser


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
