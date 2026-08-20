"""
NetGuard - Global Constants and Thresholds
"""

import os

# === AI THRESHOLDS ===
INSTANT_BLOCK_THRESHOLD = 0.90  # Risk score for immediate block
WARN_THRESHOLD = 0.55           # Risk score to issue warning
SAFE_THRESHOLD = 0.25           # Below this = definitely safe
STRIKE_LIMIT = 5                # Warnings before auto-block

# === NETWORK PORTS ===
SAFE_PORTS = {80, 443, 8080, 53, 853}  # HTTP, HTTPS, Alt-HTTP, DNS, DoT
SUSPICIOUS_PORTS = {4444, 5555, 6666, 8888, 1337, 31337}  # Common malware ports
PROXY_PORT = 8888               # Local transparent proxy port
DASHBOARD_PORT = 8080           # Dashboard API port
WEBSOCKET_PORT = 8765           # WebSocket live feed port

# === FEATURE VECTOR ===
FEATURE_COUNT = 42              # Total features in vector
FEATURE_SCHEMA = "netguard-42-v1"
DNS_FEATURES = 11
FLOW_FEATURES = 12
APP_FEATURES = 5
TLS_FEATURES = 8
TEMPORAL_FEATURES = 6

# === NETLINK CONSTANTS ===
NETLINK_INET_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
TCP_ESTABLISHED = 1
TCP_LISTEN = 10

# === TLS CONSTANTS ===
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_VERSIONS = {
    0x0301: "1.0",
    0x0302: "1.1", 
    0x0303: "1.2",
    0x0304: "1.3"
}

# === RISKY TLDs ===
RISKY_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains (abuse)
    '.xyz', '.top', '.win', '.loan',     # Cheap spam TLDs
    '.onion', '.bit'                      # Dark web
}

# === JA3 THREAT SIGNATURES ===
KNOWN_MALWARE_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "TrickBot",
    "51c64c77e60f3980eea90869b68c58a8": "Emotet",
    "6734f37431670b3ab4292b8f60f29984": "Dridex",
    "72a589da586844d7f0818ce684948eea": "Gozi",
    "a0e9f5d64349fb13191bc781f81f42e1": "IcedID",
}

# === LINUX BINARIES (PATH-resolved, standalone service) ===
IPTABLES_BIN = "iptables"
IP6TABLES_BIN = "ip6tables"
SS_BIN = "ss"

# === INFRASTRUCTURE ALLOWLIST ===
# Client IPs that enforcement must never block, regardless of verdict
# (the proxy's own address, loopback, and any configured gateway/DNS IPs).
PROTECTED_CLIENT_IPS = {"127.0.0.1", "::1"}

# === DATABASE ===
DB_PATH = os.path.join(os.getenv("SHIELDNET_DATA_DIR", "."), "netguard_reputation.db")
