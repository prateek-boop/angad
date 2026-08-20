"""
NetGuard - AI-Powered Standalone TCP Proxy Firewall
Real-time network security with hybrid AI detection, combined with
ShieldNet's URL/domain reputation model.

Components:
- Observer - real-time network monitoring via Netlink/ss/psutil
- Proxy - transparent TCP interception, TLS SNI/JA3 extraction, and the
  synchronous pre-relay block decision
- Extractor - 42-dimensional traffic feature vector extraction
- AI Engine - hybrid Isolation Forest + trained classifiers, blended with
  ShieldNet's domain/URL reputation
- Decision - behavioral analysis + strike system
- Enforcement - iptables blocking (direct subprocess, no Shizuku/Android)
- Dashboard - real-time web UI

Usage:
    from netguard import NetGuard
    guard = NetGuard()
    guard.start()
"""

__version__ = "4.0.0"

__all__ = ["NetGuard", "main"]


def __getattr__(name):
    """Keep lightweight submodule imports from initializing the ML stack."""
    if name in __all__:
        from .main import NetGuard, main

        return {"NetGuard": NetGuard, "main": main}[name]
    raise AttributeError(name)
