import threading

from integrations.netguard_bridge import UrlReputationBridge


class FakeOrchestrator:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def scan(self, url, depth="tier0", timeout_ms=None):
        self.calls.append((url, depth))
        return self.result


def test_check_domain_returns_scan_result_for_known_bad():
    orchestrator = FakeOrchestrator({
        "category": "phishing",
        "risk_score": 0.92,
        "decision": "review",
        "reasons": ["model classification"],
        "evidence": [],
    })
    bridge = UrlReputationBridge(orchestrator=orchestrator)

    result = bridge.check_domain("login.totally-not-a-bank.xyz")

    assert result["category"] == "phishing"
    assert result["risk_score"] == 0.92
    assert result["decision"] == "review"
    assert result["canonical_domain"] == "totally-not-a-bank.xyz"
    assert result["enforcement_authorized"] is False
    assert orchestrator.calls == [("https://totally-not-a-bank.xyz", "tier0")]


def test_check_domain_only_authorizes_verified_block_evidence():
    orchestrator = FakeOrchestrator({
        "category": "malware",
        "risk_score": 1.0,
        "decision": "block",
        "reasons": ["Exact URL match in URLhaus."],
        "evidence": [
            {"source": "reputation", "severity": "critical"},
        ],
    })
    result = UrlReputationBridge(orchestrator=orchestrator).check_domain("bad.xyz")

    assert result["enforcement_authorized"] is True
    assert result["verified_sources"] == ["reputation"]


def test_check_domain_returns_scan_result_for_known_safe():
    orchestrator = FakeOrchestrator({
        "category": "safe",
        "risk_score": 0.02,
        "decision": "allow",
        "reasons": [],
    })
    bridge = UrlReputationBridge(orchestrator=orchestrator)

    result = bridge.check_domain("example.com")

    assert result["category"] == "safe"
    assert result["decision"] == "allow"


def test_registered_domain_result_is_cached_across_subdomains():
    orchestrator = FakeOrchestrator({
        "category": "safe",
        "risk_score": 0.02,
        "decision": "allow",
        "reasons": [],
    })
    bridge = UrlReputationBridge(orchestrator=orchestrator)

    first = bridge.check_domain("api.github.com")
    second = bridge.check_domain("uploads.github.com")

    assert first == second
    assert orchestrator.calls == [("https://github.com", "tier0")]
    assert bridge.get_stats()["cache_hits"] == 1


def test_concurrent_model_scan_fails_open_instead_of_queuing_tls():
    entered = threading.Event()
    release = threading.Event()

    class SlowOrchestrator(FakeOrchestrator):
        def scan(self, url, depth="tier0", timeout_ms=None):
            self.calls.append((url, depth))
            entered.set()
            assert release.wait(2)
            return self.result

    orchestrator = SlowOrchestrator({
        "category": "safe",
        "risk_score": 0.02,
        "decision": "allow",
        "reasons": [],
    })
    bridge = UrlReputationBridge(orchestrator=orchestrator, scan_wait_s=0.01)
    worker = threading.Thread(target=bridge.check_domain, args=("first.example.com",))
    worker.start()
    assert entered.wait(1)

    busy_result = bridge.check_domain("second.example.net")
    release.set()
    worker.join(2)

    assert busy_result["decision"] == "allow"
    assert busy_result["enforcement_authorized"] is False
    assert bridge.get_stats()["busy_fail_open"] == 1
    assert len(orchestrator.calls) == 1


def test_check_domain_neutral_on_empty_sni():
    bridge = UrlReputationBridge(orchestrator=FakeOrchestrator({}))
    result = bridge.check_domain("")
    assert result == {
        "category": "safe",
        "risk_score": 0.0,
        "decision": "allow",
        "reasons": [],
        "canonical_domain": None,
        "verified_sources": [],
        "enforcement_authorized": False,
    }


def test_check_domain_neutral_on_scan_failure():
    class FailingOrchestrator:
        def scan(self, url, depth="tier0", timeout_ms=None):
            raise RuntimeError("model unavailable")

    bridge = UrlReputationBridge(orchestrator=FailingOrchestrator())
    result = bridge.check_domain("example.com")
    assert result == {
        "category": "safe",
        "risk_score": 0.0,
        "decision": "allow",
        "reasons": [],
        "canonical_domain": None,
        "verified_sources": [],
        "enforcement_authorized": False,
    }
