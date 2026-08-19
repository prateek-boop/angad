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
        "decision": "block",
        "reasons": ["blocklist_hit"],
    })
    bridge = UrlReputationBridge(orchestrator=orchestrator)

    result = bridge.check_domain("totally-not-a-bank.example")

    assert result["category"] == "phishing"
    assert result["risk_score"] == 0.92
    assert result["decision"] == "block"
    assert orchestrator.calls == [("https://totally-not-a-bank.example", "tier0")]


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


def test_check_domain_neutral_on_empty_sni():
    bridge = UrlReputationBridge(orchestrator=FakeOrchestrator({}))
    result = bridge.check_domain("")
    assert result == {"category": "safe", "risk_score": 0.0, "decision": "allow", "reasons": []}


def test_check_domain_neutral_on_scan_failure():
    class FailingOrchestrator:
        def scan(self, url, depth="tier0", timeout_ms=None):
            raise RuntimeError("model unavailable")

    bridge = UrlReputationBridge(orchestrator=FailingOrchestrator())
    result = bridge.check_domain("example.com")
    assert result == {"category": "safe", "risk_score": 0.0, "decision": "allow", "reasons": []}
