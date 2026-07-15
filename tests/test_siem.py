import json

from integrations.siem.formatter import to_cef, to_json_event


def test_siem_json_and_cef_are_stable_and_escaped():
    result = {
        "scan_id": "scan-1",
        "category": "phishing",
        "confidence": 0.91,
        "risk_score": 0.97,
        "threat_level": "critical",
        "decision": "block",
        "blocked": True,
        "reasons": ["Form action=x|y\nsecond"],
        "probabilities": {"safe": 0.03, "phishing": 0.91},
    }
    event = json.loads(to_json_event(result, observed_at="2026-01-01T00:00:00+00:00"))
    assert event["scan_id"] == "scan-1"
    assert event["event_type"] == "shieldnet.url_scan"

    cef = to_cef(result)
    assert cef.startswith("CEF:0|ShieldNet|")
    assert "|10|" in cef
    assert "action\\=x" in cef
    assert "\\nsecond" in cef
