from netguard.dashboard.server import DashboardServer


def test_status_requires_proxy_enforcement_and_models():
    dashboard = DashboardServer()
    client = dashboard.app.test_client()
    dashboard.set_status_provider(
        lambda: {
            "proxy": {"is_running": True},
            "enforcer": {"is_initialized": True},
            "ai_engine": {"model_stack_ready": False},
            "url_reputation": {"model_available": True},
        }
    )

    degraded = client.get("/api/status").get_json()
    assert degraded["status"] == "degraded"
    assert degraded["checks"]["models_ready"] is False

    dashboard.set_status_provider(
        lambda: {
            "proxy": {"is_running": True},
            "enforcer": {"is_initialized": True},
            "ai_engine": {"model_stack_ready": True},
            "url_reputation": {"model_available": True},
        }
    )
    ready = client.get("/api/status").get_json()
    assert ready["status"] == "online"
    assert ready["protection"] == "active"


def test_emit_verdict_includes_named_features_and_connection(monkeypatch):
    dashboard = DashboardServer()
    emitted = {}

    monkeypatch.setattr(
        dashboard.socketio,
        "emit",
        lambda event, data: emitted.update(event=event, data=data),
    )

    dashboard.emit_verdict(
        "10.0.0.9",
        {"risk_score": 0.1, "classification": "SAFE_WEB"},
        "ALLOW",
        features=[34.0, 2.0, 3.5],
        feature_names=["dns_length", "dns_dots", "dns_entropy"],
        connection={"sni": "app-analytics-v2.snapchat.com", "dst_port": 443},
    )

    assert emitted["event"] == "security_event"
    assert emitted["data"]["features"] == {
        "dns_length": 34.0,
        "dns_dots": 2.0,
        "dns_entropy": 3.5,
    }
    assert emitted["data"]["feature_vector"] == [34.0, 2.0, 3.5]
    assert emitted["data"]["connection"]["sni"] == "app-analytics-v2.snapchat.com"
