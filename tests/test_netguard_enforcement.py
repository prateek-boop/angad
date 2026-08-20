import subprocess

from netguard.enforcement import EnforcementEngine


def _fake_run(check_returncode=1, add_returncode=0):
    """`-C` (rule-exists check) and `-A`/`-D` (add/delete) need independent
    return codes: a real iptables -C returns nonzero when the rule is absent."""
    calls = []

    def run(args, capture_output=True, text=True, timeout=5):
        calls.append(args)

        class Result:
            pass

        r = Result()
        r.returncode = check_returncode if "-C" in args else add_returncode
        r.stdout = ""
        r.stderr = ""
        return r

    return run, calls


def test_block_ip_calls_iptables_with_drop_rule(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    assert engine.block_ip("203.0.113.5", reason="test") is True

    assert any(
        a[:2] == ["iptables", "-A"] and "-d" in a and "203.0.113.5" in a and "DROP" in a
        for a in calls
    )
    assert engine.is_ip_blocked("203.0.113.5")


def test_block_client_calls_iptables_with_source_match(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    assert engine.block_client("10.0.0.7", reason="test") is True

    assert any(a[:2] == ["iptables", "-A"] and "-s" in a and "10.0.0.7" in a for a in calls)
    assert engine.is_client_blocked("10.0.0.7")


def test_block_ipv6_calls_ip6tables(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    assert engine.block_ip("2001:db8::5", reason="test") is True

    assert any(
        args[:2] == ["ip6tables", "-A"] and "2001:db8::5" in args
        for args in calls
    )
    assert engine.is_ip_blocked("2001:db8::5")


def test_protected_client_ips_are_never_blocked(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    assert engine.block_client("127.0.0.1", reason="test") is False
    assert not engine.is_client_blocked("127.0.0.1")


def test_localhost_destination_is_never_blocked(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    assert engine.block_ip("127.0.0.1", reason="test") is False


def test_unblock_removes_tracking(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(subprocess, "run", run)

    engine = EnforcementEngine()
    engine._blocked_ips["203.0.113.9"] = float("inf")
    assert engine.unblock_ip("203.0.113.9") is True
    assert not engine.is_ip_blocked("203.0.113.9")


def test_no_shizuku_import_anywhere():
    import pathlib

    import netguard

    for path in pathlib.Path(netguard.__file__).parent.rglob("*.py"):
        content = path.read_text().lower()
        assert "import shizuku" not in content
        assert "shizukubridge" not in content
