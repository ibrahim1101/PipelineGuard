"""Tests for the optional finding callback in the shared scan engine."""
from pathlib import Path

from pipelineguard.engine import run_scan


def test_finding_callback_matches_report(tmp_path: Path):
    (tmp_path / "app.py").write_text('password = "not-a-real-secret-123"\\n', encoding="utf-8")
    seen = []
    report = run_scan(tmp_path, online=False, on_finding=seen.append)
    # Report findings may carry presentation fields not present in raw events.
    assert seen
    assert any(item.get("rule") == "Generic secret assignment" for item in seen)
    assert len(seen) <= len(report["findings"])


def test_callback_not_required(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('ok')\\n", encoding="utf-8")
    assert "findings" in run_scan(tmp_path, online=False)


def test_streamed_secret_precedes_report_build(tmp_path, monkeypatch):
    import pipelineguard.engine as engine

    (tmp_path / "credentials.py").write_text('password = "dummy-value-12345"\n', encoding="utf-8")
    observed = []
    original = engine.build_report

    def verify_order(*args, **kwargs):
        assert any(item.get("rule") == "Generic secret assignment" for item in observed)
        return original(*args, **kwargs)

    monkeypatch.setattr(engine, "build_report", verify_order)
    report = engine.run_scan(tmp_path, online=False, on_finding=observed.append)
    secret_events = [item for item in observed if item.get("rule") == "Generic secret assignment"]
    assert len(secret_events) == 1
    assert len([item for item in report["findings"] if item.get("rule") == "Generic secret assignment"]) == 1


def test_streaming_respects_allowlist(tmp_path):
    import json

    (tmp_path / "credentials.py").write_text('password = "dummy-value-12345"\n', encoding="utf-8")
    config = tmp_path / "policy.json"
    config.write_text(json.dumps({"allowlist": [{"rule": "Generic secret assignment", "file": "credentials.py"}]}), encoding="utf-8")
    events = []
    report = run_scan(tmp_path, config=config, online=False, on_finding=events.append)
    assert not any(item.get("rule") == "Generic secret assignment" for item in events)
    assert not any(item.get("rule") == "Generic secret assignment" for item in report["findings"])


def test_incremental_streaming_cold_and_warm_cache(tmp_path, monkeypatch):
    import pipelineguard.secret_cache as secret_cache
    from pipelineguard.engine import run_scan

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-cache"))
    project = tmp_path / "project"
    project.mkdir()
    (project / "secrets.py").write_text('password = "dummy-value-12345"\n', encoding="utf-8")
    for iteration in range(2):
        events = []
        report = run_scan(project, profile="standard", online=False, on_finding=events.append)
        matches = [item for item in events if item.get("rule") == "Generic secret assignment"]
        assert len(matches) == 1, (iteration, events)
        assert report["secret_cache"]["strategy"] == "incremental"
        assert len([item for item in report["findings"] if item.get("rule") == "Generic secret assignment"]) == 1


def test_incremental_callback_not_emitted_for_changed_file(tmp_path, monkeypatch):
    from pipelineguard import secret_cache

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    project = tmp_path / "project"
    project.mkdir()
    target = project / "secrets.py"
    target.write_text('password = "dummy-value-12345"\n', encoding="utf-8")
    original = secret_cache.scan_text

    def mutate_after_scan(content, relative):
        findings = original(content, relative)
        target.write_text("print('changed')\n", encoding="utf-8")
        return findings

    monkeypatch.setattr(secret_cache, "scan_text", mutate_after_scan)
    events = []
    findings = secret_cache.scan_secrets_incremental(project, set(), 100000, on_finding=events.append)
    assert findings == []
    assert events == []
