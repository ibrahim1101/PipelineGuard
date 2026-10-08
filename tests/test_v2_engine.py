from pipelineguard.engine import run_scan


def test_quick_profile_progress_and_cache_outside_project(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.py").write_text("print('hello')", encoding="utf-8")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "user-cache"))
    events = []
    first = run_scan(project, profile="quick", progress=events.append)
    assert first["scan_profile"] == "quick"
    assert first["dependency_check_complete"] is False
    assert first["git_context"] == {"available": False}
    assert events[-1].stage == "complete"
    assert any(event.stage == "fingerprint-complete" and event.cached == 0 for event in events)
    assert not (project / ".pipelineguard-cache.json").exists()

    events.clear()
    run_scan(project, profile="quick", progress=events.append)
    assert any(event.stage == "fingerprint-complete" and event.cached == 1 for event in events)


def test_baseline_is_explicit_and_tracks_fixed_secrets(tmp_path):
    target = tmp_path / "config.txt"
    target.write_text('password="abcdefgh123"', encoding="utf-8")
    baseline = tmp_path / ".pipelineguard-baseline.json"
    first = run_scan(tmp_path, online=False, baseline_path=baseline, update_baseline=True)
    assert first["baseline"]["new"] == 2  # secret and offline warning
    second = run_scan(tmp_path, online=False, baseline_path=baseline)
    assert second["baseline"]["existing"] == 2
    target.write_text("safe", encoding="utf-8")
    third = run_scan(tmp_path, online=False, baseline_path=baseline)
    assert third["baseline"]["fixed"] == 1
    assert third["baseline"]["existing"] == 1
    assert not any(item["rule"] == "Generic secret assignment" for item in third["findings"])


def test_cache_io_failure_does_not_suppress_security_scan(tmp_path, monkeypatch):
    def cache_unavailable(*args, **kwargs):
        raise OSError("read-only cache directory")
    monkeypatch.setattr("pipelineguard.engine.fingerprint_files", cache_unavailable)
    events = []
    result = run_scan(tmp_path, profile="quick", progress=events.append)
    assert result["scan_profile"] == "quick"
    assert any(event.stage == "fingerprint-unavailable" for event in events)
    assert events[-1].stage == "complete"


def test_quick_secret_cache_metrics_and_fresh_profiles(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "file.py").write_text("print('ok')\n" * 200, encoding="utf-8")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    events = []
    first = run_scan(project, profile="quick", online=False, progress=events.append)
    assert first["secret_cache"]["scanned"] == 1
    assert first["secret_cache"]["reused"] == 0
    assert any(event.stage == "secrets-complete" and event.processed == 1 for event in events)
    second = run_scan(project, profile="quick", online=False)
    assert second["secret_cache"]["scanned"] == 0
    assert second["secret_cache"]["reused"] == 1
    for name in ("release", "forensic"):
        result = run_scan(project, profile=name, online=False)
        assert "secret_cache" not in result


def test_full_strategy_reports_unknown_counts_without_false_zero(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    for index in range(40):
        (project / f"{index:03d}.txt").write_text("safe")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    events = []
    report = run_scan(project, profile="quick", online=False, progress=events.append)
    metrics = report["secret_cache"]
    assert metrics["strategy"] == "full"
    assert metrics["scanned"] is None
    assert metrics["discovered"] is None
    assert metrics["reused"] == 0
    complete = [event for event in events if event.stage == "secrets-complete"]
    assert len(complete) == 1
    assert complete[0].discovered is None
    assert complete[0].processed is None
    assert complete[0].cached == 0
