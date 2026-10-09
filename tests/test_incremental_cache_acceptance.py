"""Real cache persistence, invalidation and report presentation checks."""
from pathlib import Path

from pipelineguard.secret_cache import MIN_CACHE_BYTES, scan_secrets_incremental
from pipelineguard.reporting import build_report, write_html_report


def test_warm_cache_reuses_content_and_invalidates_changes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-cache"))
    project = tmp_path / "project"
    project.mkdir()
    target = project / "large.py"
    target.write_text("# safe test content\n" + ("x" * (MIN_CACHE_BYTES + 100)), encoding="utf-8")

    cold = {}
    first = scan_secrets_incremental(project, set(), 100_000, metrics=cold)
    assert cold["scanned"] == 1
    assert cold["reused"] == 0
    assert cold["hashed"] == 1

    warm = {}
    second = scan_secrets_incremental(project, set(), 100_000, metrics=warm)
    assert second == first
    assert warm["scanned"] == 0
    assert warm["reused"] == 1

    target.write_text("# modified test content\n" + ("y" * (MIN_CACHE_BYTES + 100)), encoding="utf-8")
    changed = {}
    scan_secrets_incremental(project, set(), 100_000, metrics=changed)
    assert changed["scanned"] == 1
    assert changed["reused"] == 0


def test_tiny_files_are_rescanned_not_cached(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-cache"))
    project = tmp_path / "tiny-project"
    project.mkdir()
    (project / "small.py").write_text("print('safe')\n", encoding="utf-8")
    for _ in range(2):
        metrics = {}
        scan_secrets_incremental(project, set(), 100_000, metrics=metrics)
        assert metrics["scanned"] == 1
        assert metrics["reused"] == 0
        assert metrics["hashed"] == 0


def test_html_explains_cache_telemetry(tmp_path: Path):
    report = build_report([], [])
    report["secret_cache"] = {
        "strategy": "incremental", "discovered": 3, "scanned": 2,
        "reused": 1, "hashed": 1, "skipped_size": 0,
        "skipped_changed": 0, "skipped_error": 0,
    }
    output = tmp_path / "report.html"
    write_html_report(report, output)
    html = output.read_text(encoding="utf-8")
    assert "Secret scan performance" in html
    assert "Reused: 1" in html
    assert "Files below the cache threshold" in html
