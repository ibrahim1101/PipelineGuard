"""Regression contract for nullable full-scan telemetry in report exports."""
import json

from pipelineguard.engine import run_scan
from pipelineguard.reporting import write_html_report, write_json_report, write_sarif_report


def test_full_scan_nullable_telemetry_survives_json_and_other_exports(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    for index in range(40):
        (project / f"{index:03d}.txt").write_text("safe", encoding="utf-8")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    report = run_scan(project, profile="quick", online=False)
    assert report["secret_cache"]["strategy"] == "full"
    for key in ("discovered", "hashed", "scanned", "skipped_size", "skipped_changed", "skipped_error"):
        assert report["secret_cache"][key] is None
    assert report["secret_cache"]["reused"] == 0

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    sarif_path = tmp_path / "report.sarif"
    write_json_report(report, json_path)
    write_html_report(report, html_path)
    write_sarif_report(report, sarif_path)

    decoded = json.loads(json_path.read_text(encoding="utf-8"))
    assert decoded["secret_cache"] == report["secret_cache"]
    assert all(decoded["secret_cache"][key] is None for key in ("discovered", "hashed", "scanned"))
    assert "PipelineGuard Security Report" in html_path.read_text(encoding="utf-8")
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
