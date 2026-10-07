from pathlib import Path

import json

from pipelineguard.reporting import build_report, write_html_report, write_sarif_report


def test_clean_report_scores_100() -> None:
    report = build_report([], [])
    assert report["status"] == "SAFE"
    assert report["score"] == 100


def test_critical_report_is_blocked() -> None:
    report = build_report([{"severity": "CRITICAL", "rule": "test"}], [])
    assert report["status"] == "BLOCKED"
    assert report["score"] == 50


def test_html_report_is_written(tmp_path: Path) -> None:
    output = tmp_path / "report.html"
    write_html_report(build_report([], []), output)
    assert output.exists()
    assert "PipelineGuard Security Report" in output.read_text(encoding="utf-8")


def test_sarif_report_is_written(tmp_path: Path) -> None:
    output = tmp_path / "results.sarif"
    report = build_report([{"severity": "CRITICAL", "rule": "Test secret", "file": "config.py", "line": 4}], [])
    write_sarif_report(report, output)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["level"] == "error"
