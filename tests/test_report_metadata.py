"""Metadata and HTML readability regression checks."""
from datetime import datetime
from pathlib import Path

from pipelineguard.reporting import write_html_report
from pipelineguard.engine import run_scan


def test_html_metadata_and_readable_advisory(tmp_path: Path):
    report = {
        "status": "WARNING", "score": 85,
        "summary": {"total_findings": 1, "critical": 0, "warnings": 1},
        "scan_profile": "deep", "scanned_at": "2026-10-08T12:00:00+00:00",
        "findings": [{
            "severity": "WARNING", "rule": "Known dependency vulnerability",
            "id": "GHSA-example", "package": "example", "version": "1.0",
            "summary": "Example advisory summary", "fixed_versions": ["1.1"],
        }],
    }
    output = tmp_path / "report.html"
    write_html_report(report, output)
    html = output.read_text(encoding="utf-8")
    assert "Scan profile: <strong>deep</strong>" in html
    assert "2026-10-08T12:00:00+00:00" in html
    assert "Example advisory summary" in html
    assert "<details>" in html


def test_scan_records_utc_timestamp(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("pipelineguard.engine.query_osv", lambda *args, **kwargs: [])
    report = run_scan(tmp_path, online=True, profile="deep")
    timestamp = datetime.fromisoformat(report["scanned_at"])
    assert timestamp.utcoffset().total_seconds() == 0
    assert report["scan_profile"] == "deep"
