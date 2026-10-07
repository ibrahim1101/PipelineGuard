import json
from unittest.mock import patch

from typer.testing import CliRunner
from pipelineguard.main import app
from pipelineguard.reporting import build_report, write_html_report, write_json_report, write_sarif_report


FINDING = {
    "severity": "WARNING", "rule": "Known dependency vulnerability",
    "id": "DEMO-1", "package": "demo", "version": "1.0.0",
    "summary": "Demo <unsafe> advisory", "advisory_severity": "HIGH",
    "fixed_versions": ["2.0.0"], "affected_ranges": [{"type": "SEMVER"}],
    "references": ["https://example.org/advisory"], "severity_vectors": [],
    "remediation": "Review affected ranges."
}


def test_report_formats_preserve_advisory_details(tmp_path):
    report = build_report([], [FINDING])
    html, sarif, data = [tmp_path / name for name in ("report.html", "report.sarif", "report.json")]
    write_html_report(report, html)
    write_sarif_report(report, sarif)
    write_json_report(report, data)
    assert json.loads(data.read_text())["findings"][0] == FINDING
    properties = json.loads(sarif.read_text())["runs"][0]["results"][0]["properties"]
    assert properties["fixed_versions"] == ["2.0.0"]
    assert properties["id"] == "DEMO-1"
    assert "Demo &lt;unsafe&gt; advisory" in html.read_text()
    assert "2.0.0" in html.read_text()


def test_terminal_prints_enriched_advisory(tmp_path):
    with patch("pipelineguard.engine.query_osv", return_value=[FINDING]):
        result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "DEMO-1" in result.output
    assert "2.0.0" in result.output
    assert "HIGH" in result.output
