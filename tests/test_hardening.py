import json
from unittest.mock import patch

import pytest
from pipelineguard.config import apply_allowlist
from pipelineguard.reporting import build_report, write_html_report
from scanners.osv_scanner import query_osv
from scanners.secret_scanner import scan_directory


def test_comment_does_not_hide_secret(tmp_path):
    (tmp_path / "config").write_text('password="abcdefgh123" # test example')
    assert scan_directory(tmp_path)


def test_empty_allowlist_cannot_hide_findings():
    findings = [{"rule": "Private key", "file": "key.pem", "line": 1}]
    assert apply_allowlist(findings, [{}]) == findings


def test_html_escapes_finding_content(tmp_path):
    report = build_report([{"severity": "CRITICAL", "rule": "<script>alert(1)</script>"}], [])
    target = tmp_path / "report.html"
    write_html_report(report, target)
    assert "<script>" not in target.read_text()
    assert "&lt;script&gt;" in target.read_text()


def test_network_failure_is_incomplete():
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        findings = query_osv([{"name": "demo", "ecosystem": "PyPI", "version": "1.0"}])
    assert findings[0]["rule"] == "Dependency check incomplete"


def test_unresolved_versions_are_incomplete():
    assert query_osv([{"name": "demo", "version": ""}])[0]["severity"] == "WARNING"


def test_cli_policy_report_matches_exit(tmp_path):
    pytest.importorskip("typer")
    from typer.testing import CliRunner
    from pipelineguard.main import app
    (tmp_path / "package.json").write_text("{invalid")
    config = tmp_path / "config.json"
    config.write_text('{"fail_on_warning":true}')
    output = tmp_path / "output.json"
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--config", str(config), "--json", "--output", str(output)])
    assert result.exit_code == 1, result.output
    report = json.loads(result.output)
    assert report["status"] == "BLOCKED"
    assert report["policy_blocked"]
    assert json.loads(output.read_text()) == report


def test_cli_clean_directory(tmp_path):
    pytest.importorskip("typer")
    from typer.testing import CliRunner
    from pipelineguard.main import app
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == "SAFE"
