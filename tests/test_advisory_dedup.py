"""Regression checks for OSV alias handling and HTML output."""
from pathlib import Path

from pipelineguard.reporting import build_report, write_html_report
from scanners.osv_scanner import deduplicate_advisories


def advisory(identifier, aliases=(), package="requests"):
    return {
        "rule": "Known dependency vulnerability", "severity": "WARNING",
        "id": identifier, "aliases": list(aliases), "package": package,
        "version": "2.32.3", "references": [f"https://example.test/{identifier}"],
        "fixed_versions": ["2.33.0"], "summary": "Example vulnerability",
    }


def test_explicit_aliases_merge_without_losing_identifiers():
    findings = deduplicate_advisories([
        advisory("GHSA-one", ["PYSEC-one"]),
        advisory("PYSEC-one", ["GHSA-one"]),
    ])
    assert len(findings) == 1
    assert set([findings[0]["id"], *findings[0]["aliases"]]) == {"GHSA-one", "PYSEC-one"}
    assert len(findings[0]["references"]) == 2


def test_unrelated_and_other_package_advisories_remain_distinct():
    findings = deduplicate_advisories([
        advisory("GHSA-one", ["PYSEC-one"]),
        advisory("GHSA-two"),
        advisory("PYSEC-one", ["GHSA-one"], package="urllib3"),
    ])
    assert len(findings) == 3


def test_html_includes_package_advisory_and_remediation(tmp_path: Path):
    report = build_report([], [advisory("GHSA-one", ["PYSEC-one"])])
    output = tmp_path / "report.html"
    write_html_report(report, output)
    html = output.read_text(encoding="utf-8")
    assert "Advisory IDs" in html
    assert "requests 2.32.3" in html
    assert "GHSA-one, PYSEC-one" in html
    assert "Fixed in: 2.33.0" in html
