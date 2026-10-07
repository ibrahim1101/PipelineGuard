from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from pipelineguard.theme import BLOCKED, OLIVE, OLIVE_DARK, OLIVE_LIGHT, SAFE


def build_report(secret_findings: list[dict[str, Any]], dependency_findings: list[dict[str, Any]]) -> dict[str, Any]:
    findings = secret_findings + [item for item in dependency_findings if item.get("severity") != "INFO"]
    critical = sum(item.get("severity") == "CRITICAL" for item in findings)
    warnings = sum(item.get("severity") == "WARNING" for item in findings)
    score = max(0, 100 - (critical * 50) - (warnings * 15))
    status = "BLOCKED" if critical else ("WARNING" if warnings else "SAFE")
    return {
        "status": status,
        "score": score,
        "summary": {"total_findings": len(findings), "critical": critical, "warnings": warnings},
        "findings": findings,
        "dependency_inventory": [item for item in dependency_findings if item.get("severity") == "INFO"],
    }


def write_json_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_html_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(
        "<tr>" + "".join(f"<td>{escape(str(item.get(key, '')))}</td>" for key in ("severity", "rule", "file", "line")) + "</tr>"
        for item in report["findings"]
    ) or '<tr><td colspan="4">No findings</td></tr>'
    color = SAFE if report["status"] == "SAFE" else BLOCKED
    advisory_sections = ""
    for item in report["findings"]:
        if not item.get("id"):
            continue
        details = {key: item.get(key, "") for key in (
            "id", "package", "version", "summary", "advisory_severity", "cvss_score",
            "severity_vectors", "affected_ranges", "fixed_versions", "references", "remediation"
        )}
        advisory_sections += "<section><h2>Dependency advisory</h2><pre>" + escape(json.dumps(details, indent=2)) + "</pre></section>"
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>PipelineGuard Report</title><style>body{{font-family:Arial;max-width:1000px;margin:40px auto}}
.status{{font-size:2em;font-weight:bold;color:{color}}}table{{border-collapse:collapse;width:100%;box-shadow:0 2px 8px #0001}}
th,td{{border:1px solid {OLIVE_LIGHT};padding:10px;text-align:left}}th{{background:{OLIVE_DARK};color:white}}
body{{color:{OLIVE_DARK};background:#FAFCF5}}h1{{color:{OLIVE_DARK};border-bottom:4px solid {OLIVE};padding-bottom:10px}}</style></head>
<body><h1>PipelineGuard Security Report</h1><div class="status">{report['status']}</div>
<p>Security score: <strong>{report['score']}/100</strong></p>
<p>Total findings: {report['summary']['total_findings']} · Critical: {report['summary']['critical']} · Warnings: {report['summary']['warnings']}</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th></tr></thead><tbody>{rows}</tbody></table>
{advisory_sections}</body></html>"""
    output.write_text(html, encoding="utf-8")


def write_sarif_report(report: dict[str, Any], output: Path) -> None:
    """Write SARIF 2.1.0 results for code-scanning integrations."""
    results = []
    rules = {}
    for finding in report["findings"]:
        rule_id = str(finding.get("rule", "pipelineguard-finding")).lower().replace(" ", "-")
        level = "error" if finding.get("severity") == "CRITICAL" else "warning"
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{finding.get('rule', 'Security finding')} detected."},
        }
        if finding.get("id"):
            result["message"]["text"] = f"{finding['id']}: {finding.get('summary', '')} ({finding.get('package', '')} {finding.get('version', '')})"
            result["properties"] = {key: finding.get(key, "") for key in (
                "id", "package", "version", "advisory_severity", "cvss_score", "severity_vectors",
                "affected_ranges", "fixed_versions", "references", "remediation"
            )}
        file_name = finding.get("file")
        line = finding.get("line")
        if not file_name:
            file_name = "PipelineGuard"
        region = {"startLine": int(line)} if line else {}
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": str(file_name)},
                "region": region,
            }
        }]
        results.append(result)
        rules[rule_id] = {"id": rule_id, "name": str(finding.get("rule", rule_id))}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PipelineGuard", "version": "1.0.0", "rules": list(rules.values())}}, "results": results}],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
