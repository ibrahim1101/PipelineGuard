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
    columns = ("severity", "rule", "location", "package", "advisory", "remediation")
    def cell(item: dict[str, Any], key: str) -> str:
        if key == "location":
            value = str(item.get("file") or "—")
            if item.get("line"):
                value += ":" + str(item["line"])
        elif key == "package":
            value = (str(item.get("package", "")) + " " + str(item.get("version", ""))).strip() or "—"
        elif key == "advisory":
            value = ", ".join(str(x) for x in [item.get("id"), *(item.get("aliases") or [])] if x) or "—"
        elif key == "remediation":
            fixed = item.get("fixed_versions") or []
            value = ("Fixed in: " + ", ".join(str(x) for x in fixed)) if fixed else (item.get("remediation") or "—")
        else:
            value = str(item.get(key) or "—")
        return "<td>" + escape(value) + "</td>"
    rows = "".join("<tr>" + "".join(cell(item, key) for key in columns) + "</tr>"
                   for item in report["findings"]) or '<tr><td colspan="6">No findings</td></tr>'
    color = SAFE if report["status"] == "SAFE" else BLOCKED
    profile = escape(str(report.get("scan_profile") or "Not specified"))
    scanned_at = escape(str(report.get("scanned_at") or "Not recorded"))
    cache = report.get("secret_cache")
    cache_section = ""
    if isinstance(cache, dict):
        def count(key: str) -> str:
            value = cache.get(key)
            return escape(str(value)) if value is not None else "Not measured"
        strategy = escape(str(cache.get("strategy") or "Unknown"))
        cache_section = (
            "<section><h2>Secret scan performance</h2>"
            "<p>Strategy: <strong>" + strategy + "</strong>"
            " · Discovered: " + count("discovered")
            + " · Scanned: " + count("scanned")
            + " · Reused: " + count("reused")
            + " · Hashed: " + count("hashed")
            + " · Skipped (size): " + count("skipped_size")
            + " · Skipped (changed): " + count("skipped_changed")
            + " · Skipped (error): " + count("skipped_error")
            + "</p><p>Files below the cache threshold are scanned directly on each run; "
              "a zero reuse count does not by itself indicate a cache failure.</p></section>"
        )
    advisory_sections = ""
    for item in report["findings"]:
        if not item.get("id"):
            continue
        details = {key: item.get(key, "") for key in (
            "id", "aliases", "package", "version", "summary", "advisory_severity", "cvss_score",
            "severity_vectors", "affected_ranges", "fixed_versions", "references", "remediation"
        )}
        heading = escape(str(item.get("id") or "Dependency advisory"))
        summary = escape(str(item.get("summary") or "No summary supplied"))
        advisory_sections += "<section><h2>Dependency advisory: " + heading + "</h2><p>" + summary + "</p><details><summary>Full advisory details</summary><pre>" + escape(json.dumps(details, indent=2)) + "</pre></details></section>"
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>PipelineGuard Report</title><style>body{{font-family:Arial;max-width:1000px;margin:40px auto}}
.status{{font-size:2em;font-weight:bold;color:{color}}}table{{border-collapse:collapse;width:100%;box-shadow:0 2px 8px #0001;overflow-wrap:anywhere}}
th,td{{border:1px solid {OLIVE_LIGHT};padding:10px;text-align:left}}th{{background:{OLIVE_DARK};color:white}}
body{{color:{OLIVE_DARK};background:#FAFCF5}}h1{{color:{OLIVE_DARK};border-bottom:4px solid {OLIVE};padding-bottom:10px}}</style></head>
<body><h1>PipelineGuard Security Report</h1><div class="status">{report['status']}</div>
<p>Security score: <strong>{report['score']}/100</strong></p>
<p>Scan profile: <strong>{profile}</strong> · Scanned at (UTC): <strong>{scanned_at}</strong></p>
<p>Total findings: {report['summary']['total_findings']} · Critical: {report['summary']['critical']} · Warnings: {report['summary']['warnings']}</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Package</th><th>Advisory IDs</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>
{cache_section}{advisory_sections}</body></html>"""
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
                "id", "aliases", "package", "version", "advisory_severity", "cvss_score", "severity_vectors",
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
