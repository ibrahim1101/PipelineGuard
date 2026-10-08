from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import quote
from typing import Any

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _cvss_score(vulnerability: dict[str, Any]) -> float | None:
    """Return an OSV-provided numeric CVSS score when available."""
    database_specific = vulnerability.get("database_specific", {})
    candidates = [database_specific.get("cvss_score"), database_specific.get("cvss")]
    candidates.extend(entry.get("score") for entry in vulnerability.get("severity", []) if isinstance(entry, dict))
    for candidate in candidates:
        try:
            value = float(candidate)
        except (TypeError, ValueError):
            continue
        if 0 <= value <= 10:
            return value
    return None


def query_osv(dependencies: list[dict[str, str]], timeout: int = 8, enrich: bool = False) -> list[dict[str, Any]]:
    """Query OSV.dev for known vulnerabilities; returns an empty list offline."""
    eligible = [item for item in dependencies if item.get("version")]
    queries = [
        {"package": {"name": item["name"], "ecosystem": item["ecosystem"]}, "version": item["version"]}
        for item in eligible
        if item.get("version")
    ]
    if not queries:
        return [{"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Exact versions unavailable."}] if dependencies else []
    payload = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(OSV_BATCH_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return [{"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Vulnerability service unavailable."}]
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(eligible) or any(
        not isinstance(result, dict) or not isinstance(result.get("vulns", []), list)
        or any(not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) for vuln in result.get("vulns", []))
        for result in results
    ):
        return [{"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Invalid vulnerability service response."}]
    findings = []
    advisory_cache = {}
    if len(eligible) != len(dependencies):
        findings.append({"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Some dependencies lack exact versions."})
    for dependency, result in zip(eligible, results):
        for vulnerability in result.get("vulns", []):
            advisory_id = vulnerability["id"]
            if enrich:
                if advisory_id not in advisory_cache:
                    try:
                        with urllib.request.urlopen("https://api.osv.dev/v1/vulns/" + quote(advisory_id, safe=""), timeout=timeout) as response:
                            detail = json.loads(response.read().decode("utf-8"))
                        if not isinstance(detail, dict) or detail.get("id") != advisory_id:
                            raise ValueError("Invalid advisory")
                        advisory_cache[advisory_id] = detail
                    except (OSError, ValueError):
                        advisory_cache[advisory_id] = None
                detail = advisory_cache[advisory_id]
                if detail is None:
                    findings.append({"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Advisory details unavailable.", "id": advisory_id})
                else:
                    vulnerability = detail
            affected = [item for item in vulnerability.get("affected", []) if item.get("package", {}).get("name") == dependency["name"] and item.get("package", {}).get("ecosystem") == dependency["ecosystem"]]
            fixed = sorted({event["fixed"] for item in affected for interval in item.get("ranges", []) for event in interval.get("events", []) if "fixed" in event})
            findings.append({
                "severity": "CRITICAL" if vulnerability.get("database_specific", {}).get("severity") == "CRITICAL" else "WARNING",
                "rule": "Known dependency vulnerability",
                "package": dependency["name"],
                "version": dependency.get("version", ""),
                "id": vulnerability.get("id"),
                "aliases": vulnerability.get("aliases", []),
                "summary": vulnerability.get("summary", ""),
                "references": [ref.get("url") for ref in vulnerability.get("references", [])],
                "advisory_severity": vulnerability.get("database_specific", {}).get("severity", "UNKNOWN"),
                "cvss_score": _cvss_score(vulnerability),
                "severity_vectors": vulnerability.get("severity", []),
                "affected_ranges": [interval for item in affected for interval in item.get("ranges", [])],
                "fixed_versions": fixed,
                "remediation": "Review fixed versions and affected ranges before upgrading." if fixed else "Review the advisory for mitigation guidance.",
            })
    return deduplicate_advisories(findings)


def deduplicate_advisories(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge advisories only when an explicit alias links their identifiers.

    OSV entries without alias evidence remain separate; different affected
    packages/versions must never be collapsed together.
    """
    merged: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str], int] = {}
    for item in findings:
        if item.get("rule") != "Known dependency vulnerability":
            merged.append(item)
            continue
        identifiers = {str(value) for value in [item.get("id"), *item.get("aliases", [])] if value}
        package = str(item.get("package", ""))
        version = str(item.get("version", ""))
        existing = next((by_key[(package, version, identifier)] for identifier in identifiers
                         if (package, version, identifier) in by_key), None)
        if existing is None:
            merged.append(dict(item))
            existing = len(merged) - 1
        else:
            target = merged[existing]
            target_ids = {str(value) for value in [target.get("id"), *target.get("aliases", [])] if value}
            target["aliases"] = sorted((target_ids | identifiers) - {str(target.get("id"))})
            for key in ("references", "fixed_versions", "severity_vectors", "affected_ranges"):
                values = list(target.get(key) or [])
                for value in item.get(key) or []:
                    if value not in values:
                        values.append(value)
                target[key] = values
            if not target.get("summary") and item.get("summary"):
                target["summary"] = item["summary"]
            if target.get("advisory_severity") in (None, "UNKNOWN") and item.get("advisory_severity") not in (None, "UNKNOWN"):
                target["advisory_severity"] = item["advisory_severity"]
            if item.get("severity") == "CRITICAL":
                target["severity"] = "CRITICAL"
        for identifier in identifiers | {str(value) for value in merged[existing].get("aliases", [])}:
            by_key[(package, version, identifier)] = existing
    return merged
