import io
import json
from unittest.mock import patch

from scanners.osv_scanner import query_osv
from scanners.dependency_scanner import reconcile_inventory


def test_advisory_details_are_enriched():
    detail = {"id": "DEMO-1", "summary": "Demo", "database_specific": {"severity": "CRITICAL"}, "affected": [{"package": {"name": "demo", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}
    responses = [io.BytesIO(b'{"results":[{"vulns":[{"id":"DEMO-1"}]}]}'), io.BytesIO(json.dumps(detail).encode())]
    with patch("urllib.request.urlopen", side_effect=responses):
        result = query_osv([{"name": "demo", "ecosystem": "npm", "version": "1.0.0"}], enrich=True)
    assert result[0]["severity"] == "CRITICAL"
    assert result[0]["fixed_versions"] == ["2.0.0"]
    assert result[0]["summary"] == "Demo"


def test_numeric_cvss_score_is_extracted():
    detail = {"id": "DEMO-2", "database_specific": {"severity": "HIGH", "cvss_score": 8.1}, "affected": []}
    responses = [io.BytesIO(b'{"results":[{"vulns":[{"id":"DEMO-2"}]}]}'), io.BytesIO(json.dumps(detail).encode())]
    with patch("urllib.request.urlopen", side_effect=responses):
        result = query_osv([{"name": "demo", "ecosystem": "npm", "version": "1.0.0"}], enrich=True)
    assert result[0]["cvss_score"] == 8.1


def test_missing_cvss_score_is_unknown():
    detail = {"id": "DEMO-3", "database_specific": {"severity": "HIGH"}, "severity": [{"type": "CVSS_V3", "score": "not-a-number"}], "affected": []}
    responses = [io.BytesIO(b'{"results":[{"vulns":[{"id":"DEMO-3"}]}]}'), io.BytesIO(json.dumps(detail).encode())]
    with patch("urllib.request.urlopen", side_effect=responses):
        result = query_osv([{"name": "demo", "ecosystem": "npm", "version": "1.0.0"}], enrich=True)
    assert result[0]["cvss_score"] is None


def test_lockfile_replaces_range_in_same_project():
    records = [{"dependencies": [
        {"name": "demo", "ecosystem": "npm", "version": "", "manifest": "package.json"},
        {"name": "demo", "ecosystem": "npm", "version": "1.0.0", "manifest": "package-lock.json", "resolved": True},
    ]}]
    result = reconcile_inventory(records)
    assert len(result) == 1
    assert result[0]["version"] == "1.0.0"
