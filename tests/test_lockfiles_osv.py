import io
import json
from unittest.mock import patch

import pytest

from scanners.dependency_scanner import scan_dependencies
from scanners.osv_scanner import query_osv


def test_npm_lock_scoped_and_transitive_packages(tmp_path):
    data = {"lockfileVersion": 3, "packages": {"": {"name": "root"}, "node_modules/@demo/lib": {"version": "1.2.3"}, "node_modules/a/node_modules/b": {"version": "2.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(data))
    packages = scan_dependencies(tmp_path)[0]["dependencies"]
    assert [(item["name"], item["version"]) for item in packages] == [("@demo/lib", "1.2.3"), ("b", "2.0.0")]


@pytest.mark.parametrize("response", [[], {"results": None}, {"results": [None]}, {"results": [{"vulns": [None]}]}])
def test_malformed_osv_response_is_incomplete(response):
    with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())):
        result = query_osv([{"name": "demo", "ecosystem": "npm", "version": "1.0.0"}])
    assert result[0]["rule"] == "Dependency check incomplete"


def test_osv_results_match_filtered_packages():
    dependencies = [{"name": "unresolved", "version": ""}, {"name": "resolved", "ecosystem": "npm", "version": "1.0.0"}]
    with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"results":[{"vulns":[{"id":"DEMO-1"}]}]}')):
        result = query_osv(dependencies)
    assert result[-1]["package"] == "resolved"
