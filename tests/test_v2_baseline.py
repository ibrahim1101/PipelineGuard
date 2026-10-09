import json

import pytest

from pipelineguard.baseline import compare_baseline, finding_key, read_baseline, snapshot, write_baseline


def test_baseline_new_existing_fixed_and_regressed(tmp_path):
    first = [
        {"rule": "Private key", "file": "a.py", "line": 1, "severity": "WARNING"},
        {"rule": "Generic secret assignment", "file": "b.py", "line": 3, "severity": "CRITICAL"},
    ]
    path = tmp_path / ".pipelineguard-baseline.json"
    write_baseline(path, first)
    next_scan = [
        {"rule": "Private key", "file": "a.py", "line": 1, "severity": "CRITICAL"},
        {"rule": "Private key", "file": "c.py", "line": 2, "severity": "CRITICAL"},
    ]
    diff = compare_baseline(next_scan, read_baseline(path))
    assert {k: diff[k] for k in ("new", "existing", "fixed", "regressed")} == {
        "new": 1, "existing": 1, "fixed": 1, "regressed": 1,
    }
    assert diff["finding_states"][finding_key(next_scan[0])] == "regressed"
    assert diff["fixed_findings"][0]["file"] == "b.py"


def test_baseline_deterministic_and_no_raw_evidence(tmp_path):
    finding = {"severity": "CRITICAL", "rule": "Private key", "file": "x", "line": 1,
               "raw_evidence": "DO_NOT_PERSIST"}
    path = tmp_path / "baseline.json"
    write_baseline(path, [finding])
    assert "DO_NOT_PERSIST" not in path.read_text()
    assert json.loads(path.read_text()) == snapshot([finding])
    assert finding_key(finding) == finding_key(dict(reversed(list(finding.items()))))


def test_baseline_rejects_corruption(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{broken")
    with pytest.raises(ValueError, match="Cannot read baseline"):
        read_baseline(path)
