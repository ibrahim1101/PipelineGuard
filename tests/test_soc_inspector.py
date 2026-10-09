"""SOC inspector metadata and grouping tests."""
from pipelineguard.soc_inspector import finding_group, safe_finding_details, masked_code_preview


def test_grouping():
    assert finding_group({"file": "src/example.py"}) == "Secrets"
    assert finding_group({"package": "demo-lib", "file": "requirements.txt"}) == "Dependencies"
    assert finding_group({"rule": "Other"}) == "Other"


def test_private_fields_are_not_displayed():
    marker = "hidden-private-value"
    item = {"severity": "CRITICAL", "rule": "Example", "file": "demo.py",
            "line": 8, "summary": marker, "remediation": marker,
            "raw": marker, "snippet": marker}
    text = safe_finding_details(item) + masked_code_preview(item)
    assert "Example" in text
    assert "demo.py:8" in text
    assert marker not in text


def test_dependency_has_no_source_preview():
    item = {"package": "example", "id": "ADV-1"}
    assert "ADV-1" in safe_finding_details(item)
    assert "unavailable" in masked_code_preview(item)
