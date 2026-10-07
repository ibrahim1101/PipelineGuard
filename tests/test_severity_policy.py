import pytest
from pipelineguard.config import PipelineGuardConfig, policy_blocks


@pytest.mark.parametrize("severity,blocked", [
    ("LOW", False), ("MODERATE", False), ("MEDIUM", False),
    ("HIGH", True), ("CRITICAL", True), ("UNKNOWN", False),
])
def test_high_advisory_threshold(severity, blocked):
    config = PipelineGuardConfig(block_advisory_severity="HIGH")
    report = {"score": 100, "findings": [{"rule": "Known dependency vulnerability", "advisory_severity": severity}]}
    assert policy_blocks(report, config) is blocked


def test_unrelated_warning_is_not_advisory():
    config = PipelineGuardConfig(block_advisory_severity="LOW")
    assert not policy_blocks({"score": 100, "findings": [{"rule": "Dependency check incomplete", "severity": "WARNING"}]}, config)
