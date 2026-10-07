from pipelineguard.annotations import github_annotations


def test_annotation_escapes_workflow_control_characters():
    report = {"findings": [{"severity": "CRITICAL", "file": "file,:\n.env", "line": 2, "rule": "Secret\n::notice::injected%"}]}
    annotation = github_annotations(report)[0]
    assert "\n" not in annotation
    assert "file=file%2C%3A%0A.env,line=2" in annotation
    assert "Secret%0A::notice::injected%25" in annotation


def test_policy_and_nonlocation_annotations():
    result = github_annotations({"findings": [{"rule": "Dependency check incomplete", "severity": "WARNING"}], "policy_blocked": True})
    assert result[0].startswith("::warning ")
    assert result[1].startswith("::error ")
