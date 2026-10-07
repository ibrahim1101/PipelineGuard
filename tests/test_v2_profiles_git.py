import subprocess

import pytest

from pipelineguard.git_context import get_git_context
from pipelineguard.profiles import get_profile


def test_scan_profiles_have_expected_cost_envelopes():
    assert get_profile("quick").online_intelligence is False
    assert get_profile("standard").incremental is True
    assert get_profile("deep").deep_analysis is True
    assert get_profile("release").history_secrets is True
    assert get_profile("forensic").incremental is False


def test_unknown_scan_profile_is_rejected():
    with pytest.raises(ValueError, match="Unknown scan profile"):
        get_profile("impossible")


def test_git_context_degrades_outside_repository(tmp_path):
    assert get_git_context(tmp_path) == {"available": False}


def test_git_context_reports_commit_and_dirty_state(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "pipelineguard@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "PipelineGuard Test"], cwd=tmp_path, check=True)
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    subprocess.run(["git", "add", "a.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, check=True, capture_output=True)

    context = get_git_context(tmp_path)
    assert context["available"] is True
    assert len(context["commit"]) == 40
    assert context["dirty"] is False

    (tmp_path / "a.txt").write_text("changed", encoding="utf-8")
    assert get_git_context(tmp_path)["dirty"] is True
