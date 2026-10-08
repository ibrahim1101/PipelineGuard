"""Regression tests for concurrent, read-only Git context collection."""

import shutil
import subprocess

import pytest

from pipelineguard.git_context import get_git_context


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git executable required")


def _git(root, *args):
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "PipelineGuard Regression")
    (tmp_path / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt")
    _git(tmp_path, "commit", "-m", "initial")
    return tmp_path


def test_clean_repository(repo):
    context = get_git_context(repo)
    assert context == {
        "available": True,
        "commit": _git(repo, "rev-parse", "HEAD"),
        "branch": _git(repo, "branch", "--show-current"),
        "dirty": False,
        "remote": None,
    }


def test_modified_tracked_file_marks_dirty(repo):
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    assert get_git_context(repo)["dirty"] is True


def test_untracked_file_marks_dirty(repo):
    (repo / "new.txt").write_text("untracked\n", encoding="utf-8")
    assert get_git_context(repo)["dirty"] is True


def test_detached_head_has_no_branch(repo):
    commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "--detach", commit)
    context = get_git_context(repo)
    assert context["available"] is True
    assert context["commit"] == commit
    assert context["branch"] is None
    assert context["dirty"] is False


def test_non_git_directory_unavailable(tmp_path):
    assert get_git_context(tmp_path) == {"available": False}


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        ("https://alice:fake-token@github.com/owner/repo.git?token=hidden#fragment",
         "https://github.com/owner/repo.git"),
        ("git@github.com:owner/repo.git", "ssh://github.com/owner/repo.git"),
        ("https://alice:fake-token@github.com/private/hidden/owner/repo.git",
         "https://github.com"),
    ],
)
def test_remote_credentials_never_exported(repo, remote, expected):
    _git(repo, "remote", "add", "origin", remote)
    context = get_git_context(repo)
    assert context["remote"] == expected
    assert "fake-token" not in str(context)
    assert "hidden" not in str(context)


def test_branch_with_upstream(repo):
    _git(repo, "remote", "add", "origin", "https://github.com/example/repo.git")
    current = _git(repo, "branch", "--show-current")
    _git(repo, "update-ref", f"refs/remotes/origin/{current}", _git(repo, "rev-parse", "HEAD"))
    _git(repo, "branch", "--set-upstream-to", f"origin/{current}", current)
    context = get_git_context(repo)
    assert context["branch"] == current
    assert context["dirty"] is False


def test_staged_change_marks_dirty(repo):
    (repo / "tracked.txt").write_text("staged\\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    assert get_git_context(repo)["dirty"] is True
