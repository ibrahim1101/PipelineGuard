"""Read-only Git context for scan attribution and future differential analysis."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def get_git_context(root: Path) -> dict[str, object]:
    commit = _git(root, "rev-parse", "HEAD")
    if not commit:
        return {"available": False}
    branch = _git(root, "branch", "--show-current")
    status = _git(root, "status", "--porcelain")
    remote = _git(root, "config", "--get", "remote.origin.url")
    return {
        "available": True,
        "commit": commit,
        "branch": branch or None,
        "dirty": bool(status),
        "remote": remote,
    }
