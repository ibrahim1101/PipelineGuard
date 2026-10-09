"""Read-only, credential-redacted Git context for scan attribution."""
from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_HOST = re.compile(r"^[A-Za-z0-9.-]+$")
_SCP = re.compile(r"^(?:[^@/:\s]+@)?([A-Za-z0-9.-]+):(.+)$")


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


def _safe_remote(value: str | None) -> str | None:
    """Keep only a conventional repository locator; strip credentials/tokens.

    Reject local paths and ambiguous or unusually structured remotes instead
    of accidentally exporting an access token in a scan report.
    """
    if not value:
        return None
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"https", "http", "ssh", "git"}:
                return None
            host = parsed.hostname
        except ValueError:
            return None
        if not host or not _HOST.fullmatch(host):
            return None
        scheme = parsed.scheme
        raw_path = parsed.path
    else:
        match = _SCP.fullmatch(value)
        if not match:
            return None
        host, raw_path = match.groups()
        scheme = "ssh"
    path = raw_path.strip("/")
    segments = path.split("/")
    if len(segments) == 2 and all(_SEGMENT.fullmatch(segment) for segment in segments):
        return f"{scheme}://{host}/{path}"
    return f"{scheme}://{host}"


def _branch_and_dirty(status: str | None) -> tuple[str | None, bool]:
    """Extract branch and working-tree state from porcelain v1 branch output."""
    if not status:
        return None, False
    lines = status.splitlines()
    if not lines or not lines[0].startswith("## "):
        return None, bool(status)
    header = lines[0][3:]
    if header.startswith("HEAD (detached") or header == "HEAD (no branch)":
        branch = None
    elif header.startswith("No commits yet on "):
        branch = header[len("No commits yet on "):]
    elif header.startswith("Initial commit on "):
        branch = header[len("Initial commit on "):]
    else:
        branch = header.split("...", 1)[0]
    return branch or None, len(lines) > 1


def get_git_context(root: Path) -> dict[str, object]:
    commit = _git(root, "rev-parse", "HEAD")
    if not commit:
        return {"available": False}
    with ThreadPoolExecutor(max_workers=2) as pool:
        status_job = pool.submit(_git, root, "status", "--porcelain=v1", "--branch")
        remote_job = pool.submit(_git, root, "config", "--get", "remote.origin.url")
        status = status_job.result()
        branch, dirty = _branch_and_dirty(status)
        remote = remote_job.result()
    return {
        "available": True,
        "commit": commit,
        "branch": branch or None,
        "dirty": dirty,
        "remote": _safe_remote(remote),
    }
