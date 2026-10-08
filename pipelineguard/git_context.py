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


def get_git_context(root: Path) -> dict[str, object]:
    commit = _git(root, "rev-parse", "HEAD")
    if not commit:
        return {"available": False}
    with ThreadPoolExecutor(max_workers=3) as pool:
        branch_job = pool.submit(_git, root, "branch", "--show-current")
        status_job = pool.submit(_git, root, "status", "--porcelain")
        remote_job = pool.submit(_git, root, "config", "--get", "remote.origin.url")
        branch = branch_job.result()
        status = status_job.result()
        remote = remote_job.result()
    return {
        "available": True,
        "commit": commit,
        "branch": branch or None,
        "dirty": bool(status),
        "remote": _safe_remote(remote),
    }
