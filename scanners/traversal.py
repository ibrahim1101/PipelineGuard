"""Shared traversal: prune ignored folders and PipelineGuard-generated state."""
import os
from pathlib import Path

DEFAULT_IGNORES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
GENERATED_FILES = {".pipelineguard-cache.json", ".pipelineguard-baseline.json"}


def iter_files(root: Path, ignored: set[str] | None = None):
    excluded = DEFAULT_IGNORES if ignored is None else ignored
    for directory, folders, files in os.walk(root, followlinks=False):
        base = Path(directory)
        folders[:] = sorted(name for name in folders if name not in excluded and not (base / name).is_symlink())
        for name in sorted(files):
            if name in GENERATED_FILES:
                continue
            path = base / name
            if not path.is_symlink() and path.is_file():
                yield path
