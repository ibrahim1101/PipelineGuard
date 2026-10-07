"""Persistent content-hash cache for incremental PipelineGuard scans."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

CACHE_VERSION = 1
DEFAULT_CACHE_NAME = ".pipelineguard-cache.json"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return a streaming SHA-256 digest without loading the whole file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class ScanCache:
    """Small persistent cache keyed by normalized repository-relative path."""

    path: Path
    entries: dict[str, dict[str, object]] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path, name: str = DEFAULT_CACHE_NAME) -> "ScanCache":
        cache_path = root / name
        if not cache_path.exists():
            return cls(cache_path)
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if payload.get("version") != CACHE_VERSION or not isinstance(payload.get("entries"), dict):
                return cls(cache_path)
            return cls(cache_path, dict(payload["entries"]))
        except (OSError, json.JSONDecodeError, AttributeError):
            # A damaged cache must never prevent a security scan.
            return cls(cache_path)

    def key_for(self, root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

    def digest(self, root: Path, path: Path) -> tuple[str, bool]:
        """Return digest and whether the cached fingerprint could be reused."""
        key = self.key_for(root, path)
        stat = path.stat()
        cached = self.entries.get(key, {})
        if cached.get("size") == stat.st_size and cached.get("mtime_ns") == stat.st_mtime_ns and cached.get("sha256"):
            return str(cached["sha256"]), True
        value = sha256_file(path)
        self.entries[key] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "sha256": value}
        return value, False

    def prune(self, live_keys: set[str]) -> None:
        self.entries = {key: value for key, value in self.entries.items() if key in live_keys}

    def save(self) -> None:
        """Atomically persist cache so interrupted writes do not corrupt it."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": CACHE_VERSION, "entries": self.entries}
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
