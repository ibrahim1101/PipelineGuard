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


def _file_identity(stat: os.stat_result) -> tuple[int, int, int, int, int]:
    """Detect replacement or in-flight modification while hashing."""
    return (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_dev, stat.st_ino)


@dataclass
class ScanCache:
    """Persistent fingerprints keyed by normalized repository-relative path.

    Cached metadata never proves content is unchanged. Re-hash each file
    before marking a fingerprint reusable. This allows a future result cache
    to skip expensive parsing without trusting timestamps.
    """

    path: Path
    entries: dict[str, dict[str, object]] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path, name: str = DEFAULT_CACHE_NAME) -> "ScanCache":
        cache_path = root / name
        if not cache_path.exists():
            return cls(cache_path)
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if (not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION
                    or not isinstance(payload.get("entries"), dict)):
                return cls(cache_path)
            entries = payload["entries"]
            if any(not isinstance(key, str) or not isinstance(value, dict)
                   for key, value in entries.items()):
                return cls(cache_path)
            return cls(cache_path, dict(entries))
        except (OSError, ValueError, TypeError):
            return cls(cache_path)

    def key_for(self, root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

    def digest(self, root: Path, path: Path) -> tuple[str, bool]:
        """Return verified SHA-256 and whether previous content matched.

        The second value indicates a verified match, NOT skipped I/O.
        """
        key = self.key_for(root, path)
        for _ in range(2):
            before = path.stat()
            value = sha256_file(path)
            after = path.stat()
            if _file_identity(before) == _file_identity(after):
                cached = self.entries.get(key, {})
                reused = cached.get("sha256") == value
                self.entries[key] = {
                    "size": after.st_size,
                    "mtime_ns": after.st_mtime_ns,
                    "ctime_ns": after.st_ctime_ns,
                    "sha256": value,
                }
                return value, reused
        raise OSError(f"File changed while hashing: {path}")

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
