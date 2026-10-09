"""Security regression tests for verified fingerprint reuse."""
import json
import os
from pathlib import Path

import pytest

from pipelineguard.cache import ScanCache
import pipelineguard.cache as cache_module


def test_same_size_restored_mtime_does_not_bypass_hash(tmp_path: Path):
    file = tmp_path / "source.py"
    file.write_text("abc", encoding="utf-8")
    original_mtime = file.stat().st_mtime_ns
    cache = ScanCache.load(tmp_path)
    first, reused = cache.digest(tmp_path, file)
    assert reused is False
    cache.save()
    file.write_text("xyz", encoding="utf-8")
    os.utime(file, ns=(original_mtime, original_mtime))
    loaded = ScanCache.load(tmp_path)
    second, reused = loaded.digest(tmp_path, file)
    assert first != second
    assert reused is False


def test_unchanged_content_reuses_verified_digest(tmp_path: Path):
    file = tmp_path / "source.py"
    file.write_text("hello", encoding="utf-8")
    cache = ScanCache.load(tmp_path)
    first, reused = cache.digest(tmp_path, file)
    assert not reused
    cache.save()
    second, reused = ScanCache.load(tmp_path).digest(tmp_path, file)
    assert first == second and reused


def test_invalid_cache_entry_does_not_crash(tmp_path: Path):
    path = tmp_path / ".pipelineguard-cache.json"
    path.write_text(json.dumps({"version": 1, "entries": {"source.py": "corrupt"}}))
    assert ScanCache.load(tmp_path).entries == {}


def test_in_flight_modification_fails_closed(tmp_path: Path, monkeypatch):
    file = tmp_path / "source.py"
    file.write_text("a", encoding="utf-8")
    original = cache_module.sha256_file

    def changing(path):
        digest = original(path)
        path.write_text(path.read_text() + "x", encoding="utf-8")
        return digest

    monkeypatch.setattr(cache_module, "sha256_file", changing)
    with pytest.raises(OSError, match="changed while hashing"):
        ScanCache.load(tmp_path).digest(tmp_path, file)
