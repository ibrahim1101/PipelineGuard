"""Regression checks for content-hash reuse."""
import hashlib
import json
import os

from pipelineguard.secret_cache import scan_secrets_incremental


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("safe")
    return root, target


def test_modified_file_rechecked_even_with_same_size_and_mtime(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    original = target.stat()
    target.write_text("note")
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    calls = []
    scanner = secret_cache.scan_file
    def spy(*args, **kwargs):
        calls.append(1)
        return scanner(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_file", spy)
    scan_secrets_incremental(root, set(), 100)
    assert calls == [1]


def test_unchanged_file_reuses_cached_result(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged source rescanned")
    monkeypatch.setattr(secret_cache, "scan_file", unexpected)
    assert scan_secrets_incremental(root, set(), 100) == []


def test_corrupt_cache_rescans_and_prunes_deleted_file(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    cache.write_text("{invalid")
    assert scan_secrets_incremental(root, set(), 100) == []
    target.unlink()
    assert scan_secrets_incremental(root, set(), 100) == []
    assert json.loads(cache.read_text())["files"] == {}
