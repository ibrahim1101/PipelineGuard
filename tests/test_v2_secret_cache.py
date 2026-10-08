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


def test_tampered_cache_entry_is_rescanned(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    data = json.loads(cache.read_text())
    data["files"]["a.txt"]["findings"] = [{"severity": "SAFE", "rule": "unknown", "confidence": "high", "file": "a.txt", "line": 0}]
    cache.write_text(json.dumps(data))
    calls = []
    original = secret_cache.scan_file
    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_file", spy)
    assert scan_secrets_incremental(root, set(), 100) == []
    assert calls == [1]


def test_changed_limit_invalidates_cache(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    calls = []
    original = secret_cache.scan_file
    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_file", spy)
    scan_secrets_incremental(root, set(), 101)
    assert calls == [1]


def test_unchanged_cache_is_not_rewritten(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    scan_secrets_incremental(root, set(), 100)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    before = cache.stat().st_mtime_ns
    assert scan_secrets_incremental(root, set(), 100) == []
    assert cache.stat().st_mtime_ns == before


def test_cache_metrics_distinguish_scan_and_reuse(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    first = {}
    scan_secrets_incremental(root, set(), 100, metrics=first)
    assert first == {"discovered": 1, "hashed": 1, "scanned": 1, "reused": 0,
                     "skipped_size": 0, "skipped_changed": 0, "skipped_error": 0}
    second = {}
    scan_secrets_incremental(root, set(), 100, metrics=second)
    assert second["reused"] == 1
    assert second["scanned"] == 0
    target.write_text("changed", encoding="utf-8")
    third = {}
    scan_secrets_incremental(root, set(), 100, metrics=third)
    assert third["scanned"] == 1
    assert third["reused"] == 0


def test_cache_metrics_count_oversize_files(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text("a" * 101, encoding="utf-8")
    counts = {}
    assert scan_secrets_incremental(root, set(), 100, metrics=counts) == []
    assert counts["discovered"] == 1
    assert counts["skipped_size"] == 1
    assert counts["hashed"] == 0


def test_tiny_files_are_scanned_without_cache(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    calls = []
    original = secret_cache.scan_file
    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_file", spy)
    first = {}
    second = {}
    assert scan_secrets_incremental(root, set(), 100, metrics=first) == []
    assert scan_secrets_incremental(root, set(), 100, metrics=second) == []
    assert calls == [1, 1]
    assert first["hashed"] == second["hashed"] == 0
    assert first["scanned"] == second["scanned"] == 1
    assert second["reused"] == 0


def test_large_file_reuses_verified_cache(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text("safe " * 300)
    limit = 10000
    first = {}
    scan_secrets_incremental(root, set(), limit, metrics=first)
    assert first["scanned"] == first["hashed"] == 1
    def unexpected(*args, **kwargs):
        raise AssertionError("large unchanged file should be reused")
    monkeypatch.setattr(secret_cache, "scan_file", unexpected)
    second = {}
    assert scan_secrets_incremental(root, set(), limit, metrics=second) == []
    assert second["reused"] == second["hashed"] == 1
