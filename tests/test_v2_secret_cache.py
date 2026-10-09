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
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    original = target.stat()
    target.write_text("note " * 300)
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    calls = []
    scanner = secret_cache.scan_text
    def spy(*args, **kwargs):
        calls.append(1)
        return scanner(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_text", spy)
    scan_secrets_incremental(root, set(), 10000)
    assert calls == [1]


def test_unchanged_file_reuses_cached_result(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged source rescanned")
    monkeypatch.setattr(secret_cache, "scan_text", unexpected)
    assert scan_secrets_incremental(root, set(), 10000) == []


def test_corrupt_cache_rescans_and_prunes_deleted_file(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    cache.write_text("{invalid")
    assert scan_secrets_incremental(root, set(), 10000) == []
    target.unlink()
    assert scan_secrets_incremental(root, set(), 10000) == []
    assert json.loads(cache.read_text())["files"] == {}


def test_tampered_cache_entry_is_rescanned(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    data = json.loads(cache.read_text())
    data["files"]["a.txt"]["findings"] = [{"severity": "SAFE", "rule": "unknown", "confidence": "high", "file": "a.txt", "line": 0}]
    cache.write_text(json.dumps(data))
    calls = []
    original = secret_cache.scan_text
    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_text", spy)
    assert scan_secrets_incremental(root, set(), 10000) == []
    assert calls == [1]


def test_changed_limit_invalidates_cache(tmp_path, monkeypatch):
    from pipelineguard import secret_cache
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    calls = []
    original = secret_cache.scan_text
    def spy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(secret_cache, "scan_text", spy)
    scan_secrets_incremental(root, set(), 10001)
    assert calls == [1]


def test_unchanged_cache_is_not_rewritten(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    scan_secrets_incremental(root, set(), 10000)
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    cache = tmp_path / "cache" / "PipelineGuard" / "secret-findings" / name
    before = cache.stat().st_mtime_ns
    assert scan_secrets_incremental(root, set(), 10000) == []
    assert cache.stat().st_mtime_ns == before


def test_cache_metrics_distinguish_scan_and_reuse(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('safe ' * 300)
    first = {}
    scan_secrets_incremental(root, set(), 10000, metrics=first)
    assert first == {"discovered": 1, "hashed": 1, "scanned": 1, "reused": 0,
                     "skipped_size": 0, "skipped_changed": 0, "skipped_error": 0}
    second = {}
    scan_secrets_incremental(root, set(), 10000, metrics=second)
    assert second["reused"] == 1
    assert second["scanned"] == 0
    target.write_text("changed", encoding="utf-8")
    third = {}
    scan_secrets_incremental(root, set(), 10000, metrics=third)
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
    from scanners.secret_scanner import scan_directory
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('password="abcdefgh123"', encoding="utf-8")
    expected = scan_directory(root, set(), 100)
    assert expected
    first = {}
    second = {}
    assert scan_secrets_incremental(root, set(), 100, metrics=first) == expected
    assert scan_secrets_incremental(root, set(), 100, metrics=second) == expected
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
    monkeypatch.setattr(secret_cache, "scan_text", unexpected)
    second = {}
    assert scan_secrets_incremental(root, set(), limit, metrics=second) == []
    assert second["reused"] == second["hashed"] == 1


def test_strategy_selection_threshold_and_mixed_files(tmp_path):
    from pipelineguard.secret_cache import choose_scan_strategy
    root = tmp_path / "strategy"
    root.mkdir()
    for i in range(36):
        (root / f"{i:03d}.txt").write_text("small")
    for i in range(4):
        (root / f"{i + 36:03d}.txt").write_text("large" * 300)
    assert choose_scan_strategy(root, set(), 10000) == "full"
    (root / "035.txt").write_text("large" * 300)
    assert choose_scan_strategy(root, set(), 10000) == "incremental"


def test_strategy_selection_ignores_oversize_and_small_samples(tmp_path):
    from pipelineguard.secret_cache import choose_scan_strategy
    root = tmp_path / "strategy"
    root.mkdir()
    for i in range(20):
        (root / f"{i:03d}.txt").write_text("small")
    assert choose_scan_strategy(root, set(), 10000) == "incremental"
    for i in range(20, 40):
        (root / f"{i:03d}.txt").write_text("X" * 11000)
    assert choose_scan_strategy(root, set(), 10000) == "incremental"


def test_mixed_repository_parity(tmp_path, monkeypatch):
    from pipelineguard.secret_cache import choose_scan_strategy
    from scanners.secret_scanner import scan_directory
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text('password="abcdefgh123"')
    for i in range(40):
        (root / f"file-{i:03d}.txt").write_text("safe " * (300 if i % 4 == 0 else 2))
    assert choose_scan_strategy(root, set(), 10000) == "incremental"
    expected = scan_directory(root, set(), 10000)
    assert scan_secrets_incremental(root, set(), 10000) == expected
    assert scan_secrets_incremental(root, set(), 10000) == expected


def test_metrics_count_oversize_and_scanned_together(tmp_path, monkeypatch):
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text("safe " * 300)
    (root / "oversize.txt").write_text("X" * 12000)
    counts = {}
    scan_secrets_incremental(root, set(), 10000, metrics=counts)
    assert counts["discovered"] == 2
    assert counts["scanned"] == 1
    assert counts["skipped_size"] == 1
    assert counts["hashed"] == 1
    assert counts["reused"] == 0


def test_cache_write_error_keeps_scan_results(tmp_path, monkeypatch):
    from pathlib import Path
    root, target = _setup(tmp_path, monkeypatch)
    target.write_text("safe " * 300)
    original = Path.write_text

    def fail_cache_write(path, *args, **kwargs):
        if path.suffix == ".tmp":
            raise OSError("cache unavailable")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_cache_write)
    counts = {}
    assert scan_secrets_incremental(root, set(), 10000, metrics=counts) == []
    assert counts["scanned"] == 1
