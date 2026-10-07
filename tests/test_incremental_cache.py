from pathlib import Path

from pipelineguard.cache import ScanCache
from pipelineguard.orchestrator import fingerprint_files
from scanners.traversal import iter_files


def test_incremental_cache_reuses_unchanged_files(tmp_path: Path):
    (tmp_path / "a.py").write_text("print('a')", encoding="utf-8")
    (tmp_path / "b.txt").write_text("hello", encoding="utf-8")
    events = []

    first = ScanCache.load(tmp_path)
    first_hashes = fingerprint_files(tmp_path, iter_files(tmp_path), first, workers=2, progress=events.append)
    assert set(first_hashes) == {"a.py", "b.txt"}
    assert events[-1].stage == "fingerprint-complete"
    assert events[-1].cached == 0

    events.clear()
    second = ScanCache.load(tmp_path)
    second_hashes = fingerprint_files(tmp_path, iter_files(tmp_path), second, workers=2, progress=events.append)
    assert second_hashes == first_hashes
    assert events[-1].cached == 2


def test_incremental_cache_detects_changed_and_removed_files(tmp_path: Path):
    keep = tmp_path / "keep.py"
    remove = tmp_path / "remove.py"
    keep.write_text("one", encoding="utf-8")
    remove.write_text("gone", encoding="utf-8")

    cache = ScanCache.load(tmp_path)
    original = fingerprint_files(tmp_path, iter_files(tmp_path), cache)
    keep.write_text("two", encoding="utf-8")
    remove.unlink()

    cache = ScanCache.load(tmp_path)
    updated = fingerprint_files(tmp_path, iter_files(tmp_path), cache)
    assert updated["keep.py"] != original["keep.py"]
    assert "remove.py" not in updated
    assert "remove.py" not in cache.entries


def test_corrupt_cache_degrades_gracefully(tmp_path: Path):
    (tmp_path / ".pipelineguard-cache.json").write_text("{broken", encoding="utf-8")
    cache = ScanCache.load(tmp_path)
    assert cache.entries == {}


def test_traversal_excludes_pipelineguard_generated_state(tmp_path: Path):
    (tmp_path / "source.py").write_text("pass", encoding="utf-8")
    (tmp_path / ".pipelineguard-cache.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".pipelineguard-baseline.json").write_text("{}", encoding="utf-8")
    assert [path.name for path in iter_files(tmp_path)] == ["source.py"]
