"""Race checks for incremental secret scanning."""
from pipelineguard import secret_cache


def test_changed_file_is_discarded(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "sample.txt"
    target.write_text("initial " * 300)
    original = secret_cache.scan_text

    def change_after_read(content, relative):
        target.write_text("updated " * 300)
        return original(content, relative)

    monkeypatch.setattr(secret_cache, "scan_text", change_after_read)
    metrics = {}
    assert secret_cache.scan_secrets_incremental(root, set(), 10000, metrics=metrics) == []
    assert metrics["skipped_changed"] == 1
    assert metrics["scanned"] == 0
    monkeypatch.setattr(secret_cache, "scan_text", original)
    metrics = {}
    assert secret_cache.scan_secrets_incremental(root, set(), 10000, metrics=metrics) == []
    assert metrics["scanned"] == 1
    assert metrics["reused"] == 0
