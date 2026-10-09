"""Tiny-file scan race checks."""
from pipelineguard import secret_cache


def test_tiny_file_changed_during_scan(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "sample.txt"
    target.write_text("initial")
    original = secret_cache.scan_text

    def change_after_read(content, relative):
        target.write_text("updated")
        return original(content, relative)

    monkeypatch.setattr(secret_cache, "scan_text", change_after_read)
    metrics = {}
    assert secret_cache.scan_secrets_incremental(root, set(), 10000, metrics=metrics) == []
    assert metrics["skipped_changed"] == 1
    assert metrics["scanned"] == 0
