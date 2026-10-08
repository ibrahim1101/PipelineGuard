"""Tests for the optional finding callback in the shared scan engine."""
from pathlib import Path

from pipelineguard.engine import run_scan


def test_finding_callback_matches_report(tmp_path: Path):
    (tmp_path / "app.py").write_text('password = "not-a-real-secret-123"\\n', encoding="utf-8")
    seen = []
    report = run_scan(tmp_path, online=False, on_finding=seen.append)
    # Report findings may carry presentation fields not present in raw events.
    assert seen
    assert any(item.get("rule") == "Generic secret assignment" for item in seen)
    assert len(seen) <= len(report["findings"])


def test_callback_not_required(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('ok')\\n", encoding="utf-8")
    assert "findings" in run_scan(tmp_path, online=False)
