from pathlib import Path

from pipelineguard.secret_scanner import scan_directory


def test_detects_generic_secret(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('API_KEY = "this-is-a-fake-secret-key"\n', encoding="utf-8")
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_ignores_virtual_environment(tmp_path: Path) -> None:
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "config.py").write_text('PASSWORD = "fake-test-secret"\n', encoding="utf-8")
    assert scan_directory(tmp_path) == []


def test_clean_project_has_no_findings(tmp_path: Path) -> None:
    (tmp_path / "hello.py").write_text("print('hello')\n", encoding="utf-8")
    assert scan_directory(tmp_path) == []
