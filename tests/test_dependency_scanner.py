from pathlib import Path

from scanners.dependency_scanner import scan_dependencies


def test_inventories_python_dependencies(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("typer>=0.12\nrich==13.7.1\n", encoding="utf-8")
    findings = scan_dependencies(tmp_path)
    assert findings[0]["dependency_count"] == 2


def test_reports_invalid_package_manifest(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{invalid", encoding="utf-8")
    findings = scan_dependencies(tmp_path)
    assert findings[0]["severity"] == "WARNING"
