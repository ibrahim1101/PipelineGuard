import pytest

from scanners.traversal import iter_files
from scanners.secret_scanner import scan_directory
from scanners.dependency_scanner import scan_dependencies


def test_custom_exclusions_apply_to_both_scanners(tmp_path):
    folder = tmp_path / "generated"
    folder.mkdir()
    (folder / "requirements.txt").write_text("demo==1.0")
    (folder / "config").write_text('password="abcdefgh123"')
    assert scan_dependencies(tmp_path, {"generated"}) == []
    assert scan_directory(tmp_path, {"generated"}) == []


def test_symlinked_files_are_skipped(tmp_path):
    source = tmp_path / "source"
    source.write_text("hello")
    try:
        (tmp_path / "link").symlink_to(source)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink creation requires Developer Mode or elevated privileges")
        raise
    assert list(iter_files(tmp_path)) == [source]


def test_empty_exclusions_are_respected(tmp_path):
    folder = tmp_path / "node_modules"
    folder.mkdir()
    (folder / "requirements.txt").write_text("demo==1.0")
    assert len(scan_dependencies(tmp_path, set())) == 1


def test_thousand_file_repository(tmp_path):
    for index in range(1000):
        (tmp_path / f"file-{index}.py").write_text("print('hello')")
    assert len(list(iter_files(tmp_path))) == 1000
    assert scan_directory(tmp_path) == []
