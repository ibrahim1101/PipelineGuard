import time

from scanners.secret_scanner import scan_directory
from scanners.traversal import iter_files


def test_ten_thousand_files_with_pruned_dependencies(tmp_path):
    for folder_index in range(100):
        folder = tmp_path / f"module-{folder_index}"
        folder.mkdir()
        for file_index in range(100):
            (folder / f"file-{file_index}.py").write_text("print('hello')")
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    for index in range(100):
        (ignored / f"file-{index}").write_text('password="abcdefgh123"')
    start = time.perf_counter()
    findings = scan_directory(tmp_path)
    elapsed = time.perf_counter() - start
    assert findings == []
    assert len(list(iter_files(tmp_path))) == 10000
    print(f"10,000-file scan: {elapsed:.3f}s (Linux synthetic fixture)")


def test_spaces_and_unicode_paths(tmp_path):
    folder = tmp_path / "project files — demo"
    folder.mkdir()
    target = folder / "settings file.txt"
    target.write_text('password="abcdefgh123"')
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0]["file"] == str(target.relative_to(tmp_path))
