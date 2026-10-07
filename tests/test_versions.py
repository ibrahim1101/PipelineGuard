import json

from scanners.dependency_scanner import scan_dependencies


def test_npm_ranges_are_not_exact_versions(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "^1.2.3", "b": "1.2.3", "c": "https://example.org/1.2.3"}}))
    packages = scan_dependencies(tmp_path)[0]["dependencies"]
    assert [item["version"] for item in packages] == ["", "1.2.3", ""]
    assert [item["constraint_type"] for item in packages] == ["range", "exact", "url"]


def test_python_wildcards_are_not_versions(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.*\nother[extra]==1.2.3\n")
    packages = scan_dependencies(tmp_path)[0]["dependencies"]
    assert [item["version"] for item in packages] == ["", "1.2.3"]


def test_pyproject_dependencies_are_read(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["demo==1.2.3", "other>=2"]\n')
    packages = scan_dependencies(tmp_path)[0]["dependencies"]
    assert [item["version"] for item in packages] == ["1.2.3", ""]


def test_common_python_ranges_are_classified_without_guessing(tmp_path):
    (tmp_path / "requirements.txt").write_text("a~=1.4\nb>=2,<3\nc==2.0.1\n")
    packages = scan_dependencies(tmp_path)[0]["dependencies"]
    assert [item["constraint_type"] for item in packages] == ["range", "range", "exact"]
    assert [item["version"] for item in packages] == ["", "", "2.0.1"]


def test_invalid_dependency_structure_is_warning(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": []}')
    assert scan_dependencies(tmp_path)[0]["severity"] == "WARNING"
