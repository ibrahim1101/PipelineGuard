from pathlib import Path

from pipelineguard.config import apply_allowlist, load_config, policy_blocks


def test_loads_custom_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text('{"ignored_directories": ["custom"], "fail_on_warning": true}', encoding="utf-8")
    config = load_config(config_file)
    assert config.ignored_directories == {"custom"}
    assert config.fail_on_warning is True


def test_allowlist_removes_only_matching_finding() -> None:
    findings = [
        {"rule": "Secret", "file": "example.env", "line": 2},
        {"rule": "Secret", "file": "real.env", "line": 2},
    ]
    result = apply_allowlist(findings, [{"rule": "Secret", "file": "example.env", "line": 2}])
    assert result == [{"rule": "Secret", "file": "real.env", "line": 2}]


def test_policy_blocks_low_score() -> None:
    config = load_config(None)
    config.minimum_score = 80
    assert policy_blocks({"score": 70, "findings": []}, config)


def test_policy_blocks_selected_rule() -> None:
    config = load_config(None)
    config.blocked_rules = {"Private key"}
    assert policy_blocks({"score": 100, "findings": [{"rule": "Private key"}]}, config)


def test_allowlist_supports_scoped_file_patterns() -> None:
    findings = [
        {"rule": "Generic secret assignment", "file": "tests/fixtures/example.env", "line": 1},
        {"rule": "Generic secret assignment", "file": "src/config.env", "line": 1},
        {"rule": "Generic secret assignment", "file": "tests/fixtures/real.env", "line": 2},
    ]
    result = apply_allowlist(findings, [{"rule": "Generic secret assignment", "file": "tests/fixtures/*.env", "line": 1}])
    assert result == [findings[1], findings[2]]
