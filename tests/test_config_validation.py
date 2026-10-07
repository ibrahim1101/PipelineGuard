import json
import pytest
from typer.testing import CliRunner
from pipelineguard.config import load_config
from pipelineguard.main import app


@pytest.mark.parametrize("value", [
    [], {"fail_on_warning": "false"}, {"max_file_size": -1},
    {"minimum_score": 101}, {"max_file_size": True},
    {"ignored_directories": "build"}, {"allowlist": [{}]},
    {"allowlist": [{"rule": "Secret", "file": "a", "line": 0}]},
    {"fail_on_warnng": True},
])
def test_invalid_config_rejected(tmp_path, value):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_config(path)


def test_cli_config_error_has_exit_two(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"fail_on_warning":"false"}')
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--config", str(config)])
    assert result.exit_code == 2
    assert "Configuration error" in result.output
