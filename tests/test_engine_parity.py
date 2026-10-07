import json
from unittest.mock import patch
from typer.testing import CliRunner
from pipelineguard.engine import run_scan
from pipelineguard.main import app


def test_cli_and_desktop_engine_match(tmp_path):
    (tmp_path / "settings").write_text('password="abcdefgh123"')
    with patch("pipelineguard.engine.query_osv", return_value=[]):
        expected = run_scan(tmp_path)
        result = CliRunner().invoke(app, ["scan", str(tmp_path), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output) == expected
