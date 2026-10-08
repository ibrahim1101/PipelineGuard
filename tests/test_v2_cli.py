import json

from typer.testing import CliRunner
from pipelineguard.main import app


def test_cli_profile_baseline_and_explicit_update(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "user-cache"))
    project = tmp_path / "project"
    project.mkdir()
    (project / "hello.py").write_text("print('ok')", encoding="utf-8")
    baseline = project / ".pipelineguard-baseline.json"
    args = ["scan", str(project), "--profile", "quick", "--baseline", str(baseline), "--json"]
    first = CliRunner().invoke(app, args + ["--save-baseline"])
    assert first.exit_code == 0, first.output
    report = json.loads(first.output)
    assert report["scan_profile"] == "quick"
    assert report["baseline"]["new"] == 1  # offline intelligence warning
    assert baseline.exists()
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0, second.output
    assert json.loads(second.output)["baseline"]["existing"] == 1
