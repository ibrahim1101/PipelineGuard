from pipelineguard.engine import run_scan


def test_desktop_offline_scan_reports_incomplete(tmp_path):
    result = run_scan(tmp_path, online=False)
    assert result["status"] == "WARNING"
    assert not result["dependency_check_complete"]


def test_desktop_secret_scan_blocks(tmp_path):
    (tmp_path / "config").write_text('password="abcdefgh123"')
    result = run_scan(tmp_path, online=False)
    assert result["status"] == "BLOCKED"
