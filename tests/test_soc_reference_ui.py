"""Visual structure and data provenance checks for the v2 SOC dashboard."""
import tkinter as tk
from types import SimpleNamespace

import pytest

from pipelineguard.desktop import Desktop
from pipelineguard.reporting import build_report


@pytest.fixture
def dashboard():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Graphical display unavailable")
    root.withdraw()
    app = Desktop(root)
    yield app
    root.destroy()


def test_single_scan_action_and_soc_canvases(dashboard):
    assert dashboard.header_scan_button.winfo_manager() == "pack"
    assert dashboard.scan_button.winfo_manager() == ""
    assert dashboard.score_gauge.winfo_exists()
    assert dashboard.severity_chart.winfo_exists()
    assert dashboard.trend_chart.winfo_exists()
    assert len(dashboard.issue_labels) == 5


def test_issue_counts_come_from_report(dashboard):
    report = build_report([
        {"severity": "CRITICAL", "rule": "Test rule A", "file": "a.py", "line": 1},
        {"severity": "CRITICAL", "rule": "Test rule A", "file": "b.py", "line": 2},
        {"severity": "WARNING", "rule": "Test rule B", "file": "c.py", "line": 3},
    ], [])
    dashboard.report = report
    dashboard._refresh_analytics(report)
    assert "Test rule A" in str(dashboard.issue_labels[0].cget("text"))
    assert "2" in str(dashboard.issue_labels[0].cget("text"))
    assert "Test rule B" in str(dashboard.issue_labels[1].cget("text"))


def test_activity_uses_observed_stages(dashboard):
    dashboard._record_activity("Scan started")
    dashboard._process_scan_event(
        "progress", SimpleNamespace(stage="dependencies", discovered=None,
                                    processed=None, cached=0))
    value = str(dashboard.scan_activity_text.cget("text"))
    assert "Scan started" in value
    assert "Scanning dependencies" in value
    assert "Scan complete" not in value
