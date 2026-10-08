"""Real Tk widget tests. Run on a graphical Windows/Linux session."""
import json
import tkinter as tk
from unittest.mock import patch

import pytest

from pipelineguard.desktop import Desktop
from pipelineguard.reporting import build_report


@pytest.fixture
def desktop():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Graphical display unavailable")
    root.withdraw()
    app = Desktop(root)
    yield app
    root.destroy()


def test_window_initial_state(desktop):
    assert desktop.report is None
    assert desktop.status.get().startswith("Ready")
    assert desktop.online.get()


def test_result_populates_findings_and_details(desktop):
    report = build_report([{"severity": "CRITICAL", "rule": "Secret", "file": "settings", "line": 1}], [])
    report["dependency_check_complete"] = True
    desktop.events.put(("result", report))
    desktop.poll()
    assert len(desktop.tree.get_children()) == 1
    desktop.tree.selection_set("0")
    desktop.details()
    assert "Secret" in desktop.detail.get("1.0", "end")
    assert "BLOCKED" in desktop.status.get()


def test_export_json(desktop, tmp_path):
    desktop.report = build_report([], [])
    path = tmp_path / "report.json"
    with patch("pipelineguard.desktop.filedialog.asksaveasfilename", return_value=str(path)):
        desktop.export()
    assert json.loads(path.read_text()) == desktop.report


def test_scan_error_restores_controls(desktop):
    desktop.scan_button.state(["disabled"])
    desktop.events.put(("error", "Test failure"))
    with patch("pipelineguard.desktop.messagebox.showerror") as message:
        desktop.poll()
    assert not desktop.scan_button.instate(["disabled"])
    message.assert_called_once()


def test_live_finding_updates_before_final_report(desktop):
    desktop.report = None
    desktop.all_findings = []
    desktop.events.put(("finding", {"severity": "CRITICAL", "rule": "Live test finding", "file": "example.py", "line": 1}))
    desktop.poll()
    assert desktop.report is None
    assert len(desktop.all_findings) == 1
    assert len(desktop.tree.get_children()) == 1
    assert desktop.findings_value.cget("text") == "1"
    desktop.tree.selection_set("0")
    desktop.details()
    assert "Live test finding" in desktop.detail.get("1.0", "end")
