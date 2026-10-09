"""Tests for the reusable privacy-safe finding panel."""
import tkinter as tk

import pytest

from pipelineguard.soc_inspector import safe_finding_heading
from pipelineguard.soc_finding_panel import FindingInspector


def test_bounded_inspector_heading():
    severity, rule = safe_finding_heading({
        "severity": "critical\nignored",
        "rule": "Rule\rName" + "X" * 300,
        "snippet": "TOP-SECRET-NEVER-RENDER",
    })
    assert "\n" not in severity and "\r" not in rule
    assert len(severity) <= 17 and len(rule) <= 91
    assert "TOP-SECRET" not in severity + rule


def test_panel_displays_only_safe_metadata():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Graphical display unavailable")
    root.withdraw()
    try:
        panel = FindingInspector(root)
        assert str(panel.copy_button.state()).find("disabled") >= 0
        panel.select_finding({
            "severity": "CRITICAL",
            "rule": "EXAMPLE_SECRET",
            "file": "example.py",
            "line": 9,
            "summary": "DO-NOT-SHOW-THIS-SECRET",
            "snippet": "DO-NOT-SHOW-THIS-SECRET",
        })
        visible = (panel.details_text.get("1.0", "end") +
                   panel.preview_text.get("1.0", "end") +
                   str(panel.title_label.cget("text")))
        assert "EXAMPLE_SECRET" in visible
        assert "DO-NOT-SHOW-THIS-SECRET" not in visible
        assert "source content hidden" in visible
        assert panel.badge.cget("text") == "CRITICAL"
        panel.copy_safe_details()
        assert "DO-NOT-SHOW-THIS-SECRET" not in root.clipboard_get()
        panel.clear()
        assert "disabled" in panel.copy_button.state()
    finally:
        root.destroy()
