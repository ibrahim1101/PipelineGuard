"""Basic window-level checks for the SOC companion dialogs."""
import tkinter as tk

import pytest

from pipelineguard.desktop import Desktop


@pytest.mark.parametrize("method, title", [
    ("show_settings", "PipelineGuard — Settings"),
    ("show_about", "PipelineGuard — About"),
])
def test_companion_dialogs(method, title):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Graphical display unavailable")
    root.withdraw()
    try:
        desktop = Desktop(root)
        getattr(desktop, method)()
        windows = [child for child in root.winfo_children()
                   if isinstance(child, tk.Toplevel)]
        assert len(windows) == 1
        assert windows[0].title() == title
        windows[0].destroy()
    finally:
        root.destroy()
