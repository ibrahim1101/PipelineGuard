"""Reusable privacy-safe SOC finding inspector for the v2 desktop.

A presentation component, not a new scanner. The existing desktop inspector
will be migrated to this widget after the large desktop.py edit is unblocked.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Mapping

from pipelineguard.soc_inspector import (
    masked_code_preview, safe_finding_details, safe_finding_heading,
)
from pipelineguard.theme import (
    CARD, OLIVE_DEEP, OLIVE_DARK, OLIVE_LIGHT, INK, MUTED,
    BORDER, WHITE, BLOCKED, WARNING, SAFE,
)


class FindingInspector(tk.Frame):
    """Dark SOC inspector with a severity pill and intentionally masked preview."""

    def __init__(self, parent: tk.Misc, **kwargs: Any) -> None:
        super().__init__(parent, bg=CARD, highlightbackground=BORDER,
                         highlightthickness=1, **kwargs)
        self._current: Mapping[str, Any] | None = None
        tk.Label(self, text="FINDING INSPECTOR", bg=CARD, fg=OLIVE_LIGHT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=(15, 10))
        header = tk.Frame(self, bg=CARD)
        header.pack(fill="x", padx=16, pady=(0, 10))
        self.badge = tk.Label(header, text="SELECT", bg=OLIVE_DARK, fg=WHITE,
                              padx=10, pady=6, font=("Segoe UI", 9, "bold"))
        self.badge.pack(side="left")
        self.title_label = tk.Label(header, text="Choose a finding", bg=CARD,
                                    fg=INK, font=("Segoe UI", 10, "bold"),
                                    anchor="w", wraplength=250)
        self.title_label.pack(side="left", fill="x", expand=True, padx=(10, 0))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=16)
        tk.Label(self, text="DETAILS & REMEDIATION", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        self.details_text = tk.Text(self, height=9, width=38, wrap="word",
                                    bg=CARD, fg=INK, relief="flat",
                                    font=("Consolas", 9), padx=12, pady=8,
                                    insertbackground=INK)
        self.details_text.pack(fill="both", expand=True, padx=10)
        tk.Label(self, text="MASKED SOURCE PREVIEW", bg=CARD, fg=OLIVE_LIGHT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        self.preview_text = tk.Text(self, height=6, width=38, wrap="word",
                                    bg=OLIVE_DEEP, fg=MUTED, relief="flat",
                                    font=("Consolas", 9), padx=12, pady=10)
        self.preview_text.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.copy_button = ttk.Button(self, text="Copy safe details",
                                       command=self.copy_safe_details)
        self.copy_button.pack(anchor="e", padx=16, pady=(0, 14))
        self.clear()
        self._bind_findings_tree()

    def _bind_findings_tree(self) -> None:
        """Clear stale details when the owning findings table loses selection."""
        # The desktop places its Treeview inside a sibling table card.
        # Standalone inspector tests have no table, so binding is optional.
        for sibling in self.master.winfo_children():
            if sibling is self:
                continue
            for child in sibling.winfo_children():
                if isinstance(child, ttk.Treeview):
                    child.bind("<<TreeviewSelect>>", self._on_tree_selection, add="+")
                    return

    def _on_tree_selection(self, event: tk.Event) -> None:
        if not event.widget.selection():
            self.clear()

    @staticmethod
    def _set_readonly(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def clear(self) -> None:
        self._current = None
        self.badge.configure(text="SELECT", bg=OLIVE_DARK)
        self.title_label.configure(text="Choose a finding")
        self._set_readonly(self.details_text, "Select a finding to inspect its details.")
        self._set_readonly(self.preview_text, "No source location selected.")
        self.copy_button.state(["disabled"])

    def select_finding(self, finding: Mapping[str, Any]) -> None:
        severity, rule = safe_finding_heading(finding)
        colors = {
            "CRITICAL": BLOCKED, "HIGH": BLOCKED,
            "WARNING": WARNING, "MEDIUM": WARNING,
            "LOW": SAFE, "INFO": OLIVE_DARK,
        }
        self._current = finding
        self.badge.configure(text=severity, bg=colors.get(severity, OLIVE_DARK))
        self.title_label.configure(text=rule)
        self._set_readonly(self.details_text, safe_finding_details(finding))
        self._set_readonly(self.preview_text, masked_code_preview(finding))
        self.copy_button.state(["!disabled"])

    def copy_safe_details(self) -> None:
        if self._current is None:
            return
        self.clipboard_clear()
        self.clipboard_append(safe_finding_details(self._current))
