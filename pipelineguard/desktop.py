"""Standalone matte-olive desktop interface; no HTTP server or browser."""
import json
import os
import sys
import subprocess
from datetime import datetime
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from pipelineguard.engine import run_scan
from pipelineguard.reporting import write_json_report, write_html_report, write_sarif_report
from pipelineguard.theme import (
    OLIVE, OLIVE_DARK, OLIVE_DEEP, OLIVE_MID, OLIVE_LIGHT, CANVAS,
    CARD, INK, MUTED, BORDER, SAFE, WARNING, BLOCKED, WHITE,
)


class Desktop:
    def __init__(self, root):
        self.root = root
        self.report = None
        self.all_findings = []
        self.scan_started = None
        self.last_export = None
        self.history_file = Path(os.environ.get("APPDATA", Path.home())) / "PipelineGuard" / "history.json"
        self.preferences_file = self.history_file.parent / "preferences.json"
        self.events = queue.Queue()
        self.root.title("PipelineGuard — Security Scanner")
        self.root.geometry("1180x780")
        self.root.minsize(900, 650)
        self.root.configure(bg=CANVAS)
        self.root.geometry("1440x900")
        self.root.minsize(1050, 700)

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background=CANVAS)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(14, 8),
                        background=OLIVE_MID, foreground=WHITE, borderwidth=0)
        style.map("TButton", background=[("active", OLIVE_DARK), ("disabled", BORDER)])
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=INK,
                        rowheight=32, borderwidth=0, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=OLIVE_DARK, foreground=WHITE,
                        font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Treeview", background=[("selected", OLIVE_DARK)], foreground=[("selected", WHITE)])
        style.configure("TEntry", fieldbackground=CARD, foreground=INK, insertcolor=INK)
        style.configure("TCombobox", fieldbackground=CARD, foreground=INK, background=OLIVE_DARK)
        style.map("TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", INK)])
        style.configure("Horizontal.TProgressbar", troughcolor=BORDER, background=OLIVE,
                        bordercolor=CANVAS, lightcolor=OLIVE, darkcolor=OLIVE)

        self._build_shell()
        self._build_header()
        self._build_controls()
        self._build_dashboard()
        self._build_analytics()
        self._build_charts()
        self._build_findings()
        self.root.after(100, self.poll)

    def _build_shell(self):
        """SOC navigation shell; existing scanner widgets remain intact."""
        self.sidebar = tk.Frame(self.root, bg=OLIVE_DEEP, width=174)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Label(self.sidebar, text="◈  PipelineGuard", bg=OLIVE_DEEP,
                 fg=OLIVE_LIGHT, font=("Segoe UI", 14, "bold")).pack(
                     anchor="w", padx=12, pady=(24, 30))
        self.workspace = tk.Frame(self.root, bg=CANVAS)
        self.workspace.pack(side="left", fill="both", expand=True)
        navigation = (
            ("▦  Dashboard", lambda: self._navigate("Dashboard")),
            ("⌕  Scan Project", lambda: self._navigate("Scan Project")),
            ("☷  Findings", lambda: self._navigate("Findings")),
            ("◫  Dependencies", lambda: self._navigate("Dependencies")),
            ("◇  OSV Lookup", lambda: self._navigate("OSV Lookup")),
            ("▤  Reports", lambda: self._navigate("Reports")),
            ("◷  Scan History", self.show_history),
            ("⚙  Settings", lambda: self._navigate("Settings")),
        )
        for label, callback in navigation:
            tk.Button(self.sidebar, text=label, command=callback, anchor="w",
                      bg=OLIVE_DARK if label.startswith("▦") else OLIVE_DEEP,
                      fg=WHITE, activebackground=OLIVE_MID,
                      activeforeground=WHITE, relief="flat", borderwidth=0,
                      font=("Segoe UI", 10), padx=14, pady=11).pack(fill="x", padx=7, pady=2)
        tk.Button(self.sidebar, text="ⓘ  About", command=self.show_about,
                  anchor="w", bg=OLIVE_DEEP, fg=OLIVE_LIGHT, relief="flat",
                  borderwidth=0, padx=14, pady=12).pack(side="bottom", fill="x")

    def _navigate(self, destination):
        """Navigate to a working section without presenting nonfunctional pages."""
        if destination == "Scan Project":
            self.scan_button.focus_set()
        elif destination == "Findings":
            self.tree.focus_set()
        elif destination == "Reports":
            self.export()
        elif destination == "Settings":
            self.show_config_help()
        elif destination == "OSV Lookup":
            messagebox.showinfo("OSV Lookup", "Enable live OSV lookup in the scan options, then scan a project.")
        elif destination == "Dependencies":
            messagebox.showinfo("Dependencies", "Dependency results are included in the findings table and exported report.")
        else:
            self.status_label.configure(text=self.status.get())

    def _label(self, parent, text, size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", CANVAS), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def _build_header(self):
        header = tk.Frame(self.workspace, bg=OLIVE_DEEP, height=112)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="PipelineGuard", bg=OLIVE_DEEP, fg=WHITE,
                 font=("Segoe UI", 30, "bold")).pack(anchor="w", padx=28, pady=(20, 0))
        tk.Label(header, text="Secure every build before it reaches production.",
                 bg=OLIVE_DEEP, fg=OLIVE_LIGHT, font=("Segoe UI", 11)).pack(anchor="w", padx=31)
        ttk.Button(header, text="About", command=self.show_about).place(relx=1.0, x=-28, y=32, anchor="e")

    def show_about(self):
        window = tk.Toplevel(self.root)
        window.title("About PipelineGuard")
        window.geometry("440x300")
        window.resizable(False, False)
        window.configure(bg=CANVAS)
        self._label(window, "PipelineGuard", 22, OLIVE_LIGHT, True).pack(pady=(28, 4))
        self._label(window, "DevSecOps security scanner", 11, MUTED, bg=CANVAS).pack()
        text = (
            "Version 1.0.0\\n\\n"
            "Scan projects for exposed secrets, dependency issues, "
            "and release-blocking security findings.\\n\\n"
            "Desktop · Docker · JSON · HTML · SARIF · OSV"
        )
        self._label(window, text, 10, INK, bg=CANVAS, justify="center", wraplength=360).pack(pady=24)
        ttk.Button(window, text="Close", command=window.destroy).pack()

    def _build_controls(self):
        card = tk.Frame(self.workspace, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=24, pady=(18, 10))
        self.folder = tk.StringVar()
        try:
            if self.preferences_file.exists():
                self.folder.set(json.loads(self.preferences_file.read_text(encoding="utf-8")).get("last_project", ""))
        except Exception:
            pass
        self.config = tk.StringVar()
        try:
            if self.preferences_file.exists():
                self.config.set(json.loads(self.preferences_file.read_text(encoding="utf-8")).get("last_config", ""))
        except Exception:
            pass
        self.online = tk.BooleanVar(value=True)
        self.scan_profile = tk.StringVar(value="Standard")

        self._label(card, "PROJECT FOLDER", 9, MUTED, True, bg=CARD).grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 4))
        folder_entry = tk.Frame(card, bg=CARD)
        folder_entry.grid(row=1, column=0, sticky="ew", padx=(16, 8), pady=(0, 14))
        ttk.Entry(folder_entry, textvariable=self.folder, font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True)
        ttk.Button(folder_entry, text="×", width=3, command=lambda: self.folder.set("")).pack(side="left", padx=(4, 0))
        ttk.Button(card, text="Choose project", command=self.choose).grid(
            row=1, column=1, padx=(0, 16), pady=(0, 14))

        config_heading = tk.Frame(card, bg=CARD)
        config_heading.grid(row=2, column=0, sticky="w", padx=16, pady=(4, 4))
        self._label(config_heading, "CONFIGURATION (OPTIONAL)", 9, MUTED, True, bg=CARD).pack(side="left")
        ttk.Button(config_heading, text="?", width=3, command=self.show_config_help).pack(side="left", padx=(10, 0))
        config_entry = tk.Frame(card, bg=CARD)
        config_entry.grid(row=3, column=0, sticky="ew", padx=(16, 8), pady=(0, 14))
        ttk.Entry(config_entry, textvariable=self.config, font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True)
        ttk.Button(config_entry, text="×", width=3, command=lambda: self.config.set("")).pack(side="left", padx=(4, 0))
        ttk.Button(card, text="Choose config", command=self.choose_config).grid(
            row=3, column=1, padx=(0, 16), pady=(0, 14))

        options = tk.Frame(card, bg=CARD)
        options.grid(row=4, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 14))
        tk.Label(options, text="Scan profile:", bg=CARD, fg=INK,
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 6))
        ttk.Combobox(options, textvariable=self.scan_profile, state="readonly", width=11,
                     values=("Quick", "Standard", "Deep", "Release", "Forensic")).pack(side="left", padx=(0, 14))
        tk.Checkbutton(options, text="Enable live OSV vulnerability lookup",
                       variable=self.online, bg=CARD, fg=INK, activebackground=CARD,
                       activeforeground=INK, selectcolor=OLIVE_DARK,
                       font=("Segoe UI", 10)).pack(side="left")
        self.scan_button = ttk.Button(options, text="Scan project", command=self.scan)
        self.scan_button.pack(side="right")
        ttk.Button(options, text="Export report", command=self.export).pack(side="right", padx=(0, 8))
        ttk.Button(options, text="Open report folder", command=self.open_report_folder).pack(side="right", padx=(0, 8))
        ttk.Button(options, text="Scan history", command=self.show_history).pack(side="right", padx=(0, 8))
        card.columnconfigure(0, weight=1)

    def _metric(self, parent, title, value="—", color=INK):
        box = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        box.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(box, text=title.upper(), bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        label = tk.Label(box, text=value, bg=CARD, fg=color,
                         font=("Segoe UI", 20, "bold"))
        label.pack(anchor="w", padx=16, pady=(0, 12))
        return label

    def _build_dashboard(self):
        row = tk.Frame(self.workspace, bg=CANVAS)
        row.pack(fill="x", padx=24, pady=(0, 12))
        self.status_value = self._metric(row, "Status", "READY", OLIVE_MID)
        self.score_value = self._metric(row, "Security score", "—")
        self.findings_value = self._metric(row, "Findings", "—")
        self.critical_value = self._metric(row, "Critical", "—", BLOCKED)
        self.warning_value = self._metric(row, "Warnings", "—", WARNING)
        self.dependency_value = self._metric(row, "Dependency lookup", "—")
        self.duration_value = self._metric(row, "Scan duration", "—")
        self.status = tk.StringVar(value="Ready — choose a project folder to begin")
        self.status_label = self._label(self.workspace, self.status.get(), 10, MUTED)
        self.status_label.pack(anchor="w", padx=28, pady=(0, 6))
        self.progress = ttk.Progressbar(self.workspace, mode="indeterminate",
                                        style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=24, pady=(0, 4))
        self.cache_status = self._label(self.workspace, "Cache: —", 9, MUTED)
        self.cache_status.pack(anchor="w", padx=28, pady=(0, 10))

    def _build_analytics(self):
        """Real scan-history summary, without fabricated trend data."""
        panel = tk.Frame(self.workspace, bg=CANVAS)
        panel.pack(fill="x", padx=24, pady=(0, 12))
        history_card = tk.Frame(panel, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        history_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self._label(history_card, "RECENT SCANS", 10, OLIVE_LIGHT, True, bg=CARD).pack(
            anchor="w", padx=14, pady=(10, 4))
        self.recent_scans_text = self._label(history_card, "No completed scans yet.", 10, INK,
                                            bg=CARD, justify="left", anchor="nw")
        self.recent_scans_text.pack(fill="x", padx=14, pady=(0, 12))
        insight_card = tk.Frame(panel, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        insight_card.pack(side="left", fill="both", expand=True)
        self._label(insight_card, "SCAN INSIGHTS", 10, OLIVE_LIGHT, True, bg=CARD).pack(
            anchor="w", padx=14, pady=(10, 4))
        self.scan_insights_text = self._label(insight_card, "Run a scan to see security insights.",
                                             10, INK, bg=CARD, justify="left", anchor="nw")
        self.scan_insights_text.pack(fill="x", padx=14, pady=(0, 12))
        self._refresh_analytics()

    def _refresh_analytics(self, report=None):
        try:
            entries = json.loads(self.history_file.read_text(encoding="utf-8")) if self.history_file.exists() else []
            if not isinstance(entries, list):
                entries = []
            lines = []
            for item in reversed(entries[-3:]):
                if not isinstance(item, dict):
                    continue
                name = Path(str(item.get("project", ""))).name or "Unknown project"
                lines.append(f"{name[:28]}  |  {item.get('status', '?')}  |  {item.get('findings', '?')} findings")
            self.recent_scans_text.configure(text="\\n".join(lines) if lines else "No completed scans yet.")
        except (OSError, ValueError, TypeError):
            self.recent_scans_text.configure(text="Scan history unavailable.")
        if hasattr(self, "trend_chart"):
            self._draw_charts()
        if report is not None:
            summary = report.get("summary", {})
            cache = report.get("secret_cache") or {}
            self.scan_insights_text.configure(
                text=(f"Critical: {summary.get('critical', 0)}  |  Warnings: {summary.get('warnings', 0)}\\n"
                      f"Secret files scanned: {cache.get('scanned', '—')}  |  Reused: {cache.get('reused', '—')}"))

    def _build_charts(self):
        """Canvas charts based exclusively on persisted scans and actual findings."""
        row = tk.Frame(self.workspace, bg=CANVAS)
        row.pack(fill="x", padx=24, pady=(0, 10))
        for title, name in (("FINDINGS TREND · LAST 10 SCANS", "trend_chart"),
                            ("FINDINGS BY SEVERITY", "severity_chart")):
            card = tk.Frame(row, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            self._label(card, title, 9, OLIVE_LIGHT, True, bg=CARD).pack(
                anchor="w", padx=12, pady=(8, 2))
            canvas = tk.Canvas(card, bg=CARD, height=95, highlightthickness=0)
            canvas.pack(fill="x", padx=10, pady=(0, 6))
            setattr(self, name, canvas)
            canvas.bind("<Configure>", lambda _event: self._draw_charts())
        self._draw_charts()

    def _draw_charts(self):
        if not hasattr(self, "trend_chart"):
            return
        trend = self.trend_chart
        trend.delete("all")
        width = max(trend.winfo_width(), 200)
        try:
            history = json.loads(self.history_file.read_text(encoding="utf-8")) if self.history_file.exists() else []
            values = [max(0, int(entry["findings"])) for entry in history[-10:]
                      if isinstance(entry, dict) and str(entry.get("findings", "")).isdigit()]
        except (OSError, ValueError, TypeError):
            values = []
        if not values:
            trend.create_text(12, 44, anchor="w", text="No historical scan data yet", fill=MUTED)
        else:
            peak = max(max(values), 1)
            points = []
            for index, count in enumerate(values):
                x = 20 + index * (width - 42) / max(len(values) - 1, 1)
                y = 72 - (count / peak) * 52
                points.extend((x, y))
                trend.create_oval(x - 3, y - 3, x + 3, y + 3, fill=OLIVE, outline=OLIVE)
            if len(points) >= 4:
                trend.create_line(*points, fill=OLIVE_LIGHT, width=2)
            trend.create_text(12, 84, anchor="w", text=f"{len(values)} scans  ·  latest: {values[-1]} findings",
                              fill=MUTED, font=("Segoe UI", 9))
        severity = self.severity_chart
        severity.delete("all")
        if self.report is None:
            severity.create_text(12, 44, anchor="w", text="Scan a project to see severity distribution", fill=MUTED)
            return
        findings = self.report.get("findings", [])
        counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "OTHER": 0}
        for item in findings:
            level = str(item.get("severity", "")).upper()
            counts[level if level in counts else "OTHER"] += 1
        total = max(sum(counts.values()), 1)
        colors = {"CRITICAL": BLOCKED, "HIGH": "#E28B59", "WARNING": WARNING, "OTHER": OLIVE}
        x = 12
        available = max(width - 28, 1)
        for level, count in counts.items():
            if count:
                segment = available * count / total
                severity.create_rectangle(x, 14, x + segment, 32, fill=colors[level], outline="")
                x += segment
        severity.create_text(12, 57, anchor="w", fill=INK,
                             text="  ·  ".join(f"{key.title()}: {value}" for key, value in counts.items() if value),
                             font=("Segoe UI", 9))
        if not findings:
            severity.create_text(12, 57, anchor="w", text="No findings detected", fill=SAFE)

    def _build_findings(self):
        self._label(self.workspace, "Security findings", 15, OLIVE_LIGHT, True).pack(
            anchor="w", padx=28, pady=(0, 8))
        search_bar = tk.Frame(self.workspace, bg=CANVAS)
        search_bar.pack(fill="x", padx=24, pady=(0, 8))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.refresh_findings())
        self.severity_filter = tk.StringVar(value="All severities")
        self.severity_filter.trace_add("write", lambda *_: self.refresh_findings())
        tk.Label(search_bar, text="Filter findings:", bg=CANVAS, fg=MUTED,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        search_input = tk.Frame(search_bar, bg=CANVAS)
        search_input.pack(side="left", padx=(8, 12))
        ttk.Entry(search_input, textvariable=self.search, width=38).pack(side="left")
        ttk.Button(search_input, text="×", width=3, command=lambda: self.search.set("")).pack(side="left", padx=(4, 0))
        ttk.Combobox(search_bar, textvariable=self.severity_filter, state="readonly", width=18,
                     values=("All severities", "CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW", "INFO")).pack(side="left")
        ttk.Button(search_bar, text="Clear filters", command=self.clear_filters).pack(side="left", padx=(8, 0))
        wrap = tk.Frame(self.workspace, bg=CANVAS)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        table_card = tk.Frame(wrap, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        table_card.pack(side="left", fill="both", expand=True)
        self.tree = ttk.Treeview(table_card, columns=("severity", "rule", "location"),
                                 show="headings")
        for column, width in (("severity", 110), ("rule", 240), ("location", 360)):
            self.tree.heading(column, text=column.title())
            self.tree.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.tree.tag_configure("critical", foreground=BLOCKED)
        self.tree.tag_configure("high", foreground=BLOCKED)
        self.tree.tag_configure("warning", foreground=WARNING)
        self.tree.tag_configure("medium", foreground=WARNING)
        self.tree.tag_configure("low", foreground=SAFE)
        self.tree.tag_configure("info", foreground=MUTED)
        self.tree.bind("<<TreeviewSelect>>", self.details)

        detail_card = tk.Frame(wrap, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        detail_card.pack(side="right", fill="both", padx=(14, 0))
        self._label(detail_card, "Finding details", 11, OLIVE_LIGHT, True, bg=CARD).pack(
            anchor="w", padx=14, pady=(12, 5))
        self.detail = tk.Text(detail_card, width=38, height=12, wrap="word",
                              bg=CARD, fg=INK, relief="flat", borderwidth=0,
                              font=("Consolas", 9), padx=14, pady=8)
        self.detail.pack(fill="both", expand=True)
        ttk.Button(detail_card, text="Copy finding details", command=self.copy_details).pack(anchor="e", padx=14, pady=(0, 12))
        self.detail.insert("end", "Select a finding to inspect its details.")
        self.detail.configure(state="disabled")

    def choose(self):
        value = filedialog.askdirectory(title="Choose a project folder")
        if value:
            self.folder.set(value)

    def show_config_help(self):
        """Explain every accepted JSON configuration key without changing scan settings."""
        window = tk.Toplevel(self.root)
        window.title("PipelineGuard — Configuration help")
        window.geometry("820x650")
        window.minsize(620, 420)
        window.configure(bg=CANVAS)
        self._label(window, "Configuration file guide", 18, OLIVE_LIGHT, True).pack(
            anchor="w", padx=20, pady=(18, 6))
        self._label(window, "Optional JSON file. Leave blank for default settings.", 10, MUTED).pack(
            anchor="w", padx=20, pady=(0, 12))
        body = tk.Frame(window, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        scroll = ttk.Scrollbar(body, orient="vertical")
        help_text = tk.Text(body, wrap="word", bg=CARD, fg=INK, relief="flat",
                            font=("Consolas", 10), padx=14, pady=12,
                            yscrollcommand=scroll.set)
        scroll.configure(command=help_text.yview)
        scroll.pack(side="right", fill="y")
        help_text.pack(side="left", fill="both", expand=True)
        instructions = (
            "HOW TO USE\n"
            "1. Create a .json file (for example .pipelineguard.json).\n"
            "2. Copy the example below and customize it.\n"
            "3. Click 'Choose config' and select your JSON file.\n"
            "4. Scan your project. Leave the field empty for defaults.\n\n"
            "ALL SUPPORTED SETTINGS (exact JSON keys)\n\n"
            "ignored_directories  [strings]  Default: .git, .venv, venv,\n"
            "  node_modules, __pycache__, .pytest_cache. Replaces defaults.\n\n"
            "max_file_size  integer  Default: 1000000 bytes. Must be > 0.\n"
            "  Maximum file size for secret scanning.\n\n"
            "fail_on_warning  boolean  Default: false.\n"
            "  Block release on WARNING, including incomplete checks.\n\n"
            "allowlist  [objects]  Default: [].\n"
            "  Each entry: rule (exact name), file (path glob), optional\n"
            "  line (positive integer). Suppresses matching findings.\n"
            "  Only allowlist verified false positives.\n\n"
            "minimum_score  integer  Default: 0. Range: 0..100.\n"
            "  Block release if the score is below this number.\n\n"
            "blocked_rules  [strings]  Default: [].\n"
            "  Exact finding rule names that block release.\n\n"
            "block_advisory_severity  string or null  Default: null.\n"
            "  LOW, MODERATE, HIGH, CRITICAL or null (disabled).\n"
            "  Blocks known dependency advisories at/above threshold.\n\n"
            "EXAMPLE (edit as needed)\n"
            '{\n  "ignored_directories": [".git", ".venv", "venv",\n'
            '    "node_modules", "__pycache__", ".pytest_cache"],\n'
            '  "max_file_size": 1000000,\n'
            '  "fail_on_warning": false,\n'
            '  "allowlist": [],\n'
            '  "minimum_score": 70,\n'
            '  "blocked_rules": ["Generic secret assignment"],\n'
            '  "block_advisory_severity": "HIGH"\n}\n\n'
            "JSON uses double quotes, true/false/null (lowercase), and\n"
            "does not support comments or trailing commas. Unknown keys\n"
            "and invalid values are rejected. Configuration files are\n"
            "not automatically loaded from the project folder.\n\n"
            "Full guide: docs/CONFIGURATION.md in the GitHub repository.\n"
        )
        help_text.insert("1.0", instructions)
        help_text.configure(state="disabled")
        footer = tk.Frame(window, bg=CANVAS)
        footer.pack(fill="x", padx=20, pady=(0, 16))
        ttk.Button(footer, text="Copy example", command=lambda: self._copy_config_example()).pack(side="left")
        ttk.Button(footer, text="Close", command=window.destroy).pack(side="right")

    def _copy_config_example(self):
        example = {
            "ignored_directories": [".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"],
            "max_file_size": 1000000,
            "fail_on_warning": False,
            "allowlist": [],
            "minimum_score": 70,
            "blocked_rules": ["Generic secret assignment"],
            "block_advisory_severity": "HIGH",
        }
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(example, indent=2) + "\\n")
        self.root.update()
        messagebox.showinfo("PipelineGuard", "Example JSON copied. Paste into a .json file and select it.")

    def choose_config(self):
        value = filedialog.askopenfilename(
            title="Choose PipelineGuard configuration",
            filetypes=[("JSON configuration", "*.json")])
        if value:
            self.config.set(value)

    def scan(self):
        if not self.folder.get() or not Path(self.folder.get()).is_dir():
            messagebox.showerror("PipelineGuard", "Choose an existing project folder.")
            return
        self.scan_button.state(["disabled"])
        try:
            self.preferences_file.parent.mkdir(parents=True, exist_ok=True)
            self.preferences_file.write_text(json.dumps({"last_project": self.folder.get(), "last_config": self.config.get()}), encoding="utf-8")
        except Exception:
            pass
        self.scan_started = time.perf_counter()
        self.report = None
        self.tree.delete(*self.tree.get_children())
        self.all_findings = []
        self.findings_value.configure(text="0", fg=OLIVE_MID)
        self.status.set("Scanning project…")
        self.status_label.configure(text=self.status.get(), fg=OLIVE_MID)
        self.status_value.configure(text="SCANNING", fg=OLIVE_MID)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "PipelineGuard is analyzing the selected project.")
        self.detail.configure(state="disabled")
        self.cache_status.configure(text="Cache: scanning…")
        self.progress.start(12)

        project_path = Path(self.folder.get())
        config_path = Path(self.config.get()) if self.config.get() else None
        online_enabled = self.online.get()
        selected_profile = self.scan_profile.get().lower()

        def worker():
            try:
                result = run_scan(project_path, config_path, online_enabled,
                                  profile=selected_profile,
                                  progress=lambda event: self.events.put(("progress", event)),
                                  on_finding=lambda finding: self.events.put(("finding", finding)))
                self.events.put(("result", result))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _process_scan_event(self, kind, value):
        if kind == "progress":
            labels = {
                "fingerprint": "Fingerprinting files",
                "fingerprint-complete": "Fingerprinting complete",
                "fingerprint-unavailable": "Fingerprint cache unavailable; continuing",
                "dependencies": "Scanning dependencies",
                "vulnerability-intelligence": "Checking vulnerability intelligence",
                "secrets": "Scanning for secrets",
                "secrets-complete": "Secret scanning complete",
                "complete": "Finishing scan",
            }
            stage = labels.get(value.stage, value.stage)
            if value.stage.startswith("fingerprint") and value.discovered is not None:
                stage += f" · {value.processed or 0}/{value.discovered} files · {value.cached} cached"
            self.status_label.configure(text=stage, fg=OLIVE_MID)
            return False
        if kind == "finding":
            self.all_findings.append(value)
            self.findings_value.configure(text=str(len(self.all_findings)), fg=OLIVE_MID)
            return True
        self.scan_button.state(["!disabled"])
        self.progress.stop()
        if kind == "error":
            self.status.set("Scan failed")
            self.status_label.configure(text=value, fg=BLOCKED)
            self.status_value.configure(text="ERROR", fg=BLOCKED)
            messagebox.showerror("Scan failed", value)
        else:
            self.report = value
            metrics = value.get("secret_cache")
            if metrics:
                scanned = metrics.get("scanned")
                count = "unknown" if scanned is None else str(scanned)
                self.cache_status.configure(text=f"Secret scan: {metrics.get('strategy', 'unknown')} · "
                                                 f"{count} scanned · {metrics.get('reused', 0)} reused")
            else:
                self.cache_status.configure(text="Secret scan: full (cache metrics unavailable for this profile)")
            self.all_findings = value["findings"]
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("end", "Select a finding to inspect its details.")
            self.detail.configure(state="disabled")
            self.save_history(value)
            self._refresh_analytics(value)
            elapsed = time.perf_counter() - (self.scan_started or time.perf_counter())
            self.duration_value.configure(text=f"{elapsed:.1f}s", fg=OLIVE_MID)
            status = value["status"]
            color = SAFE if status == "SAFE" else WARNING if status == "WARNING" else BLOCKED
            self.status.set(f"{status} · {len(value['findings'])} findings · "
                            f"Dependency lookup {'complete' if value['dependency_check_complete'] else 'incomplete'}")
            self.status_label.configure(text=self.status.get(), fg=color)
            self.status_value.configure(text=status, fg=color)
            self.score_value.configure(text=f"{value['score']}/100", fg=color)
            self.findings_value.configure(text=str(len(value["findings"])), fg=color)
            self.critical_value.configure(text=str(value["summary"]["critical"]), fg=BLOCKED)
            self.warning_value.configure(text=str(value["summary"]["warnings"]), fg=WARNING)
            self.dependency_value.configure(
                text="COMPLETE" if value["dependency_check_complete"] else "INCOMPLETE",
                fg=SAFE if value["dependency_check_complete"] else WARNING)
            self.refresh_findings()
            self._draw_charts()
    return False
    def poll(self):
        """Drain bounded batches so busy scans do not backlog the Tk event loop."""
        pending_findings = False
        try:
            for _ in range(200):
                try:
                    kind, value = self.events.get_nowait()
                except queue.Empty:
                    break
                if kind != "finding" and pending_findings:
                    self.findings_value.configure(text=str(len(self.all_findings)), fg=OLIVE_MID)
                    self.refresh_findings()
                    pending_findings = False
                pending_findings = self._process_scan_event(kind, value) or pending_findings
            if pending_findings:
                self.findings_value.configure(text=str(len(self.all_findings)), fg=OLIVE_MID)
                self.refresh_findings()
        finally:
            self.root.after(100, self.poll)

    def clear_filters(self):
        self.search.set("")
        self.severity_filter.set("All severities")

    def refresh_findings(self):
        if not hasattr(self, "tree"):
            return
        query = self.search.get().strip().lower() if hasattr(self, "search") else ""
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.all_findings):
            haystack = " ".join(str(item.get(key, "")) for key in ("severity", "rule", "file", "package", "summary")).lower()
            selected_severity = self.severity_filter.get() if hasattr(self, "severity_filter") else "All severities"
            if query and query not in haystack:
                continue
            if selected_severity != "All severities" and str(item.get("severity", "")).upper() != selected_severity:
                continue
            self.tree.insert("", "end", iid=str(index), values=(
                item.get("severity", ""), item.get("rule", ""),
                item.get("file", item.get("package", "dependencies")),),
                tags=(str(item.get("severity", "info")).lower(),))

    def details(self, event=None):
        selected = self.tree.selection()
        if selected:
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            index = int(selected[0])
            if index >= len(self.all_findings):
                return
            finding = self.all_findings[index]
            readable = (
                f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
                f"Rule: {finding.get('rule', 'Security finding')}\n"
                f"Location: {finding.get('file', finding.get('package', 'N/A'))}\n\n"
                f"Summary\n{finding.get('summary', 'No summary available.')}\n\n"
                f"Remediation\n{finding.get('remediation', 'Review this finding and remove or secure the affected value.')}\n\n"
                f"Technical details\n{json.dumps(finding, indent=2)}"
            )
            self.detail.insert("end", readable)
            self.detail.configure(state="disabled")

    def save_history(self, report):
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            history = []
            if self.history_file.exists():
                history = json.loads(self.history_file.read_text(encoding="utf-8"))
            history.append({
                "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                "project": self.folder.get(),
                "status": report["status"],
                "score": report["score"],
                "findings": len(report["findings"]),
            })
            self.history_file.write_text(json.dumps(history[-25:], indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass

    def show_history(self):
        window = tk.Toplevel(self.root)
        window.title("PipelineGuard — Scan history")
        window.geometry("760x420")
        window.configure(bg=CANVAS)
        self._label(window, "Recent scans", 16, OLIVE_LIGHT, True).pack(anchor="w", padx=18, pady=14)
        box = tk.Text(window, bg=CARD, fg=INK, relief="flat", font=("Consolas", 10), padx=12, pady=12)
        box.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        try:
            history = json.loads(self.history_file.read_text(encoding="utf-8")) if self.history_file.exists() else []
            if history:
                for item in reversed(history):
                    box.insert("end", f"{item['timestamp']} | {item['status']:<7} | Score {item['score']:>3}/100 | {item['findings']} findings | {item['project']}\n")
            else:
                box.insert("end", "No completed scans yet.")
        except Exception as exc:
            box.insert("end", f"Could not read scan history: {exc}")
        box.configure(state="disabled")
        ttk.Button(window, text="Clear history", command=lambda: self.clear_history(window)).pack(pady=(0, 14))

    def clear_history(self, window=None):
        try:
            if self.history_file.exists():
                self.history_file.unlink()
            if window and window.winfo_exists():
                window.destroy()
            self._refresh_analytics()
            messagebox.showinfo("PipelineGuard", "Scan history cleared.")
        except Exception as exc:
            messagebox.showerror("PipelineGuard", f"Could not clear history: {exc}")

    def open_report_folder(self):

        if not self.last_export:
            messagebox.showinfo("PipelineGuard", "Export a report first.")
            return
        folder = str(Path(self.last_export).parent)
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as exc:
            messagebox.showerror("PipelineGuard", f"Could not open folder: {exc}")

    def copy_details(self):
        selected = self.tree.selection()
        if not selected or not self.report:
            messagebox.showinfo("PipelineGuard", "Select a finding first.")
            return
        details = json.dumps(self.report["findings"][int(selected[0])], indent=2)
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        self.root.update()
        messagebox.showinfo("PipelineGuard", "Finding details copied to the clipboard.")

    def export(self):
        if self.report is None:
            messagebox.showinfo("PipelineGuard", "Complete a scan first.")
            return
        value = filedialog.asksaveasfilename(
            title="Export PipelineGuard report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("JSON report", "*.json"),
                       ("SARIF report", "*.sarif")])
        if value:
            try:
                output = Path(value)
                writer = {".html": write_html_report, ".json": write_json_report,
                          ".sarif": write_sarif_report}.get(output.suffix.lower())
                if writer is None:
                    raise ValueError("Choose HTML, JSON, or SARIF")
                writer(self.report, output)
                self.last_export = str(output)
                messagebox.showinfo("PipelineGuard", "Report exported successfully.")
            except Exception as exc:
                messagebox.showerror("Export failed", str(exc))


def main():
    root = tk.Tk()
    Desktop(root)
    root.mainloop()


if __name__ == "__main__":
    main()
