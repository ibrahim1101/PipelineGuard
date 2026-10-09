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
import tkinter.font
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from pipelineguard.brand_asset import load_cat_logo
from pipelineguard.engine import run_scan
from pipelineguard.reporting import write_json_report, write_html_report, write_sarif_report
from pipelineguard.soc_inspector import finding_group, safe_finding_details, masked_code_preview
from pipelineguard.soc_finding_panel import FindingInspector
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
        style.configure("TNotebook", background=CANVAS, borderwidth=0)
        style.configure("TNotebook.Tab", background=OLIVE_DARK, foreground=INK,
                        font=("Segoe UI", 10, "bold"), padding=(18, 9))
        style.map("TNotebook.Tab", background=[("selected", OLIVE_MID)],
                  foreground=[("selected", WHITE)])
        style.configure("Treeview.Heading", background=OLIVE_DARK, foreground=WHITE,
                        font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Treeview", background=[("selected", OLIVE_DARK)], foreground=[("selected", WHITE)])
        style.configure("TEntry", fieldbackground=CARD, foreground=INK, insertcolor=INK)
        style.configure("TCombobox", fieldbackground=CARD, foreground=INK, background=OLIVE_DARK)
        style.map("TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", INK)])
        style.configure("Horizontal.TProgressbar", troughcolor=BORDER, background=OLIVE,
                        bordercolor=CANVAS, lightcolor=OLIVE, darkcolor=OLIVE)

        self.brand_font = "Bahnschrift" if "Bahnschrift" in tkinter.font.families(root) else "Segoe UI"
        self.cat_logo = load_cat_logo(root)
        self._build_shell()
        self._build_controls()
        self._build_header()
        self._build_dashboard()
        self._build_analytics()
        self._build_charts()
        self._build_findings()
        self._setup_page_navigation()
        self.root.after(100, self.poll)

    def _build_shell(self):
        """SOC navigation shell; existing scanner widgets remain intact."""
        self.content_frame = tk.Frame(self.root, bg=CANVAS)
        self.content_frame.pack(fill="both", expand=True)
        self.sidebar = tk.Frame(self.content_frame, bg=OLIVE_DEEP, width=174)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self.workspace_container = tk.Frame(self.content_frame, bg=CANVAS)
        self.workspace_container.pack(side="left", fill="both", expand=True)
        self.workspace_canvas = tk.Canvas(self.workspace_container, bg=CANVAS,
                                          highlightthickness=0, borderwidth=0)
        self.workspace_scrollbar = ttk.Scrollbar(self.workspace_container, orient="vertical",
                                                  command=self.workspace_canvas.yview)
        self.workspace_canvas.configure(yscrollcommand=self.workspace_scrollbar.set)
        self.workspace_scrollbar.pack(side="right", fill="y")
        self.workspace_canvas.pack(side="left", fill="both", expand=True)
        self.workspace = tk.Frame(self.workspace_canvas, bg=CANVAS)
        self.workspace_window = self.workspace_canvas.create_window(
            (0, 0), window=self.workspace, anchor="nw")
        self.workspace.bind("<Configure>", self._update_workspace_scrollregion)
        self.workspace_canvas.bind("<Configure>", self._resize_workspace)
        self.root.bind_all("<MouseWheel>", self._scroll_workspace, add="+")
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
        self.nav_buttons = {}
        for label, callback in navigation:
            name = label.split("  ", 1)[-1]
            button = tk.Button(self.sidebar, text=label, command=callback, anchor="w",
                               bg=OLIVE_DEEP, fg=MUTED, activebackground=OLIVE_DARK,
                               activeforeground=WHITE, relief="flat", borderwidth=0,
                               font=("Segoe UI", 10), padx=14, pady=11)
            button.pack(fill="x", padx=7, pady=2)
            self.nav_buttons[name] = button
        tk.Button(self.sidebar, text="ⓘ  About", command=self.show_about,
                  anchor="w", bg=OLIVE_DEEP, fg=OLIVE_LIGHT, relief="flat",
                  borderwidth=0, padx=14, pady=12).pack(side="bottom", fill="x")

    def _update_workspace_scrollregion(self, _event=None):
        self.workspace_canvas.configure(scrollregion=self.workspace_canvas.bbox("all"))

    def _resize_workspace(self, event):
        self.workspace_canvas.itemconfigure(self.workspace_window, width=event.width)

    def _scroll_workspace(self, event):
        """Scroll the dashboard without hijacking findings or details scrolling."""
        target = self.root.winfo_containing(event.x_root, event.y_root)
        widget = target
        while widget is not None:
            if isinstance(widget, (ttk.Treeview, tk.Text, ttk.Combobox)):
                return
            if widget is self.workspace_canvas or widget is self.workspace:
                break
            widget = getattr(widget, "master", None)
        if widget is None:
            return
        if self.workspace.winfo_height() <= self.workspace_canvas.winfo_height():
            return
        if event.delta:
            self.workspace_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
            return "break"

    def _setup_page_navigation(self):
        """Separate existing dashboard and findings widgets without rebuilding scan state."""
        self._page_pack_options = {
            widget: dict(widget.pack_info())
            for widget in self.workspace.pack_slaves()
        }
        self._dashboard_widgets = []
        self._findings_widgets = []
        findings_started = False
        for widget in self.workspace.pack_slaves():
            if isinstance(widget, tk.Label) and widget.cget("text") == "Security findings":
                findings_started = True
            (self._findings_widgets if findings_started else self._dashboard_widgets).append(widget)
        self._navigate("Dashboard")

    def _navigate(self, destination):
        """Show one workspace at a time; preserve scanner widgets and scan results."""
        if destination == "Scan Project":
            self._navigate("Dashboard")
            self.header_scan_button.focus_set()
            return
        if destination == "Settings":
            for name, button in self.nav_buttons.items():
                active = name == "Settings"
                button.configure(bg=OLIVE_DARK if active else OLIVE_DEEP,
                                 fg=OLIVE_LIGHT if active else MUTED)
            self.show_settings()
            return
        if destination == "Reports":
            self.export()
            return
        if destination == "OSV Lookup":
            messagebox.showinfo("OSV Lookup", "Enable live OSV lookup in the scan options, then scan a project.")
            return
        if destination not in ("Dashboard", "Findings", "Dependencies"):
            return
        for name, button in self.nav_buttons.items():
            active = name == destination
            button.configure(bg=OLIVE_DARK if active else OLIVE_DEEP,
                             fg=OLIVE_LIGHT if active else MUTED)
        for widget in self._dashboard_widgets + self._findings_widgets:
            widget.pack_forget()
        widgets = self._dashboard_widgets if destination == "Dashboard" else self._findings_widgets
        for widget in widgets:
            widget.pack(**self._page_pack_options[widget])
        if destination == "Dependencies":
            self.finding_tabs.select(2)
        elif destination == "Findings":
            self.finding_tabs.select(0)
        self.workspace_canvas.yview_moveto(0)

    def _label(self, parent, text, size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", CANVAS), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def _build_header(self):
        """Reference-inspired compact command bar; keep approved cat branding."""
        header = tk.Frame(self.root, bg=OLIVE_DEEP, height=78)
        header.pack(side="top", fill="x", before=self.content_frame)
        header.pack_propagate(False)
        brand_row = tk.Frame(header, bg=OLIVE_DEEP)
        brand_row.pack(side="left", padx=(14, 24), pady=9)
        tk.Label(brand_row, image=self.cat_logo, bg=OLIVE_DEEP, borderwidth=0).pack(side="left")
        brand_title = tk.Frame(brand_row, bg=OLIVE_DEEP)
        brand_title.pack(side="left", padx=(9, 0))
        title_line = tk.Frame(brand_title, bg=OLIVE_DEEP)
        title_line.pack(anchor="w")
        tk.Label(title_line, text="Pipeline", bg=OLIVE_DEEP, fg=WHITE,
                 font=(self.brand_font, 22, "bold")).pack(side="left")
        tk.Label(title_line, text="Guard", bg=OLIVE_DEEP, fg=OLIVE_LIGHT,
                 font=(self.brand_font, 22, "bold")).pack(side="left")
        tk.Label(brand_title, text="Secure every build before it reaches production.",
                 bg=OLIVE_DEEP, fg=OLIVE_LIGHT,
                 font=("Segoe UI", 9)).pack(anchor="w")
        toolbar = tk.Frame(header, bg=OLIVE_DEEP)
        toolbar.pack(side="right", fill="y", padx=14, pady=17)
        self.header_scan_button = ttk.Button(toolbar, text="▶  Start Scan", command=self.scan)
        self.header_scan_button.pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="⚙", width=3, command=self.show_settings).pack(side="right", padx=(8, 0))
        self.header_profile = ttk.Combobox(toolbar, textvariable=self.scan_profile,
                                            state="readonly", width=12,
                                            values=("Quick", "Standard", "Deep", "Release", "Forensic"))
        self.header_profile.pack(side="right", padx=(6, 0))
        tk.Label(toolbar, text="Scan profile:", bg=OLIVE_DEEP, fg=INK,
                 font=("Segoe UI", 9)).pack(side="right")
        ttk.Button(toolbar, text="📁", width=3, command=self.choose).pack(side="right", padx=(6, 12))
        ttk.Entry(toolbar, textvariable=self.folder, width=36).pack(side="right")

    def show_about(self):
        """Dedicated development-version About dialog."""
        window = tk.Toplevel(self.root)
        window.title("PipelineGuard — About")
        window.geometry("480x340")
        window.resizable(False, False)
        window.configure(bg=CANVAS)
        brand = tk.Frame(window, bg=CANVAS)
        brand.pack(pady=(25, 10))
        tk.Label(brand, image=self.cat_logo, bg=CANVAS).pack(side="left", padx=(0, 10))
        title = tk.Frame(brand, bg=CANVAS)
        title.pack(side="left")
        self._label(title, "PipelineGuard", 22, OLIVE_LIGHT, True, bg=CANVAS).pack(anchor="w")
        self._label(title, "Secure every build before it reaches production.",
                    9, MUTED, bg=CANVAS).pack(anchor="w")
        info = tk.Frame(window, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        info.pack(fill="x", padx=38, pady=12)
        for label, value in (
            ("Version", "2.0.0 (unreleased development)"),
            ("License", "MIT License"),
            ("Platform", "Windows desktop / Python Tk"),
            ("Repository", "github.com/ibrahim1101/PipelineGuard"),
        ):
            row = tk.Frame(info, bg=CARD)
            row.pack(fill="x", padx=16, pady=7)
            self._label(row, label, 10, MUTED, bg=CARD).pack(side="left")
            self._label(row, value, 10, INK, bg=CARD).pack(side="right")
        ttk.Button(window, text="Close", command=window.destroy).pack(pady=(4, 10))

    def show_settings(self):
        """Settings dialog with live controls shared with the scan toolbar."""
        window = tk.Toplevel(self.root)
        window.title("PipelineGuard — Settings")
        window.geometry("720x475")
        window.minsize(620, 410)
        window.configure(bg=CANVAS)
        sidebar = tk.Frame(window, bg=OLIVE_DEEP, width=172)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        content = tk.Frame(window, bg=CANVAS)
        content.pack(side="left", fill="both", expand=True, padx=18, pady=18)
        heading = self._label(content, "General", 17, INK, True, bg=CANVAS)
        heading.pack(anchor="w", pady=(0, 15))
        panel = tk.Frame(content, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill="both", expand=True)

        def label(text):
            self._label(panel, text, 10, MUTED, bg=CARD).pack(
                anchor="w", padx=16, pady=(14, 4))

        def section(name):
            for child in panel.winfo_children():
                child.destroy()
            heading.configure(text=name)
            if name == "General":
                label("Default scan profile (also available in the quick scan bar)")
                ttk.Combobox(panel, textvariable=self.scan_profile, state="readonly",
                             values=("Quick", "Standard", "Deep", "Release", "Forensic"),
                             width=20).pack(anchor="w", padx=16)
                label("Project folder")
                ttk.Entry(panel, textvariable=self.folder).pack(fill="x", padx=16)
                ttk.Button(panel, text="Choose project", command=self.choose).pack(
                    anchor="w", padx=16, pady=10)
            elif name == "Scan Engine":
                label("Scan behavior")
                self._label(panel, "Scan profiles control depth and caching.",
                            10, INK, bg=CARD).pack(anchor="w", padx=16)
                ttk.Button(panel, text="Configuration help",
                           command=self.show_config_help).pack(anchor="w", padx=16, pady=12)
                ttk.Button(panel, text="Choose config file",
                           command=self.choose_config).pack(anchor="w", padx=16)
            elif name == "OSV Lookup":
                label("Vulnerability intelligence")
                tk.Checkbutton(panel, text="Enable live OSV vulnerability lookup",
                               variable=self.online, bg=CARD, fg=INK,
                               activebackground=CARD, activeforeground=INK,
                               selectcolor=OLIVE_DARK).pack(anchor="w", padx=16)
                self._label(panel, "Online requests use dependency names and versions.",
                            9, MUTED, bg=CARD).pack(anchor="w", padx=16, pady=8)
            elif name == "Reports":
                label("Export and scan history")
                ttk.Button(panel, text="Export latest report",
                           command=self.export).pack(anchor="w", padx=16, pady=8)
                ttk.Button(panel, text="Open reports folder",
                           command=self.open_report_folder).pack(anchor="w", padx=16)
            elif name == "Appearance":
                label("Active appearance")
                self._label(panel, "Premium Dark Titanium",
                            11, OLIVE_LIGHT, True, bg=CARD).pack(anchor="w", padx=16)
                self._label(panel, "Matte charcoal surfaces with restrained security-lime accents.",
                            9, MUTED, bg=CARD).pack(anchor="w", padx=16, pady=8)
            else:
                label("Application information")
                ttk.Button(panel, text="About PipelineGuard",
                           command=self.show_about).pack(anchor="w", padx=16, pady=8)

        for name in ("General", "Scan Engine", "OSV Lookup", "Reports", "Appearance", "About"):
            tk.Button(sidebar, text=name, command=lambda name=name: section(name),
                      anchor="w", bg=OLIVE_DEEP, fg=INK, activebackground=OLIVE_DARK,
                      activeforeground=WHITE, relief="flat", borderwidth=0,
                      font=("Segoe UI", 10), padx=14, pady=12).pack(fill="x", padx=8, pady=2)
        section("General")

    def _build_controls(self):
        """Initialize shared scan state; secondary actions live in a compact tools row."""
        self.folder = tk.StringVar()
        self.config = tk.StringVar()
        try:
            if self.preferences_file.exists():
                saved = json.loads(self.preferences_file.read_text(encoding="utf-8"))
                self.folder.set(saved.get("last_project", ""))
                self.config.set(saved.get("last_config", ""))
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        self.online = tk.BooleanVar(value=True)
        self.scan_profile = tk.StringVar(value="Standard")
        # Quick scan actions live exclusively in the persistent top command bar.
        # Keep this compatibility button for existing scan lifecycle updates.
        self.scan_button = ttk.Button(self.workspace, text="Scan project", command=self.scan)

    def _soc_card(self, parent, title, column, weight=1):
        """Reusable compact SOC card with the same spacing as the approved dashboard."""
        parent.grid_columnconfigure(column, weight=weight, minsize=135)
        card = tk.Frame(parent, bg=CARD, height=174, highlightbackground=BORDER,
                        highlightthickness=1)
        card.grid(row=0, column=column, sticky="nsew", padx=5)
        card.pack_propagate(False)
        self._label(card, title, 10, WHITE, True, bg=CARD).pack(
            anchor="w", padx=12, pady=(10, 4))
        return card

    def _build_dashboard(self):
        """Reference-inspired six-card summary using real scan state only."""
        row = tk.Frame(self.workspace, bg=CANVAS, height=184)
        row.pack(fill="x", padx=12, pady=(2, 8))
        row.pack_propagate(False)

        score_card = self._soc_card(row, "Security Score", 0, 6)
        self.score_gauge = tk.Canvas(score_card, bg=CARD, height=113,
                                     highlightthickness=0)
        self.score_gauge.pack(fill="both", expand=True, padx=8)
        self.score_value = self._label(score_card, "— /100", 20, INK, True, bg=CARD)
        self.score_value.place(relx=0.5, y=110, anchor="center")
        self.score_gauge.bind("<Configure>", lambda _event: self._draw_score_gauge())

        status_card = self._soc_card(row, "Scan Status", 1, 5)
        self.status_value = self._label(status_card, "READY", 18, OLIVE_LIGHT, True, bg=CARD)
        self.status_value.pack(anchor="w", padx=12, pady=(18, 6))
        self._label(status_card, "Security assessment", 9, MUTED, bg=CARD).pack(
            anchor="w", padx=12)
        ttk.Button(status_card, text="View findings →",
                   command=lambda: self._navigate("Findings")).pack(
            anchor="w", padx=12, pady=(12, 0))

        findings_card = self._soc_card(row, "Total Findings", 2, 5)
        self.findings_value = self._label(findings_card, "—", 30, INK, True, bg=CARD)
        self.findings_value.pack(anchor="w", padx=12, pady=(4, 1))
        counts = tk.Frame(findings_card, bg=CARD)
        counts.pack(anchor="w", padx=12)
        self._label(counts, "Critical  ", 9, BLOCKED, bg=CARD).grid(row=0, column=0, sticky="w")
        self.critical_value = self._label(counts, "—", 9, INK, True, bg=CARD)
        self.critical_value.grid(row=0, column=1, sticky="w")
        self._label(counts, "Warnings  ", 9, WARNING, bg=CARD).grid(row=1, column=0, sticky="w")
        self.warning_value = self._label(counts, "—", 9, INK, True, bg=CARD)
        self.warning_value.grid(row=1, column=1, sticky="w")

        duration_card = self._soc_card(row, "Scan Duration", 3, 4)
        self.duration_value = self._label(duration_card, "—", 25, INK, True, bg=CARD)
        self.duration_value.pack(anchor="w", padx=12, pady=(24, 8))
        self._label(duration_card, "Last completed scan", 9, MUTED, bg=CARD).pack(
            anchor="w", padx=12)

        issue_card = self._soc_card(row, "Top Issue Types", 4, 6)
        self.issue_labels = []
        for _ in range(5):
            label = self._label(issue_card, "", 9, INK, bg=CARD, anchor="w")
            label.pack(fill="x", padx=12, pady=(3, 1))
            self.issue_labels.append(label)
        self.issue_labels[0].configure(text="Run a scan to see issues", fg=MUTED)

        history_card = self._soc_card(row, "Recent Scans", 5, 7)
        self.recent_scans_text = self._label(
            history_card, "No completed scans yet.", 9, INK,
            bg=CARD, justify="left", anchor="nw")
        self.recent_scans_text.pack(fill="x", padx=12, pady=(4, 4))
        self.status = tk.StringVar(value="Ready — choose a project folder to begin")
        self.status_label = self._label(self.workspace, self.status.get(), 9, MUTED)
        self.status_label.pack(anchor="w", padx=18, pady=(0, 5))
        self.progress = ttk.Progressbar(self.workspace, mode="determinate",
                                        value=0, maximum=100,
                                        style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=17, pady=(0, 4))
        self.cache_status = self._label(self.workspace, "Cache: —", 9, MUTED)
        self.cache_status.pack(anchor="w", padx=18, pady=(0, 8))

    def _build_analytics(self):
        """Four-card analytics row with no synthetic scan counts or events."""
        row = tk.Frame(self.workspace, bg=CANVAS, height=196)
        row.pack(fill="x", padx=12, pady=(0, 10))
        row.pack_propagate(False)
        for col, weight in enumerate((5, 6, 5, 5)):
            row.grid_columnconfigure(col, weight=weight, minsize=190)

        severity_card = self._soc_card(row, "Findings by Severity", 0, 5)
        self.severity_chart = tk.Canvas(severity_card, bg=CARD, height=125,
                                        highlightthickness=0)
        self.severity_chart.pack(fill="both", expand=True, padx=9, pady=(0, 5))
        self.severity_chart.bind("<Configure>", lambda _event: self._draw_charts())

        trend_card = self._soc_card(row, "Findings Trend · Last 10 Scans", 1, 6)
        self.trend_chart = tk.Canvas(trend_card, bg=CARD, height=125,
                                     highlightthickness=0)
        self.trend_chart.pack(fill="both", expand=True, padx=9, pady=(0, 5))
        self.trend_chart.bind("<Configure>", lambda _event: self._draw_charts())

        activity_card = self._soc_card(row, "Scan Activity", 2, 5)
        self._activity_events = []
        self.scan_activity_text = self._label(
            activity_card, "No scan activity yet.", 9, MUTED,
            bg=CARD, justify="left", anchor="nw")
        self.scan_activity_text.pack(fill="x", padx=12, pady=(8, 0))

        system_card = self._soc_card(row, "System Overview", 3, 5)
        self._label(system_card, "Dependency lookup", 9, MUTED, bg=CARD).pack(
            anchor="w", padx=12, pady=(7, 2))
        self.dependency_value = self._label(system_card, "—", 10, INK, True, bg=CARD)
        self.dependency_value.pack(anchor="w", padx=12)
        self.scan_insights_text = self._label(
            system_card, "Run a scan to see statistics.", 9, MUTED,
            bg=CARD, justify="left", anchor="nw")
        self.scan_insights_text.pack(fill="x", padx=12, pady=(8, 0))
        self._refresh_analytics()

    def _record_activity(self, label):
        """Only display events that were actually observed in this session."""
        self._activity_events.append(
            f"{datetime.now().strftime('%H:%M:%S')}  {label}")
        self._activity_events = self._activity_events[-5:]
        self.scan_activity_text.configure(
            text="\n".join(self._activity_events), fg=INK)

    def _refresh_issue_types(self, report):
        counts = {}
        if report is not None:
            for item in report.get("findings", []):
                rule = str(item.get("rule") or "Unclassified finding")
                counts[rule] = counts.get(rule, 0) + 1
        sorted_rules = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
        for index, label in enumerate(self.issue_labels):
            if index < len(sorted_rules):
                rule, count = sorted_rules[index]
                label.configure(text=f"{rule[:27]}  ·  {count}", fg=INK)
            elif index == 0:
                label.configure(text="No findings" if report is not None else
                                "Run a scan to see issues", fg=SAFE if report is not None else MUTED)
            else:
                label.configure(text="")

    def _refresh_analytics(self, report=None):
        try:
            entries = json.loads(self.history_file.read_text(encoding="utf-8")) if self.history_file.exists() else []
            if not isinstance(entries, list):
                entries = []
            lines = []
            for item in reversed(entries[-5:]):
                if not isinstance(item, dict):
                    continue
                name = Path(str(item.get("project", ""))).name or "Unknown project"
                lines.append(
                    f"{name[:19]} · {item.get('status', '?')} · {item.get('findings', '?')} findings")
            self.recent_scans_text.configure(
                text="\n".join(lines) if lines else "No completed scans yet.")
        except (OSError, ValueError, TypeError):
            self.recent_scans_text.configure(text="Scan history unavailable.")
        if report is not None:
            summary = report.get("summary", {})
            cache = report.get("secret_cache") or {}
            if cache:
                self.scan_insights_text.configure(
                    text=(f"Secret files scanned: {cache.get('scanned', '—')}\n"
                          f"Reused: {cache.get('reused', '—')}\n"
                          f"Critical: {summary.get('critical', 0)}"))
            else:
                self.scan_insights_text.configure(
                    text=f"Critical: {summary.get('critical', 0)}\nCache metrics unavailable")
        self._refresh_issue_types(report if report is not None else self.report)
        if hasattr(self, "trend_chart"):
            self._draw_charts()

    def _build_charts(self):
        """Analytics canvases are placed by _build_analytics in reference order."""
        self._draw_charts()

    def _draw_score_gauge(self):
        if not hasattr(self, "score_gauge"):
            return
        canvas = self.score_gauge
        canvas.delete("all")
        width = max(canvas.winfo_width(), 155)
        radius = min((width - 24) / 2, 72)
        cx = width / 2
        bbox = (cx - radius, 10, cx + radius, 10 + radius * 2)
        canvas.create_arc(*bbox, start=180, extent=-180, style="arc",
                          width=15, outline=BORDER)
        if self.report is None:
            return
        try:
            score = max(0, min(100, float(self.report.get("score", 0))))
        except (TypeError, ValueError):
            return
        risk = 100 - score
        if risk:
            canvas.create_arc(*bbox, start=180, extent=-180 * risk / 100,
                              style="arc", width=15,
                              outline=BLOCKED if score < 50 else WARNING)
        if score:
            canvas.create_arc(*bbox, start=180 - 180 * risk / 100,
                              extent=-180 * score / 100,
                              style="arc", width=15, outline=SAFE)

    def _draw_charts(self):
        if not hasattr(self, "trend_chart"):
            return
        self._draw_score_gauge()
        trend = self.trend_chart
        trend.delete("all")
        width = max(trend.winfo_width(), 200)
        height = max(trend.winfo_height(), 110)
        try:
            history = json.loads(self.history_file.read_text(encoding="utf-8")) if self.history_file.exists() else []
            values = [max(0, int(entry["findings"])) for entry in history[-10:]
                      if isinstance(entry, dict) and str(entry.get("findings", "")).isdigit()]
        except (OSError, ValueError, TypeError):
            values = []
        if not values:
            trend.create_text(12, height / 2, anchor="w",
                              text="No historical scan data yet", fill=MUTED)
        else:
            peak = max(max(values), 1)
            points = []
            for index, count in enumerate(values):
                x = 20 + index * (width - 42) / max(len(values) - 1, 1)
                y = height - 35 - (count / peak) * (height - 62)
                points.extend((x, y))
                trend.create_oval(x - 3, y - 3, x + 3, y + 3, fill=BLOCKED, outline=BLOCKED)
            if len(points) >= 4:
                trend.create_line(*points, fill=BLOCKED, width=2)
            trend.create_text(12, height - 12, anchor="w",
                              text=f"{len(values)} scans  ·  latest: {values[-1]} findings",
                              fill=MUTED, font=("Segoe UI", 9))

        severity = self.severity_chart
        severity.delete("all")
        findings = (self.report.get("findings", []) if self.report is not None
                    else self.all_findings)
        if not findings:
            severity.create_text(12, 48, anchor="w",
                                 text="No findings yet" if self.report is None
                                 else "No findings detected", fill=MUTED if self.report is None else SAFE)
            return
        counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "OTHER": 0}
        for item in findings:
            level = str(item.get("severity", "")).upper()
            counts[level if level in counts else "OTHER"] += 1
        total = sum(counts.values())
        width = max(severity.winfo_width(), 200)
        height = max(severity.winfo_height(), 110)
        diameter = min(height - 18, width * 0.44, 120)
        left, top = 12, max(4, (height - diameter) / 2)
        bbox = (left, top, left + diameter, top + diameter)
        start = 90
        colors = {"CRITICAL": BLOCKED, "HIGH": "#E28B59",
                  "WARNING": WARNING, "OTHER": SAFE}
        for level, count in counts.items():
            if not count:
                continue
            extent = -360 * count / total
            severity.create_arc(*bbox, start=start, extent=extent, style="arc",
                                width=18, outline=colors[level])
            start += extent
        severity.create_text(left + diameter / 2, top + diameter / 2,
                             text=str(total), fill=WHITE,
                             font=("Segoe UI", 20, "bold"))
        x = left + diameter + 20
        for index, (level, count) in enumerate(counts.items()):
            severity.create_text(x, 20 + index * 24, anchor="w",
                                 text=f"{level.title()}: {count}",
                                 fill=colors[level], font=("Segoe UI", 9))

    def _render_pixel_cat(self, active):
        """Legacy scan indicator hook; sidebar pixel art intentionally removed."""
        return

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
        self.finding_tabs = ttk.Notebook(self.workspace)
        self.finding_tabs.pack(fill="x", padx=24, pady=(0, 4))
        for title in ("All Findings", "Secrets", "Dependencies"):
            tab = tk.Frame(self.finding_tabs, bg=CARD, height=1)
            self.finding_tabs.add(tab, text=title)
        self.finding_tabs.bind("<<NotebookTabChanged>>",
                               lambda _event: self.refresh_findings())
        self.findings_count_label = self._label(
            self.workspace, "0 visible · 0 total", 9, MUTED)
        self.findings_count_label.pack(anchor="w", padx=28, pady=(0, 6))
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

        self.inspector = FindingInspector(wrap)
        self.inspector.pack(side="right", fill="both", padx=(14, 0))
        # Compatibility with existing scan lifecycle and read-only display resets.
        self.detail = self.inspector.details_text
        self.preview = self.inspector.preview_text


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
        self.root.clipboard_append(json.dumps(example, indent=2) + "\n")
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
        self.header_scan_button.state(["disabled"])
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
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self._render_pixel_cat(True)
        self._activity_events = []
        self._record_activity("Scan started")
        self._refresh_issue_types(None)
        self._draw_charts()

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
            if not self._activity_events or not self._activity_events[-1].endswith(stage):
                self._record_activity(stage)
            return False
        if kind == "finding":
            self.all_findings.append(value)
            self.findings_value.configure(text=str(len(self.all_findings)), fg=OLIVE_MID)
            return True
        self.scan_button.state(["!disabled"])
        self.header_scan_button.state(["!disabled"])
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self._render_pixel_cat(False)
        if kind == "error":
            self._record_activity("Scan failed")
            self.status.set("Scan failed")
            self.status_label.configure(text=value, fg=BLOCKED)
            self.status_value.configure(text="ERROR", fg=BLOCKED)
            messagebox.showerror("Scan failed", value)
        else:
            self._record_activity("Scan complete")
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
            self.preview.configure(state="normal")
            self.preview.delete("1.0", "end")
            self.preview.insert("end", "Select a finding to see its masked location.")
            self.preview.configure(state="disabled")
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
            self.score_value.configure(text=f"{value['score']} /100", fg=color)
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
            if self.scan_button.instate(["disabled"]):
                self.cat_ticks += 1
                if self.cat_ticks % 5 == 0:
                    self._render_pixel_cat(True)
            self.root.after(100, self.poll)

    def clear_filters(self):
        self.search.set("")
        self.severity_filter.set("All severities")

    def refresh_findings(self):
        if not hasattr(self, "tree"):
            return
        query = self.search.get().strip().lower() if hasattr(self, "search") else ""
        severity = self.severity_filter.get() if hasattr(self, "severity_filter") else "All severities"
        category = ("All Findings" if not hasattr(self, "finding_tabs") else
                    self.finding_tabs.tab(self.finding_tabs.select(), "text"))
        self.tree.delete(*self.tree.get_children())
        visible = 0
        for index, item in enumerate(self.all_findings):
            if category != "All Findings" and finding_group(item) != category:
                continue
            haystack = " ".join(str(item.get(key, "")) for key in
                               ("severity", "rule", "file", "package", "summary")).lower()
            if query and query not in haystack:
                continue
            if severity != "All severities" and str(item.get("severity", "")).upper() != severity:
                continue
            self.tree.insert("", "end", iid=str(index), values=(
                item.get("severity", ""), item.get("rule", ""),
                item.get("file", item.get("package", "dependencies"))),
                tags=(str(item.get("severity", "info")).lower(),))
            visible += 1
        if hasattr(self, "findings_count_label"):
            self.findings_count_label.configure(
                text=f"{visible} visible · {len(self.all_findings)} total")


    def details(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        if index >= len(self.all_findings):
            return
        self.inspector.select_finding(self.all_findings[index])


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
        if not selected:
            messagebox.showinfo("PipelineGuard", "Select a finding first.")
            return
        index = int(selected[0])
        if index >= len(self.all_findings):
            return
        details = safe_finding_details(self.all_findings[index])
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        self.root.update()
        messagebox.showinfo("PipelineGuard", "Safe finding metadata copied.")


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
