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
        self.events = queue.Queue()
        self.root.title("PipelineGuard — Security Scanner")
        self.root.geometry("1180x780")
        self.root.minsize(900, 650)
        self.root.configure(bg=CANVAS)

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
        style.configure("Horizontal.TProgressbar", troughcolor=BORDER, background=OLIVE,
                        bordercolor=CANVAS, lightcolor=OLIVE, darkcolor=OLIVE)

        self._build_header()
        self._build_controls()
        self._build_dashboard()
        self._build_findings()
        self.root.after(100, self.poll)

    def _label(self, parent, text, size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", CANVAS), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def _build_header(self):
        header = tk.Frame(self.root, bg=OLIVE_DEEP, height=112)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="PipelineGuard", bg=OLIVE_DEEP, fg=WHITE,
                 font=("Segoe UI", 30, "bold")).pack(anchor="w", padx=28, pady=(20, 0))
        tk.Label(header, text="Secure every build before it reaches production.",
                 bg=OLIVE_DEEP, fg=OLIVE_LIGHT, font=("Segoe UI", 11)).pack(anchor="w", padx=31)

    def _build_controls(self):
        card = tk.Frame(self.root, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=24, pady=(18, 10))
        self.folder = tk.StringVar()
        self.config = tk.StringVar()
        self.online = tk.BooleanVar(value=True)

        self._label(card, "PROJECT FOLDER", 9, MUTED, True, bg=CARD).grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 4))
        ttk.Entry(card, textvariable=self.folder, font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky="ew", padx=(16, 8), pady=(0, 14))
        ttk.Button(card, text="Choose project", command=self.choose).grid(
            row=1, column=1, padx=(0, 16), pady=(0, 14))

        self._label(card, "CONFIGURATION (OPTIONAL)", 9, MUTED, True, bg=CARD).grid(
            row=2, column=0, sticky="w", padx=16, pady=(4, 4))
        ttk.Entry(card, textvariable=self.config, font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky="ew", padx=(16, 8), pady=(0, 14))
        ttk.Button(card, text="Choose config", command=self.choose_config).grid(
            row=3, column=1, padx=(0, 16), pady=(0, 14))

        options = tk.Frame(card, bg=CARD)
        options.grid(row=4, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 14))
        tk.Checkbutton(options, text="Enable live OSV vulnerability lookup",
                       variable=self.online, bg=CARD, fg=INK, activebackground=CARD,
                       selectcolor=OLIVE_LIGHT, font=("Segoe UI", 10)).pack(side="left")
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
        row = tk.Frame(self.root, bg=CANVAS)
        row.pack(fill="x", padx=24, pady=(0, 12))
        self.status_value = self._metric(row, "Status", "READY", OLIVE_MID)
        self.score_value = self._metric(row, "Security score", "—")
        self.findings_value = self._metric(row, "Findings", "—")
        self.critical_value = self._metric(row, "Critical", "—", BLOCKED)
        self.warning_value = self._metric(row, "Warnings", "—", WARNING)
        self.dependency_value = self._metric(row, "Dependency lookup", "—")
        self.duration_value = self._metric(row, "Scan duration", "—")
        self.status = tk.StringVar(value="Ready — choose a project folder to begin")
        self._label(self.root, "", 10, MUTED)
        self.status_label = self._label(self.root, self.status.get(), 10, MUTED)
        self.status_label.pack(anchor="w", padx=28, pady=(0, 6))
        self.progress = ttk.Progressbar(self.root, mode="indeterminate",
                                        style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=24, pady=(0, 14))

    def _build_findings(self):
        self._label(self.root, "Security findings", 15, OLIVE_DEEP, True).pack(
            anchor="w", padx=28, pady=(0, 8))
        search_bar = tk.Frame(self.root, bg=CANVAS)
        search_bar.pack(fill="x", padx=24, pady=(0, 8))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.refresh_findings())
        self.severity_filter = tk.StringVar(value="All severities")
        self.severity_filter.trace_add("write", lambda *_: self.refresh_findings())
        tk.Label(search_bar, text="Filter findings:", bg=CANVAS, fg=MUTED,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Entry(search_bar, textvariable=self.search, width=42).pack(side="left", padx=(8, 12))
        ttk.Combobox(search_bar, textvariable=self.severity_filter, state="readonly", width=18,
                     values=("All severities", "CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW", "INFO")).pack(side="left")
        ttk.Button(search_bar, text="Clear filters", command=self.clear_filters).pack(side="left", padx=(8, 0))
        wrap = tk.Frame(self.root, bg=CANVAS)
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
        self._label(detail_card, "Finding details", 11, OLIVE_DARK, True, bg=CARD).pack(
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
        self.scan_started = time.perf_counter()
        self.report = None
        self.tree.delete(*self.tree.get_children())
        self.status.set("Scanning project…")
        self.status_label.configure(text=self.status.get(), fg=OLIVE_MID)
        self.status_value.configure(text="SCANNING", fg=OLIVE_MID)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "PipelineGuard is analyzing the selected project.")
        self.detail.configure(state="disabled")
        self.progress.start(12)

        def worker():
            try:
                config = Path(self.config.get()) if self.config.get() else None
                result = run_scan(Path(self.folder.get()), config, self.online.get())
                self.events.put(("result", result))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            kind, value = self.events.get_nowait()
            self.scan_button.state(["!disabled"])
            self.progress.stop()
            if kind == "error":
                self.status.set("Scan failed")
                self.status_label.configure(text=value, fg=BLOCKED)
                self.status_value.configure(text="ERROR", fg=BLOCKED)
                messagebox.showerror("Scan failed", value)
            else:
                self.report = value
                self.all_findings = value["findings"]
                self.save_history(value)
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
        except queue.Empty:
            pass
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
        if selected and self.report:
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            finding = self.report["findings"][int(selected[0])]
            readable = (
                f"Severity: {finding.get('severity', 'UNKNOWN')}\\n"
                f"Rule: {finding.get('rule', 'Security finding')}\\n"
                f"Location: {finding.get('file', finding.get('package', 'N/A'))}\\n\\n"
                f"Summary\\n{finding.get('summary', 'No summary available.')}\\n\\n"
                f"Remediation\\n{finding.get('remediation', 'Review this finding and remove or secure the affected value.')}\\n\\n"
                f"Technical details\\n{json.dumps(finding, indent=2)}"
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
        self._label(window, "Recent scans", 16, OLIVE_DEEP, True).pack(anchor="w", padx=18, pady=14)
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
