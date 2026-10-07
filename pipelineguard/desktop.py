"""Standalone native desktop interface; no HTTP server or browser."""
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from pipelineguard.engine import run_scan
from pipelineguard.reporting import write_json_report, write_html_report, write_sarif_report
from pipelineguard.theme import OLIVE_DARK, OLIVE_LIGHT, INK


class Desktop:
    def __init__(self, root):
        self.root = root
        self.report = None
        self.events = queue.Queue()
        root.title("PipelineGuard — Desktop")
        root.geometry("1060x720")
        root.minsize(800, 600)
        root.configure(bg=OLIVE_LIGHT)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TButton", padding=8, background=OLIVE_DARK, foreground="white")
        style.configure("Treeview", rowheight=28)
        tk.Label(root, text="PipelineGuard", font=("Segoe UI", 24, "bold"), bg=OLIVE_DARK, fg="white", pady=16).pack(fill="x")
        bar = ttk.Frame(root, padding=12)
        bar.pack(fill="x")
        self.folder = tk.StringVar()
        ttk.Entry(bar, textvariable=self.folder, width=70).pack(side="left", fill="x", expand=True)
        ttk.Button(bar, text="Choose project", command=self.choose).pack(side="left")
        self.online = tk.BooleanVar(value=True)
        ttk.Checkbutton(root, text="Online vulnerability lookup — sends package names and versions to OSV", variable=self.online).pack(anchor="w", padx=12)
        self.config = tk.StringVar()
        settings = ttk.Frame(root, padding=12)
        settings.pack(fill="x")
        ttk.Entry(settings, textvariable=self.config).pack(side="left", fill="x", expand=True)
        ttk.Button(settings, text="Choose configuration", command=self.choose_config).pack(side="left")
        self.scan_button = ttk.Button(settings, text="Scan project", command=self.scan)
        self.scan_button.pack(side="left")
        ttk.Button(settings, text="Export report", command=self.export).pack(side="left")
        self.status = tk.StringVar(value="Ready — select a project")
        tk.Label(root, textvariable=self.status, bg=OLIVE_LIGHT, fg=INK, font=("Segoe UI", 12)).pack(anchor="w", padx=12, pady=8)
        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=12, pady=4)
        findings_frame = ttk.Frame(root)
        findings_frame.pack(fill="both", expand=True, padx=12)
        self.tree = ttk.Treeview(findings_frame, columns=("severity", "rule", "location"), show="headings", height=12)
        for column in ("severity", "rule", "location"):
            self.tree.heading(column, text=column.title())
        scrollbar = ttk.Scrollbar(findings_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.details)
        self.detail = tk.Text(root, height=10, wrap="word")
        self.detail.pack(fill="both", padx=12, pady=12)
        root.after(100, self.poll)

    def choose(self):
        value = filedialog.askdirectory()
        if value:
            self.folder.set(value)

    def choose_config(self):
        value = filedialog.askopenfilename(filetypes=[("JSON configuration", "*.json")])
        if value:
            self.config.set(value)

    def scan(self):
        path, config, online = Path(self.folder.get()), self.config.get(), self.online.get()
        if not self.folder.get() or not path.is_dir():
            messagebox.showerror("PipelineGuard", "Choose an existing project folder.")
            return
        self.scan_button.state(["disabled"])
        self.report = None
        self.tree.delete(*self.tree.get_children())
        self.status.set("Scanning…")
        self.detail.delete("1.0", "end")
        self.progress.start(12)
        def worker():
            try:
                self.events.put(("result", run_scan(path, Path(config) if config else None, online)))
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
                messagebox.showerror("Scan failed", value)
            else:
                self.report = value
                self.status.set(f"{value['status']} · Score {value['score']}/100 · {len(value['findings'])} findings · Dependency check {'complete' if value['dependency_check_complete'] else 'incomplete'}")
                for index, item in enumerate(value["findings"]):
                    self.tree.insert("", "end", iid=str(index), values=(item["severity"], item["rule"], item.get("file", item.get("package", ""))))
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def details(self, event=None):
        selected = self.tree.selection()
        if selected and self.report:
            self.detail.delete("1.0", "end")
            self.detail.insert("end", json.dumps(self.report["findings"][int(selected[0])], indent=2))

    def export(self):
        if self.report is None:
            messagebox.showinfo("PipelineGuard", "Complete a scan first.")
            return
        value = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html"), ("JSON", "*.json"), ("SARIF", "*.sarif")])
        if value:
            try:
                output = Path(value)
                writer = {".html": write_html_report, ".json": write_json_report, ".sarif": write_sarif_report}.get(output.suffix.lower())
                if writer is None:
                    raise ValueError("Choose HTML, JSON, or SARIF")
                writer(self.report, output)
            except Exception as exc:
                messagebox.showerror("Export failed", str(exc))


def main():
    root = tk.Tk()
    Desktop(root)
    root.mainloop()


if __name__ == "__main__":
    main()
