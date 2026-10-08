"""Shared scan engine for desktop, CLI and CI callers."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import os
from time import perf_counter
from pathlib import Path
from typing import Callable

from pipelineguard.baseline import compare_baseline, finding_key, read_baseline, write_baseline
from pipelineguard.cache import ScanCache
from pipelineguard.config import load_config, apply_allowlist, policy_blocks
from pipelineguard.git_context import get_git_context
from pipelineguard.orchestrator import ProgressEvent, fingerprint_files
from pipelineguard.secret_cache import scan_secrets_incremental, choose_scan_strategy
from pipelineguard.profiles import get_profile
from pipelineguard.reporting import build_report
from scanners.traversal import iter_files
from scanners.secret_scanner import scan_directory
from scanners.dependency_scanner import scan_dependencies, reconcile_inventory
from scanners.osv_scanner import query_osv


def _project_cache(root: Path) -> ScanCache:
    """Keep generated state outside the scanned tree and Git working copy."""
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    name = hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json"
    return ScanCache.load(base / "PipelineGuard" / "fingerprints", name)


def run_scan(
    path: Path,
    config: Path | None = None,
    online: bool = True,
    *,
    profile: str | None = None,
    progress: Callable[[ProgressEvent], None] | None = None,
    baseline_path: Path | None = None,
    update_baseline: bool = False,
    timings: dict[str, float] | None = None,
    on_finding: Callable[[dict[str, object]], None] | None = None,
):
    """Scan a project, optionally collecting v2 telemetry and baseline differences.

    Fingerprint reuse is *not* analyzer-result reuse: the security scanners
    still inspect all eligible files on every run to preserve v1 coverage.
    """
    scan_started = perf_counter()
    stage_started = scan_started
    if not path.is_dir():
        raise ValueError("Select an existing project directory")
    if update_baseline and baseline_path is None:
        raise ValueError("Updating a baseline requires an explicit baseline_path")
    settings = load_config(config)
    selected = get_profile(profile) if profile is not None else None
    if selected is not None:
        online = online and selected.online_intelligence
        if selected.incremental:
            try:
                fingerprint_files(
                    path.resolve(),
                    iter_files(path.resolve(), settings.ignored_directories),
                    _project_cache(path),
                    workers=selected.workers,
                    progress=progress,
                )
            except OSError:
                # Cache errors must never suppress the security scan itself.
                if progress:
                    progress(ProgressEvent("fingerprint-unavailable"))
    if timings is not None:
        timings["setup_ms"] = (perf_counter() - stage_started) * 1000
    stage_started = perf_counter()
    if progress:
        progress(ProgressEvent("dependencies"))
    records = scan_dependencies(path, settings.ignored_directories)
    packages = reconcile_inventory(records)
    if timings is not None:
        timings["dependencies_ms"] = (perf_counter() - stage_started) * 1000
    stage_started = perf_counter()
    if progress:
        progress(ProgressEvent("vulnerability-intelligence"))
    vulnerabilities = query_osv(packages, enrich=True) if online else [
        {"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Online vulnerability lookup disabled."}
    ]
    if timings is not None:
        timings["osv_ms"] = (perf_counter() - stage_started) * 1000
    stage_started = perf_counter()
    if progress:
        progress(ProgressEvent("secrets"))
    use_secret_cache = selected is not None and selected.name.lower() in {"quick", "standard", "deep"}
    secret_metrics: dict[str, int | str | None] | None = {} if use_secret_cache else None
    def emit_secret(finding: dict[str, object]) -> None:
        if on_finding is not None and apply_allowlist([finding], settings.allowlist):
            on_finding(dict(finding))

    if use_secret_cache and choose_scan_strategy(path, settings.ignored_directories, settings.max_file_size) == "full":
        secrets = scan_directory(path, settings.ignored_directories, settings.max_file_size,
                                 on_finding=emit_secret if on_finding is not None else None)
        # Full scans do not expose per-file counters; mark them unavailable.
        secret_metrics.update({"strategy": "full", "discovered": None, "hashed": None, "scanned": None,
                               "reused": 0, "skipped_size": None, "skipped_changed": None, "skipped_error": None})
    elif use_secret_cache:
        secrets = scan_secrets_incremental(path, settings.ignored_directories, settings.max_file_size,
                                           metrics=secret_metrics, on_finding=emit_secret if on_finding is not None else None)
        secret_metrics["strategy"] = "incremental"
    else:
        secrets = scan_directory(path, settings.ignored_directories, settings.max_file_size,
                                 on_finding=emit_secret if on_finding is not None else None)
    if progress and secret_metrics is not None:
        progress(ProgressEvent("secrets-complete",
                               discovered=secret_metrics["discovered"],
                               processed=(secret_metrics["scanned"] + secret_metrics["reused"]
                                          if secret_metrics["scanned"] is not None else None),
                               cached=secret_metrics["reused"]))
    if timings is not None:
        timings["secrets_ms"] = (perf_counter() - stage_started) * 1000
    stage_started = perf_counter()
    report_build_started = perf_counter()
    visible_secrets = apply_allowlist(secrets, settings.allowlist)
    visible_other = apply_allowlist(records + vulnerabilities, settings.allowlist)
    if on_finding is not None:
        # Findings are emitted only after allowlist filtering. Callback failures
        # propagate rather than silently producing an incomplete scan.
        for finding in visible_other:
            on_finding(dict(finding))
    report = build_report(visible_secrets, visible_other)
    if timings is not None:
        timings["report_build_ms"] = (perf_counter() - report_build_started) * 1000
    report["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if secret_metrics is not None:
        report["secret_cache"] = secret_metrics
    report["dependency_check_complete"] = not any(item.get("rule") == "Dependency check incomplete" for item in vulnerabilities)
    report["policy_blocked"] = policy_blocks(report, settings) or (settings.fail_on_warning and report["status"] == "WARNING")
    if report["policy_blocked"]:
        report["status"] = "BLOCKED"
    if selected is not None:
        report["scan_profile"] = selected.name
        if selected.git_context:
            git_started = perf_counter()
            report["git_context"] = get_git_context(path.resolve())
            if timings is not None:
                timings["git_context_ms"] = (perf_counter() - git_started) * 1000
    if baseline_path is not None:
        previous = read_baseline(baseline_path)
        comparison = compare_baseline(report["findings"], previous)
        report["baseline"] = {key: value for key, value in comparison.items() if key != "finding_states"}
        for finding in report["findings"]:
            finding["baseline_state"] = comparison["finding_states"][finding_key(finding)]
        if update_baseline:
            write_baseline(baseline_path, report["findings"])
    if timings is not None:
        timings["report_ms"] = (perf_counter() - stage_started) * 1000
        timings["report_other_ms"] = max(0.0, timings["report_ms"] - timings.get("report_build_ms", 0.0) - timings.get("git_context_ms", 0.0))
        timings["total_ms"] = (perf_counter() - scan_started) * 1000
    if progress:
        progress(ProgressEvent("complete"))
    return report
