"""Shared scan engine for desktop callers."""
from pathlib import Path
from pipelineguard.config import load_config, apply_allowlist, policy_blocks
from pipelineguard.reporting import build_report
from scanners.secret_scanner import scan_directory
from scanners.dependency_scanner import scan_dependencies, reconcile_inventory
from scanners.osv_scanner import query_osv


def run_scan(path: Path, config: Path | None = None, online: bool = True):
    if not path.is_dir():
        raise ValueError("Select an existing project directory")
    settings = load_config(config)
    records = scan_dependencies(path, settings.ignored_directories)
    packages = reconcile_inventory(records)
    vulnerabilities = query_osv(packages, enrich=True) if online else [
        {"severity": "WARNING", "rule": "Dependency check incomplete", "summary": "Online vulnerability lookup disabled."}
    ]
    report = build_report(
        apply_allowlist(scan_directory(path, settings.ignored_directories, settings.max_file_size), settings.allowlist),
        apply_allowlist(records + vulnerabilities, settings.allowlist),
    )
    report["dependency_check_complete"] = not any(item.get("rule") == "Dependency check incomplete" for item in vulnerabilities)
    report["policy_blocked"] = policy_blocks(report, settings) or (settings.fail_on_warning and report["status"] == "WARNING")
    if report["policy_blocked"]:
        report["status"] = "BLOCKED"
    return report
