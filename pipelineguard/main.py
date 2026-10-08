from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from scanners.secret_scanner import scan_directory
from scanners.dependency_scanner import scan_dependencies, reconcile_inventory
from scanners.osv_scanner import query_osv
from pipelineguard.reporting import build_report, write_html_report, write_json_report, write_sarif_report
from pipelineguard.config import apply_allowlist, load_config, policy_blocks
from pipelineguard.theme import OLIVE, SAFE, WARNING, BLOCKED
from pipelineguard.engine import run_scan
from pipelineguard.annotations import github_annotations

app = typer.Typer(help="PipelineGuard: a lightweight DevSecOps security scanner.")
console = Console()

@app.callback()
def cli() -> None:
    """Scan projects with PipelineGuard."""

@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write a JSON or HTML report file."),
    config: Path | None = typer.Option(None, "--config", help="Path to a .pipelineguard.json file."),
    annotations: bool = typer.Option(False, "--github-annotations", help="Emit GitHub Actions annotations to stderr."),
    profile: str | None = typer.Option(None, "--profile", help="Scan profile: quick, standard, deep, release, forensic."),
    baseline: Path | None = typer.Option(None, "--baseline", help="Compare findings with a baseline snapshot."),
    save_baseline: bool = typer.Option(False, "--save-baseline", help="Update the baseline snapshot after comparison."),
) -> None:
    """Scan a project directory for exposed secrets."""
    try:
        report = run_scan(path, config, profile=profile, baseline_path=baseline, update_baseline=save_baseline)
    except (OSError, ValueError) as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=2)
    blocked_by_policy = report["policy_blocked"]
    status = report["status"]
    if annotations:
        for annotation in github_annotations(report):
            typer.echo(annotation, err=True)

    if output:
        if output.suffix.lower() == ".html":
            write_html_report(report, output)
        elif output.suffix.lower() == ".sarif":
            write_sarif_report(report, output)
        else:
            write_json_report(report, output)

    if json_output:
        typer.echo(json.dumps(report, indent=2))
        raise typer.Exit(code=1 if status == "BLOCKED" else 0)

    status_color = SAFE if status == "SAFE" else WARNING if status == "WARNING" else BLOCKED
    console.print(f"[bold {OLIVE}]PipelineGuard Security Report[/bold {OLIVE}]\nStatus: [{status_color}][bold]{status}[/bold][/{status_color}]")
    console.print(f"[{OLIVE}]Score: {report['score']}/100[/{OLIVE}]")
    console.print(f"Findings: {report['summary']['total_findings']} | Critical: {report['summary']['critical']}")
    for finding in report["findings"]:
        console.print(f"- [{finding['severity']}] {finding.get('file', finding.get('package', 'dependencies'))}:{finding.get('line', '-')} — {finding['rule']}", markup=False)
        if finding.get("id"):
            cvss = finding.get("cvss_score")
            cvss_text = f" | CVSS {cvss:g}" if isinstance(cvss, (int, float)) else ""
            console.print(f"  {finding['id']} | {finding.get('package', '')} {finding.get('version', '')} | {finding.get('advisory_severity', 'UNKNOWN')}{cvss_text}", markup=False)
            console.print(f"  {finding.get('summary', '')}", markup=False)
            console.print(f"  Advisory fix versions: {', '.join(finding.get('fixed_versions', [])) or 'Not specified'}", markup=False)
            for reference in finding.get("references", []):
                console.print(f"  Reference: {reference}", markup=False)
    if blocked_by_policy:
        console.print(f"[{BLOCKED}]Release blocked by configured policy.[/{BLOCKED}]")
    raise typer.Exit(code=1 if status == "BLOCKED" else 0)


if __name__ == "__main__":
    app()
