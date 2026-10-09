# PipelineGuard

## Engineering history and test evidence

The editable, living [Engineering History, Trial-and-Error Log & Test Evidence](docs/ENGINEERING_HISTORY.md) records implementation milestones, failed attempts, fixes, CI validation, Windows test skips, and repeatable performance benchmarks for future final-project reporting. For a fresh conversation, start with the [New Chat Handoff](docs/NEW_CHAT_HANDOFF.md) to recover current branch, last verified results, open work, and documentation rules.

## Release and development status

**Stable release:** v1.0.0 (Windows installer, CLI and Tk desktop). **v2.0 is unreleased development** on `feat/v2-engine-integration` / PR #1; do not treat its capabilities as part of the stable installer.

The v2 development branch currently includes scan profiles, external verified SHA-256 fingerprints, bounded fingerprint workers, progress events, Git context with remote credential redaction, and baseline finding differences. The v2 development branch now includes a separate **content-verified secret-findings cache** and adaptive full/incremental scan selection. Cached findings are reused only after content verification; tiny-file-heavy repositories can use full scanning instead. The fingerprint cache and secret-findings cache are distinct. Streaming findings, actual analyzer-result reuse, dependency reachability, and the redesigned SOC desktop remain planned, not released. Linux/Windows CI success on the development branch does not constitute a v2 release.

## Configuration (optional) — complete help

The desktop's **Configuration (Optional)** field accepts a JSON file; click the **?** beside it to see all seven supported settings, a copyable example, and instructions. Leave the field blank for defaults. Select a file explicitly using **Choose config**.

Read the [complete configuration guide](docs/CONFIGURATION.md) and use the [safe starter JSON](examples/pipelineguard.example.json). The guide covers `ignored_directories`, `max_file_size`, `fail_on_warning`, `allowlist`, `minimum_score`, `blocked_rules`, and `block_advisory_severity`, with types, defaults, validation and examples.

CLI example: `python -m pipelineguard.main scan . --config .pipelineguard.json`.

## Advisory release policy

Set `"block_advisory_severity": "HIGH"` in configuration to block HIGH and
CRITICAL dependency advisories. Supported thresholds: LOW, MODERATE, HIGH,
CRITICAL; null disables this additional gate. Unknown advisory severity is
not guessed. Use `fail_on_warning` for a stricter policy that also blocks
incomplete checks and unknown-severity vulnerability warnings.

## Docker

Build the image:

```bash
docker build -t pipelineguard:local .
```

Scan a project from the current directory:

```bash
docker run --rm -v "$PWD":/workspace:ro pipelineguard:local scan /workspace
```

Generate a JSON report in the current directory:

```bash
mkdir -p reports
docker run --rm -v "$PWD":/workspace pipelineguard:local \
  scan /workspace --json --output /workspace/reports/pipelineguard.json
```

Or use Docker Compose:

```bash
docker compose run --rm pipelineguard
```

The container runs the CLI scanner only; the native desktop application remains available through the Windows build.

## v2 desktop scan profiles and progress (development branch)

The unreleased v2 desktop now offers Quick, Standard, Deep, Release and Forensic profiles, stage-based scan progress, and secret cache statistics when available. Quick disables online intelligence by profile design even if the live OSV checkbox is selected; Standard and Deep support the cache, while Release and Forensic use full secret scans without cache statistics. These are development features, not part of the stable v1.0.0 installer. Verify on Windows before relying on the new controls.

## Standalone desktop (development)

Launch with `python -m pipelineguard.desktop`. Uses native Tk widgets,
background scanning, project/configuration selection, and HTML/JSON/SARIF export.
No browser or web server is required. Online OSV lookup is optional and sends
package names and versions. Offline lookup is explicitly marked incomplete.

Windows packaging recipe (run on Windows with Python/Tk installed):

```powershell
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --windowed --onedir --name PipelineGuard desktop_launcher.py
```

The entire generated `dist/PipelineGuard` folder can be distributed directly. The Windows CI also compiles `PipelineGuard-Setup-1.0.0.exe` with Inno Setup. The standalone executable, startup smoke test, per-user installer, installed-app launch, uninstaller, and cleanup path have all passed on a GitHub-hosted Windows runner.

PipelineGuard is a lightweight DevSecOps security scanner that checks software projects before they are built or released.

## What it checks

- Exposed secrets such as API keys, tokens, passwords, and private keys
- Python and Node.js dependency manifests
- Malformed dependency files
- A release decision: `SAFE`, `WARNING`, or `BLOCKED`
- A security score from 0 to 100

## Quick start

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python -m pipelineguard.main scan .
```

Generate reports:

```bash
python -m pipelineguard.main scan . --json --output reports/security.json
python -m pipelineguard.main scan . --output reports/security.html
```

Run tests:

```bash
pytest -q
```

## Status levels

| Status | Meaning |
|---|---|
| `SAFE` | No security findings were detected. |
| `WARNING` | A non-critical issue needs review. |
| `BLOCKED` | A critical security issue was detected. |

## Project status

Stable release: v1.0.0. Secret scanning, dependency inventory,
live OSV lookup, scoring, JSON/HTML/SARIF reports, release policies, native
desktop scanning, Docker support, tests, and GitHub Actions workflows are implemented. The Windows standalone executable and v1.0.0 installer now pass automated build, launch, install, installed-app launch, and uninstall validation on a Windows runner.

When scanning this repository itself, test fixtures intentionally contain fake
credentials so the scanner can be tested; those findings are expected to make
the self-scan return `BLOCKED`.

## Responsible testing

Only scan projects you own or are authorized to assess. Never place real credentials in test fixtures; use clearly fake values.
