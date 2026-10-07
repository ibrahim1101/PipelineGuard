# PipelineGuard

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

The entire generated `dist/PipelineGuard` folder must be distributed.
This recipe has not yet been built or verified on Windows; an installer and
shortcut integration remain pending.

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

Current release development: v1.0.0. Secret scanning, dependency inventory,
live OSV lookup, scoring, JSON/HTML/SARIF reports, release policies, native
desktop scanning, Docker support, tests, and GitHub Actions workflows are implemented. Windows
executable and installer verification still require a Windows runner.

When scanning this repository itself, test fixtures intentionally contain fake
credentials so the scanner can be tested; those findings are expected to make
the self-scan return `BLOCKED`.

## Responsible testing

Only scan projects you own or are authorized to assess. Never place real credentials in test fixtures; use clearly fake values.
