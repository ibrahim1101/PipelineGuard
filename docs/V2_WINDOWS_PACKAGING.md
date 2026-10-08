# PipelineGuard v2 — Windows portable packaging (development)

**Status:** Unreleased, manual validation required. Stable v1.0.0 and its installer are unchanged.

## Build locally

On Windows, with Python installed, from the repository's `feat/v2-engine-integration` branch:

```powershell
cd C:\Users\ibrah\PipelineGuard
git pull origin feat/v2-engine-integration
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-v2-windows.ps1
.\dist\PipelineGuard-v2\PipelineGuard-v2.exe
```

The PowerShell script installs the project requirements and PyInstaller, then creates a **windowed, one-directory** bundle. Do not distribute the EXE alone; the `dist/PipelineGuard-v2` directory contains required runtime files. The executable should start the Tk desktop without a terminal window, web server, or browser. Scans, export and optional OSV lookup still need hands-on testing.

## GitHub Actions

Go to **Actions → PipelineGuard v2 Windows portable (development) → Run workflow** and select `feat/v2-engine-integration`. Download the resulting `PipelineGuard-v2-Windows-portable` artifact when the run completes. The workflow runs pytest, builds on a Windows runner, verifies that the EXE exists, and uploads the bundle. It does **not** prove that a graphical desktop opened successfully.

## Windows acceptance checks

1. Extract the whole ZIP to a writable folder and double-click `PipelineGuard-v2.exe`.
2. Verify the approved cat shield, Pipeline/Guard Bahnschrift title, olive theme, and top-level header.
3. Confirm dashboard mouse-wheel scrolling and the idle progress indicator.
4. Scan a folder with fake test secrets; confirm findings, status, progress animation, and successful completion.
5. Export HTML, JSON and SARIF reports; restart and check preferences/history persistence.
6. Try offline mode and optional online OSV mode; confirm errors are surfaced and the app stays responsive.
7. Test on a Windows PC **without a separate Python installation** before claiming standalone portability.

Do not publish a v2 installer or replace stable v1.0.0 until the acceptance checks and CI build are verified. A signed installer, shortcut, uninstall support and Windows SmartScreen reputation are **future release-gating work**, not claims about this portable build.
