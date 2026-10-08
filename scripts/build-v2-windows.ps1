# Build the unreleased PipelineGuard v2 Windows desktop app.
# Run from any working directory. Requires Python 3.10+ and Windows.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root
if ($env:OS -ne "Windows_NT") { throw "This build script requires Windows." }
$python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
& $python -m pip install -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
& $python -m PyInstaller --noconfirm --clean --windowed --onedir --name PipelineGuard-v2 --collect-submodules pipelineguard desktop_launcher.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
$exe = Join-Path $root "dist\PipelineGuard-v2\PipelineGuard-v2.exe"
if (!(Test-Path $exe)) { throw "Expected executable not found: $exe" }
Write-Host "Build complete: $exe"
Write-Host "Distribute the entire dist\PipelineGuard-v2 folder, not just the EXE."
