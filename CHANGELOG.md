# Changelog

All notable changes to PipelineGuard are documented here.

## [1.0.0] - 2026-10-07

PipelineGuard's first production-oriented release combines a lightweight DevSecOps security gate with a native Windows desktop experience.

### Security scanning
- Secret detection for generic credentials plus provider-specific AWS, GitHub, Slack, Stripe, Google, npm, PyPI, SendGrid, and Twilio patterns.
- Python and Node.js dependency inventory with OSV vulnerability lookup and an explicit offline/incomplete mode.
- Advisory enrichment with CVSS, affected ranges, known fixes, and configurable severity release gates.
- False-positive suppression, scoped allowlists, ignored directories, and configurable file-size limits.
- SAFE, WARNING, and BLOCKED decisions with a 0-100 security score.

### Reports and CI
- Terminal, JSON, HTML, and SARIF reporting.
- GitHub pull-request annotations and release-policy enforcement.
- Docker CLI workflow.
- Automated tests, integration coverage, and a dedicated fast Windows compatibility gate.

### Windows desktop
- Native matte olive-green Tk desktop interface with background scans.
- Project/config selection, scan history, finding search/filtering, detail view, and report export.
- Standalone PyInstaller Windows build requiring no browser or web server.
- Per-user Inno Setup installer with Start Menu integration and optional desktop shortcut.
- Automated Windows validation covers build, packaged-app startup, installer compilation, silent install, installed-app startup, uninstall, and artifact upload.

### Validation
- Core security workflow passes on Ubuntu.
- Windows desktop packaging and install lifecycle pass on a GitHub-hosted Windows runner.
- Large-repository synthetic benchmark is retained separately from the fast Windows packaging gate.
- Interactive visual QA remains a manual acceptance step because hosted CI is not a reliable environment for file-dialog interaction.
