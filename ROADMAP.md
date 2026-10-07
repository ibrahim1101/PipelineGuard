# PipelineGuard v1.0.0 Development Tracker

We are building one strong first release instead of several limited versions. Internal phases organize work but are not separate public versions.

## Overall progress

Verification: 74 automated tests pass locally; four real Tk GUI tests require
a graphical session and are skipped here. Live OSV lookup and advisory
enrichment passed. Windows executable, installer, startup, install, and uninstall validation now pass in CI. Desktop visual QA on a normal interactive Windows machine remains pending. Implementation counts are provisional.

Desktop scope extends the tracker to 34 features. Final-environment completion
counts remain pending release QA.

An item becomes **Done and Tested** only after implementation, automated tests, and a real-project test pass.

## Feature tracker

| # | Feature | Status | Tested |
|---:|---|---|---|
| 1 | Modular project structure | Implemented | Pending final test |
| 2 | Secret scanning engine | Implemented | Pending final test |
| 3 | Generic password and token detection | Implemented | Pending final test |
| 4 | AWS, GitHub-token, and private-key detection | Implemented | Pending final test |
| 5 | Generated-folder exclusions | Implemented | Pending final test |
| 6 | Python dependency inventory | Implemented | Pending final test |
| 7 | Node.js dependency inventory | Implemented | Pending final test |
| 8 | OSV vulnerability lookup | Implemented | Live lookup/enrichment passed |
| 9 | Offline vulnerability fallback | Implemented | Pending final test |
| 10 | SAFE/WARNING/BLOCKED decisions | Implemented | Pending final test |
| 11 | Security score from 0–100 | Implemented | Pending final test |
| 12 | Terminal report | Implemented | Pending final test |
| 13 | JSON report | Implemented | Pending final test |
| 14 | HTML report | Implemented | Pending final test |
| 15 | Custom configuration file | Implemented | Pending final test |
| 16 | Configurable ignored directories | Implemented | Pending final test |
| 17 | Configurable file-size limits | Implemented | Pending final test |
| 18 | Configurable warning failure policy | Implemented | Pending final test |
| 19 | Automated unit-test suite | Implemented | 74 local tests passed |
| 20 | Real-project integration tests | Implemented | Mixed Python/Node project gate passed |
| 21 | Better version and range parsing | Implemented | Exact versions, URLs, tags, and common ranges classified without guessing |
| 22 | CVSS and affected-version reporting | Implemented | Numeric scores, vectors, ranges, and fixes tested |
| 23 | Provider-specific secret rules | Implemented | AWS, GitHub, Slack, Stripe, Google, npm, PyPI, SendGrid, Twilio tested |
| 24 | False-positive suppression system | Implemented | Scoped wildcard paths and line matching tested |
| 25 | Allowlist support | Implemented | Pending final test |
| 26 | SARIF output | Implemented | Pending final test |
| 27 | GitHub pull-request annotations | Implemented | Escaping tests passed; GitHub execution pending |
| 28 | Rich policy and release gates | Implemented | Pending final test |
| 29 | Performance and large-repository testing | Partial | 10,000-file Linux test passed; Windows benchmark pending |
| 30 | Final packaging, documentation, and release QA | In progress | Windows packaging/install QA passed; final visual/release QA pending |
| 31 | Olive-green native desktop interface | Implemented | Visual QA pending |
| 32 | Background desktop scans and report exports | Implemented | Engine tests passed; GUI tests pending |
| 33 | Standalone Windows executable | Implemented | Windows build and startup smoke test passed |
| 34 | Windows installer and shortcut | Implemented | Build/install/launch/uninstall CI passed |

## Progress format

```text
PipelineGuard v1.0.0: 34/34 implemented
Tested: Windows packaging chain and core automated gates passing; final visual/release acceptance pending
Currently working on: Feature #30 — final packaging, documentation, and release QA
```

v1.0.0 is complete only when all features are implemented and tested, the CLI works on a clean machine, GitHub Actions passes, and the documentation is complete.
