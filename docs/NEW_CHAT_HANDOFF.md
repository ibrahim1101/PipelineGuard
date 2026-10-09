# PipelineGuard — New Chat Development Handoff

Updated: 2026-10-08
Repository: https://github.com/ibrahim1101/PipelineGuard
Active branch: `feat/v2-engine-integration`
Stable release: v1.0.0 (do not modify unless explicitly requested)

## Purpose

This document is the quick-start source of truth for resuming PipelineGuard development in a fresh ChatGPT conversation. The append-only detailed development and testing journal is `docs/ENGINEERING_HISTORY.md`. Read both before changing code. Confirm current repository contents and commits rather than assuming earlier changes are present.

## Product and architecture

PipelineGuard is a DevSecOps security scanning tool with a Windows standalone desktop application (Python/Tkinter), CLI and Docker usage. v1.0.0 provides secret and dependency/OSV scanning, reports including JSON, HTML and SARIF, and Windows installer workflows. v2 development includes scan profiles (Quick, Standard, Deep, Release, Forensic), progress telemetry, fingerprint cache, content-verified incremental secret findings cache, baseline and Git context support, OSV advisory deduplication and enhanced reporting.

## Current state (user-validated on Windows)

Latest confirmed tests: `python -m pytest -q` -> **129 passed, 1 skipped in 20.52s**, zero failures. Skip reason was not verified in that particular run.

Profiling command: `python -m scripts.engine_timing`. This runs offline Standard-profile scans and excludes online OSV network latency.

Latest after concurrent Git query optimization (commit `f4ecb50`):

| Run | Git context (ms) | Overall scan (ms) | Secret files scanned/reused |
| --- | ---: | ---: | --- |
| 1 | 72.06 | 147.23 | 29 / 55 |
| 2 | 67.38 | 133.60 | 27 / 57 |
| 3 | 59.58 | 129.20 | 27 / 57 |

Previous baseline immediately before optimization:

| Run | Git context (ms) | Overall scan (ms) |
| --- | ---: | ---: |
| 1 | 132.17 | 205.52 |
| 2 | 127.05 | 192.11 |
| 3 | 123.04 | 187.17 |

Third-run total improved ~31.0%; Git context improved ~51.6%. These are sequential Windows measurements, not rigorous multi-trial controlled results. All scans returned `status=BLOCKED`, a security policy outcome rather than an execution error. Secret cache discovered 84 files, hashed 57; warm runs reused 57 and scanned 27 small files; no skipped/error counters.

The Git context optimization in `pipelineguard/git_context.py` uses `ThreadPoolExecutor(max_workers=3)` to run independent branch, porcelain status and remote queries concurrently after resolving HEAD. Credential-redacted remote output and dirty detection were intended to remain unchanged.

## Important paths

- `pipelineguard/engine.py`: scan orchestration, optional stage and report-substage timings.
- `pipelineguard/git_context.py`: Git commit, branch, dirty and redacted remote context.
- `pipelineguard/secret_cache.py`: content-verified incremental secret cache, 1024-byte threshold.
- `scripts/engine_timing.py`: reproducible offline stage timing.
- `scripts/cache_benchmark.py`: synthetic cold/warm/invalidation secret-cache benchmarks.
- `docs/ENGINEERING_HISTORY.md`: append-only engineering history and all user validation results.
- `docs/NEW_CHAT_HANDOFF.md`: this handoff; update as milestones change.

## Immediate next milestone

1. Inspect the current Git context code and existing tests.
2. Add dedicated regression tests for clean repositories, modified tracked files, untracked files, detached HEAD, non-Git directories and remote URL credential redaction. Preserve existing behavior, including the semantics of porcelain status and remote safety.
3. Commit tests on `feat/v2-engine-integration` and append a detailed entry to `docs/ENGINEERING_HISTORY.md`.
4. Ask user to pull and run `python -m pytest -q` and `python -m scripts.engine_timing` in Windows PowerShell. Record results only after actual validation.
5. Investigate remaining setup and secret-scan overhead only after correctness tests; keep optimizations measurable.

## Workflow expectations

- Work directly on the connected GitHub repository when possible; always confirm commit SHAs and report failed writes truthfully.
- Keep v1.0.0 stable; perform v2 work on the active branch.
- Record successes, failed attempts, benchmark methodology, observed results and known limitations in the engineering history.
- Avoid saying code is tested merely because it was committed; distinguish user-side test results from unverified changes.
- Provide concise PowerShell commands for Windows validation and request outputs.
- Preserve secret/credential safety in reports and repository data.
- User prefers an informal collaborative 'bro/gang' tone and wants autonomous GitHub progress with careful validation.

## Ready-to-run Windows commands

```powershell
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q
python -m scripts.engine_timing
```

## Suggested new-chat opening message

'Continue PipelineGuard v2 development from https://github.com/ibrahim1101/PipelineGuard on branch feat/v2-engine-integration. First read docs/NEW_CHAT_HANDOFF.md and docs/ENGINEERING_HISTORY.md. Our latest Windows validation was 129 passed, 1 skipped; Git context parallelization reduced the third offline scan from 187.17 ms to 129.20 ms. Next, implement dedicated Git-context correctness regression tests, commit them to the v2 branch, and update the engineering journal. Do not touch stable v1.0.0. Give me PowerShell commands to validate each milestone.'


## Updated validation and command-history pointer — 2026-10-08

Latest Windows confirmation: Git-context regression suite **8 passed in 4.77s**; full suite initially **137 passed, 1 skipped** and most recently **136 passed, 2 skipped in 20.03s** (environment-related skips: graphical display and symlink permissions). The ten-run offline Standard benchmark median was **128.78 ms total**, including **61.87 ms Git context**, **31.52 ms secrets**, and **28.19 ms setup**. Benchmark summary feature is validated; optimization not yet claimed. The exact recent PowerShell commands and outcomes are archived in `docs/ENGINEERING_HISTORY.md` under **Windows PowerShell command archive — 2026-10-08**. For each future milestone, append actual commands, results, failures, fixes, and commit hashes.

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_git_context_regression.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Next priority: investigate Git subprocess stage costs with controlled profiling and maintain correctness and credential redaction. Do not modify stable v1.0.0.


## v2.0 scope decision — 2026-10-08

User explicitly decided to consolidate all previously proposed v2.1 work into **v2.0**, with no intermediate v2.1 release planned. Mandatory v2.0 scope now includes the SOC-style desktop redesign, streaming findings, advanced analyzer-result caching, and dependency reachability analysis in addition to the existing v2 engine work. Complete security hardening, cross-platform and desktop validation, packaging, CI, documentation, and release acceptance before tagging v2.0. **v3.0** is reserved for subsequent optimization and further capabilities after v2.0 ships. This is a scope decision, not a claim that the additional features are implemented. Continue appending exact PowerShell commands, validation results, failures, and fixes to the engineering history.
