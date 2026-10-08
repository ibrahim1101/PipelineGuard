# PipelineGuard — Engineering History, Trial-and-Error Log & Test Evidence

**Cutoff:** 8 October 2026  
**Repository:** https://github.com/ibrahim1101/PipelineGuard  
**Stable:** v1.0.0 | **Unreleased v2 branch:** `feat/v2-engine-integration` | **Latest validated commit:** `b03c4699`

> This is a living reference for a future final project report. It is reconstructed from repository commit history, README/CHANGELOG/ROADMAP, observed GitHub Actions results, and PowerShell output supplied during development. It distinguishes observed successes, failures, mitigations, and future work. Test totals are point-in-time results, not cumulative unique tests.

## 1. Project objective and outcome

PipelineGuard is a DevSecOps security scanner and release gate. It detects hardcoded secrets, inventories Python and Node.js dependencies, optionally checks vulnerabilities via OSV, applies release policy and produces CLI/JSON/HTML/SARIF reports. The v1.0.0 milestone delivered a native matte-olive Tk desktop, Docker CLI, standalone Windows executable, and Inno Setup installer. On 7 October 2026, Windows CI validated the EXE build, launch, install, installed launch, uninstall, and artifact upload.

v2 development started on a separate branch without altering the stable release. Implemented foundations include scan profiles, Git context with credential redaction, baseline differences, bounded parallel fingerprinting, content-verified secret-finding cache, adaptive tiny-file strategy, telemetry, and resilience tests. **v2 is not released or merged.** The planned SOC desktop, million-file streaming mode, reachability analysis, broader AppSec intelligence, and v2 packaging remain unfinished or unverified.

## 2. Development timeline: 7 October — v1.0.0

| Evidence | Trial / change | Result and learning |
|---|---|---|
| `6978c6c1`, `ffb65988`, `6aec48f7` | Initial structure, secret scanner, scanner modules | Basic product architecture established. |
| `cee93f8f`, `5efdf7b0`, `f3ce3e6b` | v1 implementation, remove accidentally committed `.venv`, set package version 1.0.0 | Cleaner repository and consistent version. |
| `fba9b1f5`, `b83f8380`, `d45084d1`, `36a240d3` | Fix workflow permissions, SARIF location/upload, and intentional fake-secret test fixtures | CI stopped treating known synthetic fixture findings as unexpected blockers. |
| Workflow #34, `7f89b97d` | Windows job stuck; stale runs cancelled and retried; PR security gate hardened | Timeout, least privilege, PR-safe SARIF, `fail-fast:false`; Windows rerun subsequently passed. |
| `e7f16b58`–`95118740` | Docker/Compose support and build-layout correction | CLI container workflow available. |
| `9f2b1885`, `86af2cd9`, and subsequent UI commits | Matte-olive desktop, search/filter, scorecards, history, details, saved project/config | Usable native interface without browser/server. |
| Windows workflows #3/#4, `4cc5de12` | Hosted Tk `test_desktop_ui.py::test_export_json` hung | Cancelled stuck runs; separated deterministic Windows packaging gate from manual interactive GUI QA. |
| `c7297228`, `d2384cd6`, `f5b3554d`, `32550ead` | Installer workflow, permission fixes, final Windows packaging verification | v1.0.0 EXE/install/launch/uninstall checks passed. |

## 3. Development timeline: 7–8 October — v2

| Commits | Implementation, experiment or failure | Result |
|---|---|---|
| `7e99617d`, `039124a0`, `5caf6845` | Persistent fingerprint cache, bounded worker orchestration and progress | Foundation implemented. Fingerprint cache alone did **not** reuse secret findings. |
| `48be52cb`, `5cf6c5d5`, `1036f18b`, `7b431652` | Ignore generated cache state, scan profiles, Git context, baseline diff | Prevent self-scanning generated data; redact credentials in remote URLs. |
| `80d12696`, `4c1dd818` | Content-verified incremental secret-finding cache | Actual finding reuse introduced; mutation/corruption tests. |
| `f796baac`, `cd34188e`, `09989341` | Tampered entries, file replacement, cache limit changes | Validate cached schema, verify hashes and file metadata, invalidate unsafe cache. |
| `f2a10721`, `e75d6370`, `9b423f7c`, `e67ba0a3` | Benchmark script import failure; unnecessary warm-cache JSON rewrites | Direct script execution fixed; unchanged caches no longer rewritten. |
| `133c3c4e`, `0dea8dcb`, `e070be5e`, `3de89e24` | Tiny-file cache overhead and duplicate scan logic | Scan tiny files directly; share `scan_text` matching code. |
| `d55ff98e` | Optimization reused file bytes on cache miss | **Linux CI failed:** `NameError: content_bytes not defined`. |
| `d172f1f6`, `b8aa0e4e` | Fix undefined bytes/hash, then obsolete `scan_file` test spies | Tests updated to shared `scan_text`; Linux/Windows CI green. |
| `555733ba`, `934188f7`, `f9f88bc2` | Auto-select full scan for tiny-file-heavy repositories | Reduced tiny-file penalty; parity PASS. |
| `991529e1`, `27ce4cb1`, `d9fee6d7`, `d598c816` | Strategy telemetry, sample-threshold tests, cold/modified benchmarks | Better measurements and regression coverage. |
| `574d1504`, `9c261595`, `3f306784` | File grows during read; cache write failure; size-skip counters | Bound binary reads to configured limit+1; failure/telemetry tests. |
| `291a0c5c` | File changes during scanning | Added regular and tiny-file race tests; discard stale scan results. |
| `1e3e798a`, `79a02077`, `772f8fd4`, `b03c4699` | Full scan falsely reported zero processed/discovered | Nullable unknown counters and matching progress event; integration regression test. |

## 4. Failure investigations: symptoms → diagnosis → fix → evidence

### 4.1 Windows workflow stalls
**Symptom:** Windows workflow #34 and hosted GUI packaging runs appeared stuck; some runs cancelled. **Diagnosis:** Interactive Tk file-dialog/export testing can hang in unattended CI, compounded by overlapping runs. **Fix:** Separate fast Windows compatibility/packaging checks from manual GUI tests; set timeouts, harden permissions and cancel superseded jobs. **Evidence:** v1 installer lifecycle and later v2 Windows desktop workflows passed. **Caution:** A cancelled run is not necessarily a code failure.

### 4.2 Synthetic secrets blocked self-scan
**Symptom:** PipelineGuard flagged fake credentials intentionally embedded in test fixtures. **Diagnosis:** Correct scanner detection conflicted with a naive CI gate. **Fix:** Scoped allowlists for intentional fixtures; SARIF upload and gate corrections. **Evidence:** Security workflow passed. **Caution:** Do not suppress genuine credentials globally.

### 4.3 Linux NameError after cache optimization
**Symptom:** `NameError: content_bytes not defined` after `d55ff98e`. **Diagnosis:** Refactor used bytes before initialization. **Fix:** `d172f1f6` initialized content/hash. **Second failure:** test spies still targeted `scan_file` after code switched to `scan_text`. **Fix:** `b8aa0e4e`. **Evidence:** Both CI platforms passed after corrections.

### 4.4 Cache slower for tiny files
**Symptom:** 10,000 two-line files: full 2.3688 s, warm 2.8560 s, speed ratio 0.83×; but 1,000 200-line files: full 0.4419 s, warm 0.2416 s, ratio 1.83×. **Diagnosis:** Hash/metadata/cache overhead exceeds scanning cost for tiny files. **Fix:** Under-1 KiB files use direct scanning; 64-file sample chooses full scan when at least 32 eligible samples and at least 90% are tiny. **Evidence:** Adaptive ratios ~0.98× tiny and ~1.78–1.79× larger. **Limitation:** Heuristic sampling does not guarantee optimal choice for mixed repos.

### 4.5 Cache correctness and race risks
**Risks:** Tampered JSON, same-size/same-mtime file changes, file replacement during scan, cache-write failures, files growing after stat. **Fixes:** SHA-256 verification, strict cached-finding schema, before/after metadata checks, discard changed reads, bound binary reads, tolerate cache write failures. **Evidence:** Added unit/race tests and parity benchmarks. **Limitation:** Not an atomic filesystem snapshot; changes after final check can still occur.

### 4.6 Misleading telemetry
**Symptom:** Full scans returned zero discovered/scanned even though work occurred, and progress events converted unknown processed counts to zero. **Fix:** Report `None` for unavailable counts, retain `reused=0`, and propagate nullable progress fields. **Evidence:** `b03c4699` local test suite and Linux/Windows CI passed. **Outstanding:** Audit every CLI/desktop/report consumer for nullable values.

## 5. Performance measurements — user Windows PowerShell, three rounds each

| Checkpoint | Workload | Full (s) | Warm (s) | Adaptive (s) | Cold (s) | Modified (s) | Adaptive ratio | Parity |
|---|---|---:|---:|---:|---:|---:|---:|---|
| Before selector | 10,000 × 2 lines | 2.3688 | 2.8560 | — | — | — | — | PASS |
| Before selector | 1,000 × 200 lines | 0.4419 | 0.2416 | — | — | — | — | PASS |
| Initial selector | 10,000 × 2 | 1.9860 | 2.3843 | 2.0343 | — | — | 0.98× | PASS |
| Initial selector | 1,000 × 200 | 0.4395 | 0.2348 | 0.2466 | — | — | 1.78× | PASS |
| Extended benchmark | 10,000 × 2 | 1.9782 | 2.3683 | 2.0285 | 2.4011 | 2.3945 | 0.98× | PASS |
| Extended benchmark | 1,000 × 200 | 0.4400 | 0.2368 | 0.2461 | 0.5153 | 0.2436 | 1.79× | PASS |
| Bounded-read update | 1,000 × 200 | 0.4409 | 0.2740 | 0.2758 | 0.5423 | 0.2613 | 1.60× | PASS |

**Interpretation:** Cache creation is slower than a full scan on the tested larger-file dataset; repeated warm scans can pay it back. Tiny-file adaptive selection nearly matches direct scanning. The last ratio decreased from 1.79× to 1.60×, but one run does not prove a regression. The modified-file benchmark changes one file per round, not the entire repository. Benchmarks are synthetic, not production-repository performance guarantees.

## 6. Test history and CI

| Checkpoint | Local result | CI / explanation |
|---|---|---|
| Cache API fix (`b8aa0e4e`) | 112 passed, 1 skipped (reported) | Linux and Windows passed. |
| Selector (`f9f88bc2`) | Two benchmark parity checks PASS | Linux and Windows passed. |
| Extended benchmark (`d598c816`) | 115 passed, 1 skipped; 15.99 s | Linux and Windows passed. |
| Read bounds (`3f306784`) | 116 passed, 2 skipped; 14.90 s | Linux and Windows passed. |
| Repeat (`3f306784`) | 117 passed, 1 skipped; 16.32 s | Expected Windows symlink skip. |
| Race/nullable counts (`1e3e798a`) | 118 passed, 2 skipped; 14.06 s | Linux and Windows passed. |
| Repeat (`1e3e798a`) | 117 passed, 1 skipped; 16.32 s | Expected Windows symlink skip. |
| Latest (`b03c4699`) | **120 passed, 1 skipped; 17.03 s** | **Linux security + Windows desktop passed.** |

**Skip details:** `tests/test_traversal.py:24` skips when Windows symlink creation lacks Developer Mode/elevated privileges. `tests/test_desktop_ui.py:42` can skip when a graphical display is unavailable. Environment-dependent skips explain fluctuating totals; record them instead of assuming test regressions.

**Selected successful GitHub runs:**
- `d598c816`: Linux https://github.com/ibrahim1101/PipelineGuard/actions/runs/37768509793 ; Windows https://github.com/ibrahim1101/PipelineGuard/actions/runs/37768509813
- `3f306784`: Linux https://github.com/ibrahim1101/PipelineGuard/actions/runs/37769911574 ; Windows https://github.com/ibrahim1101/PipelineGuard/actions/runs/37769911586
- `1e3e798a`: Linux https://github.com/ibrahim1101/PipelineGuard/actions/runs/37770859339 ; Windows https://github.com/ibrahim1101/PipelineGuard/actions/runs/37770859268
- **`b03c4699`:** Linux https://github.com/ibrahim1101/PipelineGuard/actions/runs/37771496724 ; Windows https://github.com/ibrahim1101/PipelineGuard/actions/runs/37771496764

## 7. Implementation details and design decisions

1. **Direct scanner:** `scanners/secret_scanner.py` applies shared `scan_text` rules; direct full scan remains parity reference.
2. **Verified cache:** `pipelineguard/secret_cache.py` stores digests and sanitized finding metadata outside the scanned repository; not secret values. Reuse requires verified content and valid finding shape.
3. **Adaptive selection:** sample up to 64 file sizes; tiny-file-heavy repos use direct full scan, otherwise verified incremental cache. Selection is heuristic.
4. **Orchestrator:** `pipelineguard/orchestrator.py` uses bounded pending fingerprint tasks, but retains per-file result/cache maps. This is **not** proof of constant-memory million-file operation.
5. **Engine:** `pipelineguard/engine.py` coordinates profiles, dependencies, OSV, secrets, baseline, policy and progress. Full-scan per-file counters are nullable because not measured.
6. **Interfaces:** native Tk desktop, CLI, CI. Planned v2 SOC workspace is a roadmap item, not a shipped feature.

## 8. Release-readiness status at cutoff

| Gate | Status | Reason |
|---|---|---|
| v1.0.0 preserved | VERIFIED | Separate stable release. |
| v2 local unit/integration tests | VERIFIED at `b03c4699` | 120 passed, 1 expected skip. |
| Linux security CI | VERIFIED | Run 37771496724 passed. |
| Windows desktop CI | VERIFIED | Run 37771496764 passed. |
| Cache corruption/race fixtures | VERIFIED for covered cases | Dedicated tests. |
| Benchmark parity | VERIFIED for synthetic fixtures | All supplied runs PASS. |
| Nullable metrics consumer audit | INCOMPLETE | Need review of all CLI/desktop/report consumers. |
| Production workload profiling | INCOMPLETE | Synthetic samples only. |
| Million-file memory target | UNVERIFIED | Roadmap milestone. |
| v2 desktop redesign and packaging | UNVERIFIED | Release work remains. |
| Manual v2 GUI acceptance | UNVERIFIED | CI does not replace physical UI testing. |
| v2 merge/release | NOT DONE | Keep development branch isolated. |

## 9. Final project report guidance

Suggested report chapters: problem statement, objectives, threat model, requirements, architecture, v1 build, v2 improvements, experimental setup, chronological trials and errors, quantitative results, regression/CI evidence, limitations, conclusion and future work.

**Preserve evidence:** commit hashes, release tag, installer checksum, failed/successful job logs, screenshots, PowerShell benchmark outputs, hardware/Python versions, synthetic fixtures, UI manual QA notes, and a feature-to-test traceability matrix. Never include real API keys or secrets.

**Do not overclaim:** synthetic parity is not universal secret detection; content hashes do not create atomic filesystem snapshots; hosted Windows packaging does not prove interactive GUI correctness; roadmap features are not delivered capabilities; v2 is not released.

## 10. Source register and reproduction

- Git history: https://github.com/ibrahim1101/PipelineGuard/commits/feat/v2-engine-integration/
- README: https://github.com/ibrahim1101/PipelineGuard/blob/feat/v2-engine-integration/README.md
- CHANGELOG: https://github.com/ibrahim1101/PipelineGuard/blob/feat/v2-engine-integration/CHANGELOG.md
- ROADMAP: https://github.com/ibrahim1101/PipelineGuard/blob/feat/v2-engine-integration/ROADMAP.md
- CI: https://github.com/ibrahim1101/PipelineGuard/actions
- Benchmark: `scripts/benchmark_v2_secret_cache.py`
- Regression tests: `tests/test_v2_secret_cache.py`, `tests/test_v2_scan_races.py`, `tests/test_v2_scan_races_tiny.py`, `tests/test_v2_engine.py`

```powershell
git checkout feat/v2-engine-integration
git pull
python -m pytest -rs -q
python scripts/benchmark_v2_secret_cache.py --files 10000 --lines 2 --rounds 3
python scripts/benchmark_v2_secret_cache.py --files 1000 --lines 200 --rounds 3
```

**Document version:** 1.0, 8 October 2026. Append dated milestone entries as work continues; preserve failures and superseded measurements rather than rewriting history.

## Ongoing engineering journal — append new entries below

This section is deliberately editable. Preserve past failures and test outputs even after a bug is fixed. When a result is uncertain, label it **unverified** rather than assuming success. For continuity across chats, see [NEW_CHAT_HANDOFF.md](NEW_CHAT_HANDOFF.md).

### Reusable milestone / experiment entry

Copy this template for each meaningful experiment, feature, regression or release milestone:

```markdown
### YYYY-MM-DD — Short descriptive title
- **Goal / hypothesis:**
- **Branch / commit(s):**
- **Environment:** OS, Python version, relevant tool versions
- **Change attempted:**
- **Commands / reproduction steps:**
- **Expected result:**
- **Observed result:** include exact error or measurement where possible
- **Outcome:** PASS / FAIL / SKIP / PARTIAL / NOT VERIFIED
- **Root cause / analysis:** confirmed vs suspected
- **Fix / workaround:** including unsuccessful attempts
- **Retest / evidence:** CI URLs, test totals, screenshots, benchmark output
- **What we learned:**
- **Open follow-ups / risks:**
```

### 2026-10-08 — Documentation continuity and new-chat handoff

- **Goal:** Preserve both successful and unsuccessful development work for future reports, learning and chat continuity.
- **Change:** Established this Markdown file as the version-controlled, append-only engineering journal; created `docs/NEW_CHAT_HANDOFF.md` for fresh-chat onboarding.
- **Outcome:** Documentation changes committed to the v2 development branch. No additional product test result is claimed for this documentation-only milestone.
- **Lesson:** Durable repository documentation is more reliable than relying on a single long chat history.
