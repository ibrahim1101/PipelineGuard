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

## 11. Continuation audit — 8 October 2026 (new chat)

**Goal:** Re-establish the verified checkpoint and audit nullable secret telemetry consumers before further v2 changes.

**Observed:** Read `docs/NEW_CHAT_HANDOFF.md`, this journal, `README.md`, `ROADMAP.md`, `pipelineguard/engine.py`, `pipelineguard/main.py`, `pipelineguard/desktop.py`, and `pipelineguard/secret_cache.py` from `feat/v2-engine-integration` through the GitHub connector. The handoff records code commit `b03c4699` as last verified (120 passed, 1 skipped; prior Linux and Windows CI successful). These are historical results, **not fresh tests**. The GitHub commit-workflow lookup for `b03c4699` returned no PR-triggered runs; this endpoint filters PR events and is insufficient to disprove the documented successful workflow URLs. Fetching `.github/workflows` as a file failed because it is a directory. Fetching `tests/test_engine.py` returned 404; test file location needs discovery.

**Consumer audit (source inspection, partial):** `engine.py` uses nullable `discovered`, `hashed`, `scanned`, and skip counters for full strategy; the progress event avoids adding `None` by checking `scanned is not None`. `main.py` does not numerically aggregate `secret_cache` telemetry, and `desktop.py` currently invokes `run_scan` without a profile or progress callback, so these two inspected interfaces do not exhibit a nullable-counter arithmetic failure. `secret_cache.py` incremental counters remain integers. Report writer, test consumers, external integrations and workflow definitions remain to be audited; absence of an issue in inspected files is not a whole-repository guarantee.

**Verification:** Read-only GitHub source inspection. No new code tests, benchmarks, Windows manual QA, CI run, or packaging validation performed during this checkpoint. No v1.0.0 changes. **Lesson:** Preserve unknown telemetry as null rather than misrepresenting it as zero, and distinguish source review from executed verification. **Next:** discover report writer and test consumers, add explicit nullable-telemetry contract regressions if needed, run local and CI checks, then record outputs and links.

## 12. Nullable telemetry exporter regression — 8 October 2026

**Objective:** Extend release-readiness coverage beyond engine-level nullable counters to report serialization.

**Observed source review:** `pipelineguard/reporting.py` JSON writer uses `json.dumps`, which serializes Python `None` to JSON `null`. HTML and SARIF exporters consume findings/status rather than performing arithmetic on `secret_cache` counters. Existing `tests/test_v2_engine.py` checks nullable full-scan counters and progress events but does not exercise all three exporters together. No crash was reproduced; this is preventive regression coverage.

**Change:** Added `tests/test_v2_telemetry_reports.py` at commit `9f7c0a70ba463905a0f5660e21255eea00f9d2f9`. It creates 40 tiny files to select the full strategy, checks unknown counters remain `None`, confirms `reused=0`, exports JSON/HTML/SARIF, verifies JSON round-trip retains null values, and verifies basic HTML/SARIF output contracts. Uses offline intelligence and isolated cache paths.

**Verification status:** Test committed but **not executed locally** through the GitHub connector. No fresh pytest pass, CI pass, performance number, or packaging result is claimed. Check GitHub Actions and run `python -m pytest -rs -q` before marking verified. **Lesson:** Test the output boundary, not only engine internals, while distinguishing untested code from validated fixes. **Remaining:** CI verification, broader consumer audit, Windows manual GUI acceptance and large-repository profiling. Stable v1.0.0 untouched.

## 13. Desktop configuration discoverability — 8 October 2026

**User-reported usability gap:** The desktop displays “Configuration (Optional)” but provides no guidance on the file contents or supported keys. This prevented even the project owner from knowing how to use it.

**Source audit:** Read `pipelineguard/config.py` and `pipelineguard/desktop.py` directly. Confirmed seven accepted JSON keys: `ignored_directories`, `max_file_size`, `fail_on_warning`, `allowlist`, `minimum_score`, `blocked_rules`, `block_advisory_severity`. Confirmed the desktop selects a JSON path explicitly, not automatically, and that allowlisting is rule/file/optional-line matching.

**Changes:** Added `docs/CONFIGURATION.md` (commit `bbd16c94`), `examples/pipelineguard.example.json` (commit `3751f4c0`), and desktop '?' help dialog plus copyable sample (commit `b05a7f08`). Updated README with links and CLI usage. Default scanner behavior and stable v1.0.0 remain unchanged. The example uses an empty allowlist to avoid suppressing genuine findings.

**Verification:** GitHub writes succeeded. No local Tk GUI execution, automated test run, Windows packaging, or fresh CI result has yet been observed for this change; mark it **implemented, pending validation**, not tested. **Lesson:** Exposing optional expert settings without discoverable documentation is a UX defect; ensure help text reflects the actual parser rather than the roadmap. **Next:** Run pytest, open the '?' window on Windows, verify copy-to-clipboard, select a valid sample, and confirm invalid JSON produces a clear error. Record pass/fail evidence.

## 14. User-reported Windows pytest checkpoint — 8 October 2026

**Evidence:** User ran `git pull origin feat/v2-engine-integration` from `C:\Users\ibrah\PipelineGuard`, fast-forwarding local checkout from `b03c469` to `b2d62c2`. They then ran `python -m pytest -rs -q` and reported **121 passed, 1 skipped in 18.36s**, with no failures. The skip was `tests/test_traversal.py:24`: Windows symlink creation requires Developer Mode or elevated privileges.

**Scope:** This validates the newly committed `tests/test_v2_telemetry_reports.py` alongside the existing suite **at the local checkout `b2d62c2`**, not the later configuration-help commits. The new desktop '?' help, README links and example JSON were committed subsequently and remain **pending local Windows GUI/pytest validation**.

**Lesson:** Always capture the exact pulled commit and test totals. A passing suite on an older checkout must not be used as evidence that later UI changes work. Next step: pull latest branch, rerun tests, open desktop, inspect help and clipboard action, and select the example config. Stable v1.0.0 unchanged.

## 15. Configuration-help Windows automated test checkpoint — 8 October 2026

**User-supplied observed commands:** From `C:\Users\ibrah\PipelineGuard`, `git pull origin feat/v2-engine-integration` fast-forwarded local checkout from `b2d62c2` to `2a3d203`, bringing in `docs/CONFIGURATION.md`, `examples/pipelineguard.example.json`, the desktop '?' help and README updates. The user ran `python -m pytest -rs -q`.

**Observed result:** **121 passed, 1 skipped in 18.57s**, no failures. Expected skip: `tests/test_traversal.py:24`, Windows symlink creation requires Developer Mode or elevated privileges. The user also entered `python -m pipelineguard.desktop`; no screenshot, GUI behavior, or subsequent outcome has been supplied yet.

**Interpretation:** Automated regression suite passed on configuration-help code at `2a3d203`. **Manual GUI acceptance remains unverified:** '?' button visibility, dialog layout, copy-example clipboard, selecting sample JSON and scan behavior. Also, no dedicated automated Tk dialog test is claimed. **Lesson:** Distinguish process invocation and passing non-GUI tests from actual GUI usability verification. Stable v1.0.0 untouched.

## 16. Configuration help manual GUI confirmation — 8 October 2026

**User-reported observation:** After launching `python -m pipelineguard.desktop` on Windows, the user confirmed that the desktop opened and the new '?' configuration-help dialog displayed correctly. This supplements the 121-passed/1-skipped pytest run at local checkout `2a3d203`.

**Verification scope:** Desktop startup and '?' help dialog visibility are **manually confirmed**. Copy-example clipboard contents, sample configuration selection, and actual scan completion **have not yet been reported**. No new automated test or packaging claim is made. Stable v1.0.0 untouched.

**Next acceptance checks:** Copy the example into an editor, select `examples/pipelineguard.example.json`, scan a chosen project, and report the outcome. Record failures or successes as observed.

## 17. Configuration-guided scan acceptance — 8 October 2026

**Manual Windows acceptance, user-reported:** Following the 121-passed/1-skipped pytest run on checkout `2a3d203`, the user confirmed the desktop and '?' configuration-help dialog opened correctly. After instructions to use the sample configuration (`examples/pipelineguard.example.json`) for a project scan, the user reported **"haha it worked"**.

**Result:** User confirms the guided configuration workflow worked and the configured scan succeeded. This is a **user-reported manual success**, not a captured application log or automated test. Clipboard example copying was part of the suggested steps, but no independent detailed output was supplied; do not claim byte-for-byte clipboard verification. No new benchmark or packaging evidence. **Lesson:** In-app discoverable documentation and a real selectable example eliminate uncertainty around advanced options; validate UX through both automated regressions and physical Windows acceptance.

**Remaining:** Broader v2 engine roadmap, dedicated UI regression automation where feasible, packaging/installer acceptance for the v2 branch. Stable v1.0.0 untouched.

## 18. v2 desktop profile, progress and cache UI — 8 October 2026

**Objective:** Surface already-implemented engine scan profiles, progress events and cache metrics to desktop users. Previously `pipelineguard/desktop.py` called `run_scan` without a profile or progress callback; the UI displayed only an indeterminate progress bar.

**Source audit:** Confirmed `pipelineguard/profiles.py` has five profiles (Quick, Standard, Deep, Release, Forensic); `pipelineguard/engine.py` emits `ProgressEvent` and `secret_cache` telemetry for Quick/Standard/Deep; full strategy reports unknown counters as `None`. Quick explicitly disables online intelligence through the profile, independent of checkbox selection.

**Implementation:** Commit `29c78107` adds a read-only profile selector, sends worker-thread progress events to the existing Tk queue, renders stage labels and fingerprint processed/discovered/cached counters, and shows final secret-cache strategy/scanned/reused metrics. Unknown counters are labeled “unknown” rather than misleadingly zero; Release/Forensic indicate metrics unavailable. The progress bar remains indeterminate because scan stages lack a trustworthy overall percentage.

**Status:** GitHub commit created; **no fresh pytest, Windows GUI, or installer validation yet**. Verify stage updates, all five profiles, checkbox semantics, error handling and small-window layout. In particular, confirm the increased controls fit the 900px minimum window width. Stable v1.0.0 untouched. **Lesson:** UI progress must respect nullable telemetry and marshal worker events through the main Tk thread.

## 19. Advisory alias grouping and HTML report usability — 8 October 2026

**Observed input:** User-provided Standard JSON and HTML output for a deliberately vulnerable sample project showed one secret finding and four OSV advisory records for requests 2.32.3, with apparent overlapping GHSA and PYSEC identifiers. HTML's file and line columns were empty for dependency findings. The report did not expose the selected scan profile in HTML.

**Changes (v2 branch only):** Added `deduplicate_advisories` to `scanners/osv_scanner.py`, merging advisories only when explicit OSV aliases or identical identifiers overlap within the same package and version. Preserves merged aliases, references, fixed versions and severity; unlinked findings remain separate. Added package/version, advisory IDs, location and remediation to HTML findings table, plus aliases in JSON-derived HTML details and SARIF properties. Added `tests/test_advisory_dedup.py` for alias grouping, distinct findings and HTML columns.

**Commits:** `d323d2fe` (scanner), `a7310b1b` (HTML), `2e6f2d79` (tests). **Status:** Changes pushed but new Windows pytest and real OSV acceptance are not yet reported. Live OSV alias metadata varies; whether the sample collapses from four to two findings must be verified by rescanning, not assumed. **Potential follow-up:** HTML profile label and improved handling of transitive alias chains. Stable v1.0.0 untouched.

## Windows validation checkpoint — 8 October 2026

User reported running `python -m pytest -rs -q` after the advisory grouping and HTML reporting updates. Result: **124 passed, 1 skipped in 18.83s**. The skip was `tests/test_traversal.py:24`, requiring Windows Developer Mode or elevated privileges for symlink creation. No test failures were reported. The uploaded updated HTML report separately showed three findings rather than five, with two dependency advisory groups, preserved alias identifiers, improved remediation columns, and status BLOCKED. These are user-provided validation results; the HTML file does not establish which scan profile was selected. Stable v1.0.0 was not modified.

## Reporting metadata Windows acceptance — 2026-10-08

Implemented UTC `scanned_at` in engine reports and HTML profile/timestamp labels plus readable advisory summaries and expandable details. Commits: `e60e95af`, `25030db5`, `dba6e35e` (two regression tests). User-provided `deep_1.html` confirms profile `deep`, UTC timestamp, two grouped dependency advisories, readable summaries, and expandable HTML markup. User subsequently ran `python -m pytest -rs -q` on Windows: **126 passed, 1 skipped in 18.21s**, zero failures. The sole skip was `tests/test_traversal.py:24` because Windows symlink creation needs Developer Mode or elevated privileges. Browser clicking of details sections was not independently verified. Status: **reporting metadata milestone accepted on Windows**, v2 branch only; stable v1.0.0 unchanged.

## Incremental cache verification upgrade — 8 October 2026

**Investigation:** Prior Deep JSON reported 3 discovered, 3 scanned, 0 hashed and 0 reused. Inspection of `pipelineguard/secret_cache.py` showed that files smaller than `MIN_CACHE_BYTES = 1024` are intentionally rescanned without hashing or cache storage. Therefore the previous report cannot demonstrate warm-cache reuse or a defect.

**Changes:** HTML reports now display secret-cache strategy, discovered, scanned, reused, hashed and skip counters, and explain the tiny-file exception (commit `acf8d803`). Added `tests/test_incremental_cache_acceptance.py` with isolated cache-directory tests for a larger file's cold scan, warm reuse, invalidation after content modification, small-file direct scanning and HTML telemetry (commit `27146231`).

**Verification status:** Changes committed to v2; Windows pytest and generated HTML acceptance still pending. Previous confirmed suite: 126 passed, 1 skipped. Stable v1.0.0 untouched.

## Windows cache acceptance — 2026-10-08

**Environment:** Windows PowerShell; `git pull origin feat/v2-engine-integration` fast-forwarded to `e6e913f` and added `scripts/cache_benchmark.py`. User ran `python -m scripts.cache_benchmark` successfully with a 40-file synthetic project.

| Phase | Discovered | Hashed | Scanned | Reused | Skipped (size/changed/error) |
|---|---:|---:|---:|---:|---|
| Cold | 40 | 40 | 40 | 0 | 0/0/0 |
| Warm | 40 | 40 | 0 | 40 | 0/0/0 |
| Modified one file | 40 | 40 | 1 | 39 | 0/0/0 |

**Outcome:** Content-verified cache reuse and single-file invalidation validated on Windows. All files are still hashed to establish trust; warm reuse avoids rerunning the secret analyzer, not disk I/O. The script reports counters but **does not measure wall-clock duration**, so no speedup claim is justified. Prior pytest checkpoint: 128 passed, 2 skipped in 18.79s (graphical display unavailable; Windows symlink permissions). Next: add timed measurements and test larger real-world-like workloads, without altering stable v1.0.0.

## Timed cache benchmark instrumentation — 2026-10-08

Updated `scripts/cache_benchmark.py` in commit `35c5cb5` to record elapsed milliseconds for cold, warm and single-file-modified scans using `time.perf_counter()`, and print the cold/warm duration ratio. Prior correctness results were validated on Windows (40/0, 0/40, 1/39 scanned/reused). **Timing results are pending user execution**; this small synthetic benchmark is illustrative and cannot alone establish representative real-world speedups. Next: run benchmark repeatedly on Windows, compare timings, and consider larger workloads if necessary.
