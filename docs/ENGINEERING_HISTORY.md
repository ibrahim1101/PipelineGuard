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

## First timed cache benchmark — Windows, 2026-10-08

User pulled v2 through `5d79af6` and executed `python -m scripts.cache_benchmark` on Windows PowerShell. **Observed single-run synthetic timings:** cold **31.14 ms** (40 scanned, 0 reused), warm **10.68 ms** (0 scanned, 40 reused), modified **12.77 ms** (1 scanned, 39 reused). Every phase hashed all 40 files; all skip/error counters were zero. Printed cold/warm ratio: **2.92x**. This is a single, 40-file synthetic benchmark, not a reproducible or representative speedup claim. Repeat runs and larger workloads are needed before any optimization conclusion. The baseline remains v2 development only; stable v1.0.0 unchanged.

## Repeated median cache benchmarking — 2026-10-08

Upgraded `scripts/cache_benchmark.py` in commit `5ca5542` to benchmark independent synthetic projects with configurable file counts (`--files`, default 40 and 400) and trials (`--trials`, default 5). Each trial checks cold/warm/one-file-modified correctness, records elapsed milliseconds, and prints median cold, warm and modified durations plus median cold/warm ratio. The benchmark uses temporary directories and an isolated cache. **Windows measurements for this new repeated benchmark are pending.** Interpret median timing ratios as workload-specific rather than general production speedups.

## Repeated Windows synthetic cache benchmark acceptance — 2026-10-08

User ran `python -m scripts.cache_benchmark` (40 and 400 files, five trials) and `python -m scripts.cache_benchmark --files 40 200 --trials 3` on Windows PowerShell after pulling commit `47f4955`. Reported medians:

| Files | Trials | Cold ms | Warm ms | One-file-modified ms | Cold/warm ratio |
|---|---:|---:|---:|---:|---:|
| 40 | 5 | 30.98 | 11.30 | 13.39 | 2.74x |
| 400 | 5 | 285.96 | 104.43 | 107.08 | 2.74x |
| 40 | 3 | 31.40 | 11.00 | 13.55 | 2.85x |
| 200 | 3 | 145.39 | 52.23 | 63.77 | 2.78x |

Every cold run scanned all files; every warm run reused all files after hashing; each modified run scanned exactly one file and reused the rest. No skipped size/changed/error events were reported. **Conclusion:** Repeated synthetic secret-cache benchmark confirms correct invalidation and workload-specific warm-run improvements. **Limitation:** This is not an end-to-end engine benchmark or proof of the same speedup for real projects; OSV/network latency, dependency scanning, filesystem variability and differing file contents are not represented. No further cache optimization should be assumed necessary without broader profiling. Stable v1.0.0 untouched.

## First real-project end-to-end offline engine timing — 2026-10-08

User executed three consecutive `run_scan(Path.cwd(), online=False, profile="Standard")` runs from the PipelineGuard repository on Windows PowerShell. Observed wall-clock totals: **238.25 ms** first, **197.86 ms** second, **196.03 ms** third (third ~17.7% below first). All returned `status=BLOCKED`, which is a policy result, not a Python exception. Secret cache: all three discovered 83 files and hashed 56; first scanned 83 and reused 0, while second/third scanned 27 and reused 56; no skipped-size/changed/error counts. `strategy=incremental` throughout. The 27 consistently scanned files are consistent with small-file direct scanning. These timings include the offline Standard-profile engine workflow but **exclude online OSV network time**. Only three sequential runs were measured; no stage breakdown or statistical confidence claim. Next step: profile per-stage timings and determine where additional improvements matter. Stable v1.0.0 remains unchanged.

## Optional per-stage scan timing — 2026-10-08

Implemented optional `timings` dictionary parameter on `pipelineguard.engine.run_scan` in commit `2e6e89c`. The engine populates `setup_ms`, `dependencies_ms`, `osv_ms`, `secrets_ms`, `report_ms` and `total_ms` using `time.perf_counter()` when requested. Existing calls remain valid without the parameter; scan semantics and stable v1.0.0 are unchanged. These measurements are pending user-side Windows execution and regression testing. The setup phase includes optional fingerprint processing; offline OSV stage includes the offline fallback rather than network requests. Next: validate per-stage measurements on the real project and compare with the earlier 238.25/197.86/196.03 ms baseline.

## Reusable end-to-end profiler and regression commands — 2026-10-08

Created `scripts/engine_timing.py` in commit `6f8568f`. It accepts an optional project path, `--runs` (default 3), and `--profile` (default Standard), calls `run_scan(..., online=False, timings=...)`, and prints individual stage durations plus cache counters. It replaces the previously chat-only PowerShell here-string profiling command with a version-controlled script. **Previous step:** the optional engine timing parameter was added in commit `2e6e89c`, and its implementation was documented in `55471d2`. An earlier attempt to add profiling instrumentation and a profiling script was blocked by GitHub safety checks; those attempts made no commit. The real-project pre-instrumentation timing baseline (238.25, 197.86, 196.03 ms; 83 files, 56 reused warm) was already recorded in commit `a436aa7`. 

Windows validation commands: `git pull origin feat/v2-engine-integration`, `python -m scripts.engine_timing`, and `python -m pytest -q`. New per-stage output and current regression results are **pending**; do not record them as passing until the user provides results. All changes remain on v2 development branch, not stable v1.0.0.

## Windows end-to-end stage profiling and regression validation — 2026-10-08

User pulled `feat/v2-engine-integration` through commit `17a9ff5` and ran `python -m scripts.engine_timing` against the PipelineGuard repository (offline Standard profile). Results (milliseconds):

| Run | Setup | Dependencies | Offline OSV | Secrets | Report stage | Total | Scanned / reused |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 30.82 | 7.30 | 0.00 | 41.50 | 119.10 | 198.72 | 30 / 54 |
| 2 | 27.62 | 6.79 | 0.00 | 27.16 | 106.33 | 167.91 | 27 / 57 |
| 3 | 27.44 | 6.83 | 0.00 | 32.50 | 116.59 | 183.36 | 27 / 57 |

Each run discovered 84 files, hashed 57, and returned `status=BLOCKED` (policy result); skipped size/changed/error all zero. First run rescanned three formerly cached eligible files after repository changes; later runs reused all 57 eligible files. Report-stage timing currently includes `build_report`, policy evaluation, metadata, optional Git context and baseline handling; it is **not** a measurement of HTML serialization alone. This stage dominated measured time (~63% in run 2) and merits substage investigation before optimization. Online OSV network latency is excluded.

**Regression check:** User ran `python -m pytest -q` and observed **129 passed, 1 skipped in 25.19s**, zero failures. Skip reason not confirmed in this run. These are user-provided Windows results, not CI confirmation. Next: isolate report construction vs Git context/policy before modifying behavior; preserve stable v1.0.0.

## Report-stage timing decomposition — 2026-10-08

After Windows stage profiling showed `report_ms` at 119.10, 106.33, and 116.59 ms across three offline Standard scans, instrumented `pipelineguard/engine.py` in commit `9f3cf21` to emit opt-in `report_build_ms`, `git_context_ms` (when the profile collects Git context), and `report_other_ms` (remainder of report stage) alongside existing `report_ms`. This isolates report construction from Git metadata work without changing security findings or existing public call behavior. **User-side validation and regression results for this change are pending**. Next: rerun `python -m scripts.engine_timing` and `python -m pytest -q`, then optimize only the measured bottleneck.

## Git-context bottleneck confirmed — Windows validation, 2026-10-08

User pulled through commit `51c8f99`, ran `python -m scripts.engine_timing` (offline Standard profile) and `python -m pytest -q` on Windows PowerShell. Timings (ms):

| Run | Setup | Dependencies | Secrets | Report build | Git context | Report total | Other report | Overall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 29.34 | 7.89 | 36.07 | 0.01 | 132.17 | 132.21 | 0.03 | 205.52 |
| 2 | 29.15 | 7.60 | 28.27 | 0.01 | 127.05 | 127.08 | 0.02 | 192.11 |
| 3 | 28.34 | 7.50 | 28.24 | 0.01 | 123.04 | 123.08 | 0.02 | 187.17 |

Offline OSV reported 0.00 ms. Cache: 84 discovered, 57 hashed each run; scanned/reused 29/55 then 27/57 and 27/57; all skip/error counters zero. Git context occupied ~65.7% of third scan, while `build_report` was effectively negligible. **Conclusion:** prior broad `report_ms` bottleneck was Git context collection, not report generation. `status=BLOCKED` is the security policy result. **Regression:** `129 passed, 1 skipped in 22.55s`, zero failures. Next: inspect `pipelineguard/git_context.py` and reduce Git command overhead without losing correctness; run before/after benchmarks. Stable v1.0.0 unchanged.

## Git context concurrent-query optimization — 2026-10-08

Earlier attempts to update `pipelineguard/git_context.py` were blocked by GitHub write safety checks, with no changes committed. User requested retry; successful commit `f4ecb50` parallelized the independent branch, porcelain status, and origin remote Git queries using `ThreadPoolExecutor(max_workers=3)` after resolving HEAD. Existing field names, dirty detection (including untracked files), and remote redaction logic were retained. **Performance improvement is hypothetical pending Windows validation** against the prior ~123–132 ms `git_context_ms` baseline; regression tests also pending. Test using `python -m scripts.engine_timing` and `python -m pytest -q` after pulling v2. Stable v1.0.0 unchanged.

## Windows validation: concurrent Git metadata optimization — 2026-10-08

User pulled through `2d4c7ee` and ran `python -m scripts.engine_timing` and `python -m pytest -q` on Windows PowerShell. Offline Standard-profile results after parallel Git context reads:

| Run | Setup ms | Dependencies ms | Secrets ms | Report build ms | Git context ms | Report total ms | Overall ms | Secret scanned/reused |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 30.98 | 7.75 | 36.38 | 0.02 | 72.06 | 72.11 | 147.23 | 29 / 55 |
| 2 | 29.11 | 7.81 | 29.25 | 0.01 | 67.38 | 67.42 | 133.60 | 27 / 57 |
| 3 | 28.46 | 7.34 | 33.78 | 0.01 | 59.58 | 59.61 | 129.20 | 27 / 57 |

Each run discovered 84 files, hashed 57; zero skipped_size, skipped_changed, or skipped_error. All runs returned policy `BLOCKED`, not an execution error; OSV offline stage 0.00 ms. Compared with immediately preceding serial Git baseline, Git context improved 132.17→72.06 ms (run 1), 127.05→67.38 ms (run 2), 123.04→59.58 ms (run 3), or ~45.5%, ~47.0%, ~51.6% reductions. Total scan time improved 205.52→147.23 ms (~28.4%), 192.11→133.60 ms (~30.5%), 187.17→129.20 ms (~31.0%). These are three sequential single-machine offline measurements, not a controlled multi-trial statistical benchmark or online OSV measurements. **Regression validation:** `129 passed, 1 skipped in 20.52s`, zero failures; skip reason not verified in this run. Optimization accepted provisionally on observed results; further Git status and subprocess work should retain dirty/untracked accuracy, credential redaction, and regression coverage.

## New-chat handoff refreshed — 2026-10-08

Updated `docs/NEW_CHAT_HANDOFF.md` in commit `0d82d89` with current v2 state, Windows test and benchmark results, code entry points, known limitations, immediate Git-context correctness testing milestone, validation commands, and a ready-to-paste new-chat opening prompt. This is documentation-only; no application logic changed. Future work should update both the handoff and this append-only journal as appropriate.


## Git-context regression milestone — 2026-10-08 (awaiting Windows validation)

Commit `27d86996d5ddcf9e1fab3779c150eb6e64240c91` added `tests/test_git_context_regression.py` on `feat/v2-engine-integration` only. Eight parametrized test cases exercise clean repositories, modified tracked files, untracked files, detached HEAD, non-Git directories, HTTPS credential/query/fragment redaction, SCP-style SSH remotes and ambiguous multi-segment remote paths. The tests use temporary Git repositories and do not alter application runtime code or stable v1.0.0. Existing Git-context tests were inspected before authoring. The first attempt to retrieve this journal through the generic GitHub fetch endpoint as JSON failed because the endpoint returned Markdown; recovery used the typed fetch_file action. **Validation status:** tests committed but not yet executed on Windows; do not count them as passing until user supplies actual pytest output. Run `python -m pytest -q tests/test_git_context_regression.py`, `python -m pytest -q`, and `python -m scripts.engine_timing`. Record failures and measurements after execution.


## Windows regression validation — 2026-10-08

The user pulled development head `d024fad` and ran the new Git-context tests on Windows PowerShell: **8 passed in 4.77s**. The complete suite reported **137 passed, 1 skipped in 24.79s**; skip reason not yet inspected. No failing tests were reported.

Offline Standard-profile engine timing results (milliseconds): run 1 setup 35.91, dependencies 7.89, secrets 38.49, Git context 74.22, total 156.60; run 2 setup 33.08, dependencies 7.84, secrets 38.83, Git context 72.80, total 152.59; run 3 setup 31.91, dependencies 7.55, secrets 35.41, Git context 68.79, total 143.70. OSV network latency was excluded (offline). All three scan statuses were `BLOCKED` as security-policy results, not execution errors. Secret cache: 85 files discovered per run, 58 hashed; scanned/reused counts were 30/55, 27/58, 27/58; no skipped-size/changed/error files.

Compared with earlier three-run totals (147.23, 133.60, 129.20 ms), these new totals are higher; the working tree changed and these are not controlled paired measurements, so no performance gain is claimed. Next: gather 10-run timing data, inspect the single pytest skip using `python -m pytest -q -rs`, and investigate setup and secret scanning without compromising detection coverage.

Documentation failure and recovery: first attempt to record this milestone was blocked by a safety check before a GitHub commit was confirmed. This entry is the retry; the preceding failure is retained as part of the engineering record.


## Ten-run Windows performance validation — 2026-10-08

The user pulled commit `7bde773` and ran `python -m scripts.engine_timing --runs 10 --summary` successfully. All ten offline Standard-profile scans returned policy status `BLOCKED` without execution errors. Median stage times in milliseconds: setup 28.19 (range 27.22–29.95), dependencies 7.21 (6.99–7.58), secrets 31.52 (28.41–36.57), Git context 61.87 (60.97–66.35), total 128.78 (126.67–138.14). OSV network latency was excluded. Git context is the largest measured stage; further changes need controlled A/B testing and preserved redaction and dirty-state correctness. Secret-cache counts: 85 discovered and 58 hashed on every run; run 1 scanned/reused 29/56, runs 2–10 27/58; no skipped-size/changed/error files.

`python -m pytest -q -rs` returned **136 passed, 2 skipped, 0 failed in 20.03s**. The skips were `tests/test_desktop_ui.py:42` (graphical display unavailable) and `tests/test_traversal.py:24` (Windows symlink creation requires Developer Mode or elevated privileges). The earlier 137 passed/1 skipped result differed by one environment-dependent skip, not by any reported failure. Benchmark summary feature is now validated on Windows. No runtime optimization or speedup is claimed by this documentation milestone.


## Windows PowerShell command archive — 2026-10-08

This section preserves the exact command sequences used or requested in the latest Git-context regression and performance milestones. Commands are intended for PowerShell in the local Windows checkout. Earlier historical milestones remain in this append-only journal; where an exact older command was not recorded, do not reconstruct it as if executed.

### Pull and identify development branch

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
git log -1 --oneline
```

### Git-context regression validation (user confirmed: 8 passed)

```powershell
python -m pytest -q tests/test_git_context_regression.py
python -m pytest -q
python -m scripts.engine_timing
```

User-observed output: 8 passed in 4.77s; full suite 137 passed, 1 skipped in 24.79s; three-run offline timing total 156.60, 152.59, 143.70 ms.

### Benchmark summary milestone (user confirmed)

```powershell
python -m scripts.engine_timing --runs 10 --summary
python -m pytest -q -rs
```

User-observed output: ten-run median total 128.78 ms, median Git context 61.87 ms; full suite 136 passed, 2 skipped in 20.03s. Skip reasons: no graphical display; Windows symlink privileges unavailable.

### Upcoming Git subprocess investigation (not yet run)

```powershell
git status --porcelain
git rev-parse HEAD
git branch --show-current
git config --get remote.origin.url
python -m scripts.engine_timing --runs 10 --summary
```

**Security note:** The last command reading remote.origin.url may print credentials if the remote URL embeds them. Do not paste its raw output into chats or logs; redact usernames, tokens, and passwords first. Prefer using the application's redacted Git context for shared diagnostics.

Future milestones must append the exact Windows validation commands alongside observed results, failures, fixes, and commit identifiers.


## Git subprocess timing diagnostic — 2026-10-08

Commit `b551117eed375b2e48e10c753538f344736e5184` added `scripts/git_context_timing.py`, measuring median/min/max time and failure counts for commit, branch, status and remote Git commands. Git stdout/stderr are captured but never printed to avoid exposing remote credentials. These are sequential diagnostic measurements, not parallel wall-time predictions. First write attempt was blocked by a safety check; simplified retry succeeded. Scanner logic and stable v1.0.0 unchanged. **Windows validation pending.**

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m scripts.git_context_timing --runs 10
python -m scripts.engine_timing --runs 10 --summary
python -m pytest -q -rs
```

Record command output, failures, and test results before considering any runtime optimization.


## Git subprocess diagnostic validated on Windows — 2026-10-08

The user pulled development commit `d8c5e77` and executed the exact commands below:

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m scripts.git_context_timing --runs 10
python -m scripts.engine_timing --runs 10 --summary
python -m pytest -q -rs
```

Git subprocess diagnostic (10 sequential runs each, median milliseconds): commit 28.96 (26.47–32.00), branch 29.32 (27.41–32.70), status 34.27 (31.22–41.34), remote 28.24 (25.71–31.04); zero failures. Status was the slowest measured command, but process launch overhead is material across all four. The diagnostic does not expose Git stdout/stderr or credentials.

Offline Standard-profile 10-run engine median (milliseconds): setup 31.79, dependencies 7.62, secrets 33.24, Git context 68.70, total 139.96 (range 133.75–170.41). OSV network latency excluded. Scans reported `BLOCKED` as policy outcomes. Secret cache discovered 86 files, hashed 59, and after warmup scanned/reused 27/59. The earlier benchmark median was 128.78 ms with 85 discovered files; differing trees and machine conditions prevent attributing the difference to a regression.

Full test suite: **137 passed, 1 skipped, 0 failed in 21.48s**. The single skip was Windows symlink creation requiring Developer Mode or elevated privileges. No code changes in this validation milestone. Next optimization candidate: reduce Git subprocess launches with regression protection for branch/commit/dirty/remote and credential redaction; benchmark before claiming any improvement.


## v2.0 scope consolidation decision — 2026-10-08

User directed that features previously suggested for v2.1 must ship as part of **v2.0**, not a separate v2.1. Includes SOC-style desktop redesign, streaming findings, advanced analyzer-result caching, and dependency reachability. v3.0 is reserved for later optimization and development. This updates release scope only; the features are not yet confirmed implemented. Handoff updated in commit `8d7d29fe9728b43954391f940be98c2437a17247`. No application code or stable v1.0.0 changed.

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
git log -2 --oneline
```


## Git context subprocess reduction — 2026-10-08

Implementation commit `e143a4aa76a78157fe8f8a03002937fcc75824e4` changes Git context collection from four subprocesses to three: after `rev-parse HEAD`, two concurrent operations collect `status --porcelain=v1 --branch` and remote configuration. Branch and dirty state are parsed from the same porcelain output; detached HEAD remains branch `None`. Credential redaction function unchanged. Test commit `a54f107a0f6f491c28250f662914b2982f7602a5` adds upstream-branch and staged-change regression coverage. No verified Windows results yet; performance improvement remains a hypothesis.

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_git_context_regression.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Compare against previous 10-run Git context median **68.70 ms** and total median **139.96 ms** cautiously; repository contents and machine conditions may differ. Log actual outputs and any failures before proceeding.


## Windows verification: three-process Git context — 2026-10-09

The user confirmed the v2 branch was up to date and executed:

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_git_context_regression.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

**Git regression tests:** 10 passed in 8.17s. **Full suite:** 138 passed, 2 skipped, 0 failed in 22.64s. Skips: desktop graphical display unavailable and Windows symlink privileges unavailable.

**Offline Standard-profile ten-run medians (ms):** setup 29.77, dependencies 7.54, secrets 34.25, Git context 60.88 (range 58.46–74.55), total 133.25 (range 125.53–162.56). Prior separate ten-run baseline Git context 68.70 and total 139.96 ms; observed median differences −7.82 ms (−11.4%) and −6.71 ms (−4.8%), respectively. Different-run system conditions mean this is suggestive, not controlled proof of speedup. All scans returned policy status `BLOCKED`, with no reported execution errors. Secret cache discovered 86, hashed 59, warm runs scanned 27 and reused 59; no skipped/error counters. Offline timing excludes OSV network latency.

The three-subprocess optimization and added regression tests are now Windows validated. Continue v2.0 expanded scope (streaming findings, advanced analyzer caching, reachability, SOC desktop) with test evidence and commands for each milestone.


## v2.0 finding callback foundation — 2026-10-09

Implementation commit `9bc3b0fc8c78d0e2db36d0a67e4de889b57d72d7` adds optional `on_finding` to shared `run_scan`. Events are copies of allowlist-filtered analyzer findings, emitted after analyzer completion and before report construction. Existing callers need no changes; callback exceptions currently propagate. **This is not yet true in-scan streaming**; integration with analyzer iteration and desktop remains open. Test commit `82722c6490cf27201bda46c3022909e31229fce2` adds smoke and compatibility coverage. No Windows validation claimed yet.

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Record any failures, fixes, and actual results before continuing to real-time analyzer streaming.


## Finding callback foundation: Windows validation — 2026-10-09

The user pulled commit `3c02dc2` and executed:

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Finding callback tests: **2 passed in 0.09s**. Full suite: **141 passed, 1 skipped, 0 failed in 17.72s**; skip was Windows symlink privilege requirement. Offline Standard-profile ten-run medians (ms): setup 25.65, dependencies 6.88, secrets 32.46, Git context 54.67, total 118.20 (range 113.42–133.91). Prior independent benchmark medians were Git context 60.88 and total 133.25 ms; observed reductions 10.2% and 11.3%, respectively, without controlled A/B proof. Secret cache discovered 87, hashed 59; warm runs scanned 28/reused 59; zero skipped/error counters. All runs `BLOCKED` as expected policy results. OSV network latency excluded.

The callback is validated as an opt-in post-analysis finding notification, **not yet true in-scan streaming**. Next milestones: analyzer-time event emission, secure callback handling, and SOC desktop integration.


## Windows validation: secret scanner callback foundation — 2026-10-09

The user pulled the journal commit `286d289` and scanner callback commit `9894662` on branch `feat/v2-engine-integration` using `git pull origin feat/v2-engine-integration`, then ran:

```powershell
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
```

Result: **2 callback tests passed in 2.77s**; **full suite 141 passed, 1 skipped, 0 failed in 15.98s**. The skipped traversal test requires Windows symlink creation privileges. This validates backward compatibility but does **not** yet prove engine-connected, in-scan streaming. `scanners/secret_scanner.py` supports optional per-file finding callback; `run_scan` has not yet been connected to that callback. Next work: safe engine integration, allowlist-filtered emission, avoid duplicates, and incremental-cache behavior; add tests that prove callbacks occur before scanner completion.


## Analyzer-time secret finding events — 2026-10-09

Commit `e03cb11f00d439dd43e5c89fd221c751e72d9689` wires `scanners.secret_scanner.scan_directory(..., on_finding=...)` into the engine for subscribers. The engine filters each secret finding through the configured allowlist before notifying listeners, then emits only non-secret inventory/advisory records after analyzer completion to avoid duplicate secret events. **Opt-in streaming currently uses a full secret traversal** (strategy `streaming-full`), while ordinary scans retain incremental caching. The callback may execute before final report assembly, but dependency and OSV events are still delivered after their stages. Callback errors are not intentionally suppressed. Commit `7748860877d606405be55b004cbb54edee322514` adds tests for event-before-report, duplicate prevention, and allowlist behavior. No local Windows validation recorded yet.

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Next: confirm test results, add incremental-cache live events safely, and connect a thread-safe desktop event queue.


## Windows verification: engine-connected secret events — 2026-10-09

The user synced through `8239e9a` and ran:

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

**Callback tests:** 4 passed in 2.24s. **Full suite:** 142 passed, 2 skipped, 0 failed in 13.80s. Skips: desktop graphical display unavailable and Windows symlink creation privileges unavailable.

**Offline ten-run medians (ms):** setup 30.31, dependencies 7.33, secrets 31.12, Git context 60.70 (range 55.71–67.24), total 129.19 (range 122.21–144.72). Prior independent run: Git context 54.67 and total 118.20 ms. The current medians are higher by approximately 11.0% and 9.3% respectively; differences are not controlled regression evidence. Warm cache: discovered 87, hashed 60, scanned 27, reused 60, no skipped/error counters; first run scanned 31/reused 56. All scan statuses `BLOCKED` due to policy, not execution errors. OSV network latency excluded. **This benchmark measures the ordinary incremental path, not the opt-in streaming-full path.** Next: benchmark both paths and integrate live events with incremental secret-cache scans while maintaining verified-content safeguards.


## Incremental-cache live finding delivery — 2026-10-09

Commits `624d431` and `69d867b` add an optional per-finding callback to `scan_secrets_incremental` and wire it through `run_scan`, retaining the normal profile-based full-vs-incremental selection. Callback delivery occurs only after per-file metadata/content verification and before final report assembly. Allowlist filtering is applied by the engine; secret findings are not emitted a second time during report assembly. Cached entries remain validated using `_safe_cached_findings`. Commit `91c8b63` adds cold/warm cache parity and changed-file suppression regression tests. **Not yet validated on user's Windows machine.**

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py
python -m pytest -q -rs
python -m scripts.engine_timing --runs 10 --summary
```

Remaining: validate Windows results, ensure callback exceptions and cached findings have robust tests, and implement a thread-safe SOC desktop event queue. Offline benchmark excludes OSV network time.


## Ubuntu CI regression and correction — 2026-10-09

GitHub Actions security gate run [37832891115](https://github.com/ibrahim1101/PipelineGuard/actions/runs/37832891115) failed in the `Run tests` step: **2 failed, 140 passed, 4 skipped**. The failed tests were `test_finding_callback_matches_report` and `test_streamed_secret_precedes_report_build`. The corresponding Windows desktop validation run **37832891065 succeeded**. Root cause: in `pipelineguard/engine.py`, the no-profile (`else`) scanner call did not forward `on_finding` to `scan_directory`; the secret findings were present in the final report but never delivered as events. This defect was exposed by the Linux CI tests; it was not a platform-specific scanner issue. Commit `5af9d15` fixes the no-profile branch to forward the filtered callback, aligning it with full-profile and incremental branches. **Post-fix CI validation is pending**; do not mark the correction verified until tests finish.


## GitHub CI recovery and desktop live-event bridge — 2026-10-09

Post-fix GitHub Actions for commit `c19a162` are both green: Ubuntu Security Scan [run 37833332759](https://github.com/ibrahim1101/PipelineGuard/actions/runs/37833332759) and Windows desktop validation [run 37833332754](https://github.com/ibrahim1101/PipelineGuard/actions/runs/37833332754). The missing no-profile callback regression is closed.

Commit `acdd4b8` connects `run_scan(..., on_finding=...)` in the desktop worker to the existing thread-safe `queue.Queue`; only the Tk main thread handles `finding` events, updates the findings table/counter, and allows details inspection before the final report. Scan options are snapshotted before starting the worker to avoid reading Tk variables from the background thread. Final `result` still replaces preliminary findings with the authoritative report. Commit `1c6c174` adds a graphical Tk test for live event display before a final report exists. **Desktop event bridge awaits post-change CI and hands-on UI validation.**

```powershell
cd C:\Users\ibrah\PipelineGuard
git switch feat/v2-engine-integration
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_finding_callback.py tests/test_desktop_ui.py
python -m pytest -q -rs
```


## Desktop user acceptance feedback and small UI fixes — 2026-10-09

User launched source desktop and scanned synthetic `sample_secrets.py`: UI showed BLOCKED, score 0/100, three critical Generic secret assignment findings, one file scanned, no reused cache entries, and matching HTML report. Selecting a finding exposed a formatting bug: details showed literal `\\n` text rather than line breaks. User also requested one-click × clearing for project folder and configuration path inputs. Commit `f8eea7b` fixes detail string newline escapes, adds clear controls to both path inputs, and resets the stale scanning placeholder after final results. **Post-change UI/CI validation pending.**

```powershell
cd C:\Users\ibrah\PipelineGuard
git pull origin feat/v2-engine-integration
python -m pytest -q tests/test_desktop_ui.py
python -m pytest -q -rs
python -m pipelineguard.desktop
```


## Desktop UI user acceptance confirmation — 2026-10-09

Following the UI fix commit `f8eea7b` (details line breaks, × path clear controls, and reset of stale details placeholder), the user confirmed in chat: **“yoo it works”**. Record this as hands-on acceptance of the reported desktop UI fixes. The user did not provide fresh pytest output in this confirmation, so do not interpret it as an automated test pass or a full end-to-end certification. Next planned milestone: SOC-style desktop redesign and richer live scan activity indicators, while preserving the working Tk event queue and scanning behavior.


## SOC redesign stage 1 — navigation shell (2026-10-09)

Approved visual spec: `docs/SOC_DESIGN_SPEC.md`. Commit `94311bb` introduces an olive sidebar and wider workspace while retaining existing scan controls, findings, progress callbacks and report export. Navigation currently routes to existing functionality or explanatory dialogs; full distinct section views, charts, logo asset and pixel-cat loader remain future stages. **Automated CI and Windows hands-on testing are pending**. Suggested verification: `python -m pytest -q tests/test_desktop_ui.py` and `python -m pipelineguard.desktop`. Watch for Tk layout regressions, small-window clipping and sidebar readability.


## SOC redesign stage 2a — dark palette and widget styling (2026-10-09)

User visually verified Stage 1 sidebar screenshot and authorized continued implementation. Commits `5f61854` and `7ed9025` update `pipelineguard/theme.py` with dark charcoal/olive design tokens and apply Tk/ttk styling adjustments in `pipelineguard/desktop.py`, including readonly combobox colors, tree selection, dark OSV checkbox and clear control for findings search. No scanner engine changes. **Validation pending**: inspect Windows screenshot for readability, checkboxes, Tk entry appearance, report export and regression suite. Analytics and actual cyber-cat logo are not yet implemented. Test with `python -m pytest -q tests/test_desktop_ui.py` and `python -m pipelineguard.desktop`.


## SOC dark theme accepted and real analytics panel milestone — 2026-10-09

User explicitly confirmed the dark desktop theme is working, but could not supply a screenshot. This is user-reported hands-on success, not an automated test result. Commit `d80d75d` adds two SOC overview panels: recent scans from the persisted 25-entry local history (display last three) and scan insights based on the actual report summary and secret cache metrics. Refresh on completed scan and after history clearing. The UI has no invented chart points or fake historical projects. CI/Windows verification for the analytics change remains pending. Follow-up: genuine history trend chart, severity distribution, responsive layout and pixel-cat loading state.


## SOC dashboard charts milestone — 2026-10-09

User confirmed prior dark SOC layout looked good and authorized full build. Commit `ef2cc7b` adds Tk Canvas charts for the last 10 genuine history finding counts and current report severity distribution. Empty history/report displays explanatory text rather than invented statistics. Commit `98d7e7a` adds Tk tests for history points and empty states. **CI and Windows acceptance remain unverified for these changes**. Planned remaining scope includes polished cyber-cat branding/pixel-art loader, live event batching, accessible responsive layout, additional real analytics, Windows packaging, full CI/release validation. Local commands: `python -m pytest -q tests/test_desktop_ui.py` and `python -m pytest -q -rs`.


## SOC live event batching — 2026-10-09

User visually confirmed the new SOC chart panels and requested continued development. Commit `03d9dfb` changed desktop Tk event polling to drain up to 200 queued events per 100ms cycle, coalescing live findings table redraws; commit `d437a78` normalized event processor indentation immediately afterward. Commit `08e8a24` adds regression coverage for 150 finding events in a single poll and for final report replacement without duplicate preliminary findings. This is a performance/correctness implementation, **not yet independently benchmarked or CI-verified**. Run `python -m pytest -q tests/test_desktop_ui.py` and `python -m pytest -q -rs`, then scan the synthetic test project. Remaining: finalized cyber-cat logo, pixel loader, release packaging, full CI and accessibility checks.


## Regression: desktop startup and pytest collection SyntaxError — 2026-10-09

**Failure:** After event batching commits `03d9dfb`/`d437a78`, user ran `python -m pytest -q -rs` on Windows and test collection failed with `SyntaxError: 'return' outside function` at `pipelineguard/desktop.py:585`. `python -m pipelineguard.desktop` also failed before opening the window. **Root cause:** indentation-normalization edit left the final `return False` of `_process_scan_event` at four spaces (class level), not eight spaces (method body). **Fix:** commit `53e207d` indents the return into `_process_scan_event` and restores blank line before `poll`. This was an assistant-introduced regression; no user environment issue. **Verification pending** until CI/local pytest and launch are rerun. Suggested commands: `python -m py_compile pipelineguard/desktop.py`; `python -m pytest -q -rs`; `python -m pipelineguard.desktop`. Prevention: syntax compile and tests must run before claiming a desktop refactor is ready.


## SOC pixel-cat scan indicator — 2026-10-09

After user confirmed the desktop syntax correction appeared and asked to continue, commits `4eb0b06` and `80df897` added a small pixel-art cat with laptop to the sidebar using built-in Tk Canvas shapes. Idle state displays CAT ON DUTY; scan state displays SCANNING with changing dots, updated at most every five 100ms poll cycles. No large cat illustrations, third-party image assets, or engine changes. Commit `94fa25f` adds a Tk regression test for idle/active state. **CI and Windows tests not yet verified.** Next: user-requested top-left cyber-cat shield branding, visual layout QA, packaging and workflow validation.


## Angular wordmark from user reference — 2026-10-09

User supplied an image showing angular pixel/cyber-styled PipelineGuard lettering and requested it replace the plain top-left title without removing the cyber-cat branding. Commits `b309b0f` and `ac98ad5` implement a dependency-free Tk Canvas pixel wordmark in `pipelineguard/wordmark.py`, replacing plain title labels in the header and sidebar, with a small geometric cat-shield mark. This is an approximation of the visual style, not an exact licensed font or copied binary asset. Commit `16e3471` adds rendering assertions. **CI and user visual approval pending**; verify wordmark legibility at normal Windows scaling.


## User-requested branding rollback — 2026-10-09

User rejected the angular wordmark and altered shield logo as visually incorrect and explicitly requested a revert. Commit `61df471` restores the previously working Segoe UI PipelineGuard header, original `◈ PipelineGuard` sidebar label and 174px sidebar; removes the custom wordmark renderer import/use from the desktop. No scanning logic or SOC charts changed. `pipelineguard/wordmark.py` remains an unused historical file; do not reinstate this experimental branding without explicit user approval. The exact approved mockup cyber-cat logo was never implemented as an asset. Validation pending.


## User-supplied approved cyber-cat branding — 2026-10-09

User supplied the exact approved mockup header screenshot, asked to retain its cyber-cat shield logo and white Pipeline/olive Guard treatment, changing only the title font to a suitable cyber/technical typeface. Commit `7c2258c` embeds a 54x53 color-quantized crop of the user-provided logo as a Tk-compatible PNG in `pipelineguard/brand_asset.py` (no redistributed font binary). Commit `4eb469d` displays this logo in the sidebar and header, renders Pipeline and Guard in Bahnschrift Bold where installed (Segoe UI fallback), and preserves the original tagline. Commit `484dbd1` tests logo load and fallback; `336c7b3` removes obsolete test assertions from the rejected experimental pixel-wordmark. Note that the logo crop has a small amount of original mockup background, so the image/background seam should be checked at normal Windows scaling. **CI and user acceptance pending.**


## Global top-left branding placement — 2026-10-09

User showed that the single approved cyber-cat logo/title still appeared offset right, inside the workspace, and requested the originally agreed top-left placement. Commit `144e7f3` restructures Tk layout: a full-width header is packed into the root before a new content frame, with sidebar and workspace beneath it. The approved logo asset, Bahnschrift title, colors and tagline remain unchanged. Commit `0d663f1` adds a desktop Tk layout regression test. **Visual QA and CI pending.**


## Post-branding dashboard readability regression — 2026-10-09

User visually approved the full-width top-left cyber-cat header. The next development pass preserves that design and addresses the screenshot-observed Recent Scans card displaying literal `\\n` separators. Commit `fb0bcdf` replaces double-escaped newline sequences in `pipelineguard/desktop.py` with Python newline escape sequences, also correcting the insights and About text. Commit `6fc7cf2` adds a desktop UI regression test for multi-line scan history. **Automated tests and Windows rendering not yet verified**; run `python -m pytest -q -rs` and launch desktop after pulling.


## Scrollable dashboard and idle progress cleanup — 2026-10-09

Following user's 153 passed/2 skipped Windows pytest run and approval to proceed, commit `ee4c55b` wraps the existing SOC workspace in a Tk Canvas with a vertical scrollbar, canvas width synchronization, and mouse wheel handling that leaves findings Treeview and details Text controls alone. The approved global header/sidebar branding and scan engine remain unchanged. Progressbar now starts in determinate 0 state, enters indeterminate mode only while scanning, and resets to determinate 0 on result or error. Commit `b409e1d` adds GUI tests for scroll container, idle progress and error reset; commit `a4c3f1f` updates a layout assertion for the new canvas parent. **New CI/Windows tests not yet verified.** Test mouse wheel behavior and findings table at reduced window height.


## Windows Tcl string mismatch in new scroll/progress tests — 2026-10-09

**User test result:** `python -m py_compile pipelineguard/desktop.py` succeeded; pytest returned **2 failed, 154 passed, 1 skipped** (Windows symlink permissions). Both failures occurred in new GUI tests (`test_scrollable_workspace_and_idle_progress` and `test_scan_error_resets_idle_progress`), where `ttk.Progressbar.cget('mode')` returned a Tkinter Tcl string object displaying `'determinate'` but not equal to Python's native string under direct comparison. **Root cause:** over-specific test assertions, not demonstrated application progress behavior failure. **Fix:** commit `e144969` uses `str(desktop.progress.cget('mode')) == 'determinate'` in both tests. No application/UI changes. **Rerun required** to verify the correction. Prevention: normalize Tcl-backed option values before asserting equality across Tk/Tcl versions.


## Isolated v2 Windows portable packaging — 2026-10-09

User confirmed dashboard mouse-wheel scrolling on Windows and authorized next milestone. Added `scripts/build-v2-windows.ps1` (Windows PyInstaller `--windowed --onedir` build from desktop launcher), `.github/workflows/v2-windows-portable.yml` (manually dispatched Windows test/build/artifact upload), and `docs/V2_WINDOWS_PACKAGING.md` (local build, CI, interactive acceptance checklist). Stable v1.0.0 release, installer, and main branch remain untouched. **Pending:** GitHub Actions run and user double-click/scan/export verification; no claims of successful packaged launch yet. The v2 installer is deliberately deferred until portable validation.


## Reference-faithful SOC UI overhaul — phase 1 — 2026-10-09

User supplied a polished dashboard reference image and an actual Windows screenshot, identifying a substantial visual mismatch. Previous UI completion statements were premature. The supplied reference is now the visual acceptance target, including integrated toolbar, score/status/severity panels, activity/system cards, findings tabs, inspector/code preview, loading/settings/about surfaces. **Phase 1:** commit `62ff57c` begins restructuring the existing Tk desktop with a compact full-width top command bar and shared project/profile state, while retaining approved cyber-cat branding and the existing scan engine. The older controls panel remains temporarily for compatibility; this is an intermediate state, not reference parity. **Unverified:** Windows launch, pytest and packaged build after the change. Subsequent phases must replace redundant controls, redesign the actual metric/chart layout and findings workspace, and verify screenshots on Windows. Do not claim the UI complete until visually reviewed against the target.


## Phase 1 toolbar duplication regression — 2026-10-09

**User Windows screenshot:** project folder, scan profile and scan action appeared in both the new top command bar and the original stacked controls card, creating significant redundant space. **Cause:** phase 1 added a new toolbar before removing the old controls panel. **Fix:** commit `29c7193` replaces the old card with a compact secondary options row for OSV, optional config selection/help, scan history and exports. Project folder, scan profile and primary Start Scan action remain only in the top bar. Existing `scan_button` reference is retained as an unshown widget for scan state compatibility; top-bar button is also disabled/re-enabled by scan events. **Pending:** user Windows launch and pytest; reference-image redesign remains incomplete.


## SOC reference UI: dark palette and companion dialogs — 2026-10-09

**Initial remote review:** draft PR #1 remains open; branch is ahead of stable main, which is untouched. The prior dashboard commits `0aa6912` and `0d7a3c4` are present. Prior GitHub-hosted Linux run 37847854724 and Windows run 37847854663 both completed successfully; those results do not validate the new changes in this entry.

**This iteration:** commit `2fd8877` aligns the SOC color tokens with the approved near-black olive reference. Commit `05748a9` replaces the old minimal About dialog with a branded development-version panel and introduces a dedicated Settings window with functional General, Scan Engine, OSV Lookup, Reports, Appearance and About sections. Settings use the existing shared project/profile/OSV variables; scanning engine, report formats and stable release remain unchanged. Commit `a8a8d26` adds graphical Tk smoke tests for both dialogs. An isolated presentation helper `soc_labels.py` was also added in commit `0337651` but is not yet integrated into the desktop.

**Failures and verification limits:** Two proposed inspector-file writes and a larger follow-up helper edit were rejected by connector safety checks; no claims are made that those changes landed. An attempted append to the existing SOC test file was also rejected; a separate test file was created instead. At last inspection, Windows workflow 37853588718 and Linux workflow 37853588719 were pending and had no jobs returned. Windows visual acceptance and the new tests are not yet confirmed. Next: check CI before further commits, then implement the tabbed findings workspace and privacy-safe inspector without exposing raw source values.


## SOC findings workspace — 2026-10-09, ~04:56 IST

**Starting state:** draft PR #1 open; base main remained at `5347d260`. The previous dark-palette/dialog commit `2d3ea6c` had successful Linux Security Scan (37853643187) and Windows desktop validation (37853643106), verified through the GitHub workflow API. No failed push from that commit needed retry.

**Implementation:** `93ced16` adds `pipelineguard/soc_inspector.py` with allowlisted, bounded, control-character-normalized metadata and a deliberately masked source-location preview; it never reads source files or displays arbitrary finding JSON, snippets, summaries or captured values. `15c3da8` adds pure Python grouping/privacy tests. `d3d0fff` integrates a three-tab Findings workspace (All Findings / Secrets / Dependencies) with category-aware search/severity filtering, visible/total count, masked preview panel and safe clipboard export. It also replaces the former raw JSON inspector that could disclose sensitive scanner payloads. Findings use the original scan engine and event stream. No changes to main or stable v1.0.0.

**Failure:** attempts to add a separate Tk findings-tab test file were rejected by connector safety checks; no such test was committed. Do not misreport this as an automated-test success. The existing Tk tests remain in the repo and the new pure Python tests are present.

**Verification pending at this entry:** Linux run 37859563854 was in progress and Windows run 37859563891 pending for head `d3d0fff`. CI results and physical visual acceptance are not yet known. If CI fails, inspect job logs and repair before the next feature increment. Follow-up: verify tabs and clipboard behavior on Windows, add graphical tab tests when connector permits, improve inspector layout and richer source previews only with strict secret redaction and explicit privacy boundaries.


## SOC inspector component extraction — 2026-10-09, ~06:00 IST

**Fresh remote check:** main remains stable at 5347d260; v2 is ahead on the development branch. Previously pending Linux 37859607882 and Windows 37859607893 both completed successfully. No prior failed workflow required a retry. This does not validate new changes below.

**Progress:** commit 28a23fe adds a bounded, sanitized heading helper in `soc_inspector.py`. Commit 8f45f8e introduces `pipelineguard/soc_finding_panel.py`, a reusable reference-styled dark SOC inspector with a severity badge, metadata/remediation area, intentionally masked source-location preview and clipboard copying of safe allowlisted details only. Commit 94399d1 adds helper/privacy and Tk smoke tests. This component is **not yet integrated into the main desktop**, so do not claim the new panel is visible in the running application.

**Blocked writes:** two attempts to update the existing 58 KB `pipelineguard/desktop.py` via the GitHub connector were rejected by safety checks. First attempt included navigation and inspector layout changes; second was a smaller navigation-only change. Refetch confirmed the edits had not landed. Avoid repeated identical retries; consider safe smaller-file extraction/integration through a supported path on a future run. No main-branch changes or release were made.

**Pending verification:** check Linux/Windows CI for 94399d1, and visually test the integrated component after the desktop edit is unblocked. Continue reference matching, including working sidebar navigation and inspector replacement. 


## SOC inspector integration and sidebar navigation — 2026-10-09, ~07:00 IST

**Remote starting state:** draft PR #1 open, head `6c5b92a`, stable main at `5347d260`. Latest preceding Linux run `37865491924` and Windows run `37865491909` both completed successfully, verified using GitHub workflow-run API. No interrupted prior commit was detected and no rerun was required.

**Implementation:** commit `bc81032abeb6f44304134269ab8abd9cc5c96a16` successfully updates `pipelineguard/desktop.py` to import and instantiate the previously committed `FindingInspector` as the actual right-hand findings panel. Existing `self.detail` and `self.preview` widget references are maintained as compatibility aliases for scan lifecycle code. Selecting a finding now invokes the panel's `select_finding` method, displaying bounded severity/title, allowlisted metadata and intentionally masked source location. The sidebar's Dashboard action scrolls to top, Findings scrolls to the tabbed workspace and activates All Findings, and Dependencies activates the Dependencies tab and scrolls there. Reports, Settings, OSV help and scan-profile behavior are preserved. No scanner engine or release/main changes.

**Verification:** GitHub Linux Security Scan `37870188445` completed successfully for `bc81032`. GitHub Windows desktop validation `37870188366` completed successfully for the same commit, including its packaged Windows checks. This is automated build/startup validation, not user visual acceptance against the reference image.

**Failed attempts:** two separate new integration-test file creates and one append to existing `tests/test_soc_dialogs.py` were rejected by connector safety checks. No integration-test commit landed; the already committed component tests remain. The desktop integration write itself succeeded on the first attempt. Do not blindly retry blocked test writes unchanged.

**Next:** refresh CI before additional changes; add integration coverage when permitted, clear inspector selection/badge when scans restart, verify real Windows layout and responsiveness, and continue reference-image parity. Keep PR draft and stable main unchanged.


## Inspector stale-selection investigation — 2026-10-09, ~08:00 IST

**Fresh remote checks:** draft PR #1 remains open on `feat/v2-engine-integration` at `2a1f2e43ab82cc2636efdfc2bde8101c333daf55`; stable main remains `5347d260e86ef1dc3f8d5963bed3df95fe03aa64`. Linux Security Scan run `37870320106` and Windows desktop validation run `37870320093` both completed successfully on the branch head. No CI failure or incomplete push required a retry at the beginning of this iteration.

**Issue found by code review:** The desktop aliases the new inspector's text widgets as `self.detail` and `self.preview`. Scan startup and completion replace their text directly but do not reset `FindingInspector._current`, severity badge, title or Copy button. Rebuilding the findings table on filter/tab changes can also leave a stale inspector selection. This is a UI correctness/privacy issue: users could see or copy details for a finding no longer selected. The existing `FindingInspector.clear()` method resets all state, but it is not called during these transitions.

**Uncommitted attempts:** A minimal full-file replacement of `pipelineguard/desktop.py` to call `self.inspector.clear()` on scan start/completion and findings refresh was blocked by connector safety checks. A separate small `pipelineguard/soc_finding_panel.py` update to clear on `<<TreeviewSelect>>` and reject clipboard copy without an active selection was also blocked. Neither change landed. Do not bypass connector safety controls or claim a fix; re-evaluate through an approved edit path when available. Until then, the current Windows/Linux CI successes do not cover this stale-inspector behavior.

**Next:** Implement and test explicit inspector lifecycle reset through an approved path, then verify responsive layout and screenshot parity. Keep main and the stable release unchanged.


## Inspector deselection guard — 2026-10-09, ~09:00 IST

**Starting remote state:** draft PR #1 open on `feat/v2-engine-integration` at `19549ef61d71528288efd7282e543ca9e92ab013`; stable `main` remains `5347d260e86ef1dc3f8d5963bed3df95fe03aa64`. Linux Security Scan run `37874831501` and Windows desktop validation run `37874831484` both completed successfully for the preceding head. No failed run needed rerunning.

**Implemented:** commit `0cc97fb9fb5c9b9ef98205def4ac7fc17b14a6af` updates `pipelineguard/soc_finding_panel.py` to attach an additional `<<TreeviewSelect>>` listener to the sibling findings Treeview. When the table selection becomes empty (e.g. a selected row is removed by filtering or scan reset), the inspector calls its existing `clear()` method to remove stale heading, severity badge, displayed metadata, masked preview and clipboard button state. The original Treeview handler remains installed via `add="+"`. Standalone panel use without a sibling Treeview remains supported. This is a targeted UI lifecycle mitigation; live Windows interaction is still unverified.

**Rejected writes:** a direct `pipelineguard/desktop.py` lifecycle patch was blocked by GitHub connector safety checks; it did not land. An attempted `tests/test_soc_finding_panel.py` regression-test addition was also blocked. An attempt to refresh draft PR #1 description was blocked. Do not claim these edits were committed. No alternate force push or safety-control bypass was attempted.

**CI at last check:** Linux run `37879855595` and Windows run `37879855580` were in progress for `0cc97fb`; outcomes pending. Next: inspect CI results, test actual Tk deselection behavior, add integration regression coverage when permitted, then continue responsive/reference layout work. Keep stable main/release unchanged.


## SOC inspector lifecycle follow-up — 2026-10-09, 12:00 IST

Fresh remote check: draft PR #1 remains open at e90a8fb; stable main remains 5347d260. Both Linux Security Scan 37879907191 and Windows desktop validation 37879907340 succeeded on e90a8fb. The earlier cancelled Windows run 37879855580 was superseded; no failed current-head CI needs rerun.

Uncommitted attempts: a desktop.py change to clear the inspector on scan start, scan completion, and findings refresh was rejected by connector safety checks. A separate soc_finding_panel.py change to snapshot allowlisted clipboard details and wrap long headings was also rejected. Neither landed. No push was performed. Next: implement these fixes through a supported, permitted edit path and add regression tests, then verify actual Windows UI behavior. Do not claim visual acceptance or alter main/release.
