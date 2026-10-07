# PipelineGuard v2.0 — Security Intelligence Platform

v1.0.0 remains the stable released baseline. v2.0 is a fast, consolidated upgrade cycle: scale the engine, add application-security intelligence, replace the desktop experience, validate, release, then move development focus to SentinelLab.

## Product direction

PipelineGuard v2.0 must answer four questions quickly even on very large repositories:

1. What changed?
2. What is actually dangerous?
3. Why does it matter?
4. What should the developer do next?

The UI is inspired by dense professional SOC/security dashboards, but is an original PipelineGuard design: dark graphite surfaces, matte olive identity, compact information hierarchy, live telemetry, drill-down workspaces, and minimal wasted space.

## Architecture rules

- Preserve the v1.0 tag and installer as the stable release.
- One scan engine serves Desktop, CLI and CI.
- Stream findings instead of waiting for an entire scan to finish.
- Bounded-memory traversal and batched intelligence requests.
- Incremental content hashing and persistent scan cache.
- Parallel scanner workers with configurable CPU/resource limits.
- New capabilities are scanner/intelligence plugins rather than hard-coded UI logic.
- Expensive analyzers can be disabled by scan profile.
- Every automated remediation must support preview before apply.
- AI explains structured findings; AI does not decide whether a vulnerability exists.

## v2.0 implementation tracker

### Scale and scan orchestration
- [ ] 1. Incremental content-hash scan cache
- [ ] 2. Parallel worker scan orchestrator
- [ ] 3. Million-file/monorepo streaming mode
- [ ] 4. Quick / Standard / Deep / Release / Forensic scan profiles
- [ ] 5. Baseline and differential findings
- [ ] 6. Git-aware branch/commit/PR analysis

### Vulnerability intelligence
- [ ] 7. Dependency graph and direct/transitive paths
- [ ] 8. Reachability analysis
- [ ] 9. CVSS + EPSS + KEV contextual risk scoring
- [ ] 10. Finding deduplication and incident correlation
- [ ] 11. Actionable remediation engine
- [ ] 12. Preview/apply/rescan safe automated fixes

### Analyst experience
- [ ] 13. Local AI analyst through Ollama/OpenAI-compatible endpoints
- [ ] 14. Multi-finding investigation/correlation workspace

### Supply chain and compliance
- [ ] 15. CycloneDX/SPDX SBOM generation
- [ ] 16. SBOM import and drift comparison
- [ ] 17. Dependency license/compliance analysis
- [ ] 18. Typosquatting/dependency-confusion heuristics
- [ ] 19. Suspicious/malicious package intelligence

### AppSec scanners
- [ ] 20. Dockerfile/container security analysis
- [ ] 21. Terraform/Kubernetes/Helm/GitHub Actions IaC analysis
- [ ] 22. Source-code SAST engine
- [ ] 23. Git-history secret scanning
- [ ] 24. Entropy/context secret detection

### Platform
- [ ] 25. Stable scanner plugin API
- [ ] 26. Isolated remote repository scanning
- [ ] 27. Multi-project workspace mode
- [ ] 28. Historical security trends and metrics
- [ ] 29. Executive/developer security report generation
- [ ] 30. Extensible CI adapters for GitHub/GitLab/Jenkins/Azure DevOps

## Complete UI overhaul

Replace the single-screen v1 desktop with a v2 security operations workspace.

### Visual identity
- Dark graphite/near-black application shell.
- Matte olive PipelineGuard accent rather than generic blue SOC styling.
- High-contrast severity colors used only where security state needs attention.
- Compact cards, restrained borders, clear typography and dense but readable data.
- Original layout and components; reference dashboards are inspiration only.

### Navigation
Dashboard · Projects · Scan · Vulnerabilities · Dependencies · Secrets · Code · Containers · IaC · SBOM · Investigations · History · Reports · Policies · Integrations · Settings

### Dashboard
- Security score and release decision
- Critical/high/medium/low counts
- New/fixed/regressed findings since baseline
- Scan telemetry and duration
- Dependency health
- Risk trend
- Recent scans
- Highest-priority remediation queue

### Scan workspace
- Live stage timeline
- Files discovered/scanned/skipped/cached
- Worker utilization
- Findings streamed while scanning
- Pause/cancel support
- Quick/Standard/Deep/Release/Forensic selector

### Vulnerability workspace
- Searchable/filterable virtualized table
- CVE/advisory, package, severity, CVSS, EPSS, KEV, reachability
- New/existing/fixed/regression state
- Dependency path
- Evidence
- Remediation and fixed versions
- Suppress/accept-risk controls with reason and expiry
- Preview fix / apply fix / rescan

### Investigation workspace
Correlate selected secrets, vulnerable dependencies, SAST, IaC, containers and Git context into one case-style view.

## Fast implementation order

### Wave A — foundation
Plugin API, streaming traversal, cache, parallel orchestrator, scan profiles, progress events, baseline/diff and Git context.

### Wave B — intelligence
Dependency graph, batched OSV, EPSS/KEV adapters, correlation, remediation, SBOM and license intelligence.

### Wave C — AppSec
SAST, IaC, containers, Git-history secrets, entropy secrets, package-risk heuristics.

### Wave D — product
New desktop shell/workspaces, projects, trends, investigations, reports, integrations and local AI analyst.

### Wave E — hardening/release
Large-repository benchmarks, regression suite, Windows packaging, installer lifecycle, UI acceptance, documentation and v2.0 release.

## Completion gate

v2.0 is ready only when:
- v1 regression tests remain green.
- Large-repository scanning is bounded-memory and benchmarked.
- Incremental rescans demonstrate substantial reuse of unchanged-file results.
- New/existing/fixed/regressed findings are deterministic.
- Intelligence failures degrade gracefully instead of blocking local scans.
- Desktop remains responsive during deep scans.
- Windows build/install/launch/uninstall passes.
- Documentation distinguishes implemented intelligence from heuristic/experimental intelligence.
