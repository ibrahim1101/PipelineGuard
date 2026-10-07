# PipelineGuard Development Roadmap

PipelineGuard v1.0.0 is the first complete public release. This document now separates the shipped baseline from post-release development.

## v1.0.0 — Released

**Status: Released and validated**

Release validation completed successfully:

- 34/34 planned v1.0 features implemented.
- Core security workflow passes in GitHub Actions.
- Live OSV lookup and advisory enrichment validated.
- Mixed Python/Node integration gate passed.
- 10,000-file synthetic scale test passed on Linux.
- Native Windows desktop build passed.
- Packaged Windows application startup smoke test passed.
- Inno Setup installer compilation passed.
- Silent install, installed-app launch, uninstall, and cleanup passed on a GitHub-hosted Windows runner.
- `PipelineGuard-Setup-1.0.0.exe` was generated and attached to the v1.0.0 GitHub release.
- Terminal, JSON, HTML, and SARIF reporting shipped.
- GitHub annotations, configurable release gates, allowlists, suppression rules, Docker support, and the native desktop workflow shipped.

Interactive visual inspection on real user hardware remains useful acceptance feedback, but it is no longer a blocker for the already-published v1.0.0 release.

## Shipped v1.0 feature set

1. Modular project structure
2. Secret scanning engine
3. Generic password and token detection
4. AWS, GitHub-token, and private-key detection
5. Generated-folder exclusions
6. Python dependency inventory
7. Node.js dependency inventory
8. OSV vulnerability lookup
9. Offline vulnerability fallback
10. SAFE/WARNING/BLOCKED decisions
11. Security score from 0–100
12. Terminal report
13. JSON report
14. HTML report
15. Custom configuration file
16. Configurable ignored directories
17. Configurable file-size limits
18. Configurable warning failure policy
19. Automated unit-test suite
20. Real-project integration tests
21. Version and dependency-range parsing
22. CVSS and affected-version reporting
23. Provider-specific secret rules
24. False-positive suppression
25. Allowlist support
26. SARIF output
27. GitHub pull-request annotations
28. Rich policy and release gates
29. Performance and large-repository testing
30. Packaging, documentation, and release QA
31. Matte olive-green native desktop interface
32. Background desktop scans and report exports
33. Standalone Windows executable
34. Windows installer and shortcuts

## Post-v1.0 development

Future work will be developed without rewriting the v1.0 release history. Candidate priorities are:

- Improve desktop UX using feedback from real Windows installations.
- Add a polished PipelineGuard application icon and richer Windows executable metadata.
- Add signed-build readiness and document a future code-signing path.
- Expand dependency ecosystems beyond Python and Node.js.
- Improve vulnerability caching and offline intelligence.
- Add richer remediation guidance and fix prioritization.
- Add scan baselines/diff mode so CI can highlight newly introduced findings.
- Expand CI integrations beyond the initial GitHub workflow.
- Continue performance profiling on very large repositories.
- Strengthen release artifact integrity and provenance metadata.

The next development version will be selected when the first post-v1.0 feature set is scoped.
