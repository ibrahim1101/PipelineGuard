# PipelineGuard v2.0 — Approved SOC Desktop Design

Status: **User-approved visual direction (2026-10-09)**.

## Visual identity
- Dark charcoal / near-black surfaces, matte olive-green highlights, high-contrast typography.
- Top-left branding: compact cyber-cat head within a security shield, next to PipelineGuard wordmark.
- Do **not** include large literal cat illustrations in dashboard corners, banners, or backgrounds.
- Optional loading/splash screen: small pixel-art cat coding at a laptop, restrained animation and accessible static fallback.
- Professional security-workstation look; maintain usable contrast and readable data density.

## Approved layout (combination of SOC Command Center and Cybersecurity Analytics)
- Left sidebar: Dashboard, Scan Project, Findings, Dependencies, OSV Lookup, Reports, Scan History, Settings.
- Top scan bar: selected project folder with clear button, folder picker, scan profile, settings and Start Scan.
- Overview cards: security score, policy status, finding counts by severity, scan duration, issue types, recent scans.
- Analytics: severity donut, historical findings trend from actual stored scans, scan activity, file/cache metrics.
- Main workspace: findings table with filters and severity indicators, selectable details with location, confidence, rule, summary, remediation and safely redacted code preview where feasible.
- Companion views: loading/splash, settings, about.

## Engineering constraints
- Mockup numbers and project names are illustrative, not fixtures or product promises. Render only real scan/history data; use informative empty states.
- Avoid exposing raw credentials or secrets in previews/logs/reports; mask sensitive values by default.
- Preserve existing scanner engine, callback event queue, report export, incremental cache, and Windows packaging.
- Keep UI responsive; batch and throttle high-volume live finding events rather than redrawing per finding.
- Implement incrementally with tests and append-only entries in ENGINEERING_HISTORY.md. No claim that mockup is already implemented.

## Delivery sequence
1. Shell and design tokens, navigation, header and metric cards.
2. Findings workspace, filters, detail inspection and privacy-safe code context.
3. Real history charts, scan activity and cache telemetry.
4. Pixel-cat loading state, settings/about and accessibility polish.
5. Desktop regression tests, Windows packaging and release validation.
