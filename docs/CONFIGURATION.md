# Configuration guide

PipelineGuard's **Configuration (Optional)** field accepts a local **JSON** file. Leave it blank to use defaults. Click **?** beside the field in the desktop app for this guide, or choose **Choose config** to select an existing file. You may create `.pipelineguard.json` in your project directory and select it; the desktop does not automatically discover it.

## Complete supported options

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `ignored_directories` | array of nonempty strings | `[".git",".venv","venv","node_modules","__pycache__",".pytest_cache"]` | Directory names excluded from traversal. Supplying the array **replaces**, rather than adds to, the defaults. |
| `max_file_size` | positive integer | `1000000` | Maximum file size in bytes considered by the secret scanner. |
| `fail_on_warning` | boolean | `false` | Blocks release on a WARNING status, including incomplete dependency checks. |
| `allowlist` | array of objects | `[]` | Suppresses findings matching an exact rule name and a file glob, optionally a 1-based line number. |
| `minimum_score` | integer from 0 to 100 | `0` | Blocks release when the score falls below the threshold. |
| `blocked_rules` | array of nonempty strings | `[]` | Blocks release when a finding's rule name exactly matches an entry. |
| `block_advisory_severity` | `"LOW"`, `"MODERATE"`, `"HIGH"`, `"CRITICAL"`, or `null` | `null` | Blocks known dependency vulnerability advisories at or above this severity. Unknown severity is not guessed. |

These are **all seven accepted top-level keys** in the current `pipelineguard/config.py`. Unknown keys, invalid types, nonpositive file sizes, invalid score ranges and malformed allowlist entries cause a configuration error. JSON does not permit comments or trailing commas.

## Example: balanced project policy

Save the following as `.pipelineguard.json` (or copy [the sample](../examples/pipelineguard.example.json)):

```json
{
  "ignored_directories": [".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "build"],
  "max_file_size": 1000000,
  "fail_on_warning": false,
  "allowlist": [
    {"rule": "Generic secret assignment", "file": "tests/fixtures/*", "line": 12}
  ],
  "minimum_score": 70,
  "blocked_rules": ["Generic secret assignment"],
  "block_advisory_severity": "HIGH"
}
```

**Important:** The allowlist above is an *illustrative* exception. Replace its rule, file pattern and line with a verified false positive in your own repository, or use `"allowlist": []`. Never allowlist genuine credentials. Paths are compared using forward slashes and case-sensitive glob matching. Omitting `line` suppresses **all matching lines** for the specified rule/file pattern, so use a line number where possible.

`blocked_rules` uses exact scanner rule names (visible in findings), not wildcard patterns. `minimum_score`, `blocked_rules`, and advisory severity apply release-blocking policy; they do not change the finding severity or automatically remove findings.

## Desktop usage

1. Choose the project folder.
2. Create a JSON configuration file using the example and edit only the settings you need.
3. Select it with **Choose config**. Leave the field blank for defaults.
4. Choose whether to enable live OSV lookup, then click **Scan project**.
5. Inspect findings and the report. Live OSV lookup requires network access; offline scans can report incomplete dependency intelligence.

The optional configuration file is **not** the scan report. Exported reports are separate HTML, JSON or SARIF files.

## CLI usage

```bash
python -m pipelineguard.main scan . --config .pipelineguard.json
```

Use `python -m pipelineguard.main scan --help` for other CLI flags. In Docker, mount the configuration file or project directory so the CLI can read it.

## Common mistakes

- **Invalid JSON:** Use double quotes for strings and keys, lowercase `true`/`false`/`null`, and no comments.
- **No files scanned:** Supplying `ignored_directories` replaces the built-in exclusions; confirm folder names.
- **Unexpected warning/block:** `fail_on_warning` can block when OSV checking is disabled or incomplete; `minimum_score` and `blocked_rules` also apply.
- **Allowlist does not match:** Copy the exact finding rule and project-relative path from a report; line numbers start at 1.
- **Advisory threshold does nothing:** It only applies to findings identified as known dependency vulnerabilities with recognized advisory severity.

**Security:** Do not put actual secrets in your configuration. Only scan code you own or are authorized to assess.
