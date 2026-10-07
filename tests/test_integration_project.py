from __future__ import annotations

import json
from pathlib import Path

from pipelineguard.engine import run_scan


def test_realistic_project_scan_covers_inventory_secrets_and_policy(tmp_path: Path, monkeypatch) -> None:
    """Exercise the complete engine against a small mixed-language project."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}), encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "settings.py").write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    monkeypatch.setattr(
        "pipelineguard.engine.query_osv",
        lambda packages, enrich=True: [
            {
                "severity": "WARNING",
                "rule": "Known dependency vulnerability",
                "package": "requests",
                "version": "2.31.0",
                "id": "DEMO-REQUESTS-1",
                "advisory_severity": "HIGH",
                "cvss_score": 8.1,
                "fixed_versions": ["2.32.0"],
            }
        ],
    )

    config = tmp_path / ".pipelineguard.json"
    config.write_text(json.dumps({"block_advisory_severity": "HIGH"}), encoding="utf-8")
    report = run_scan(tmp_path, config=config, online=True)

    assert report["dependency_check_complete"] is True
    assert report["policy_blocked"] is True
    assert report["status"] == "BLOCKED"
    assert any(item["rule"] == "AWS access key" for item in report["findings"])
    advisory = next(item for item in report["findings"] if item.get("id") == "DEMO-REQUESTS-1")
    assert advisory["cvss_score"] == 8.1
    inventory_names = {dependency["name"] for item in report["dependency_inventory"] for dependency in item["dependencies"]}
    assert {"requests", "lodash"} <= inventory_names
