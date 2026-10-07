from pathlib import Path

from scanners.secret_scanner import scan_directory


def test_detects_secret(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('API_KEY = "fake-test-secret-12345"\n', encoding="utf-8")
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_ignores_virtual_environment(tmp_path: Path) -> None:
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "config.py").write_text('PASSWORD = "fake-test-secret-12345"\n', encoding="utf-8")
    assert scan_directory(tmp_path) == []


def test_clean_project_is_safe(tmp_path: Path) -> None:
    (tmp_path / "hello.py").write_text("print('hello')\n", encoding="utf-8")
    assert scan_directory(tmp_path) == []


def test_detects_provider_specific_token(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SLACK_TOKEN=xoxb-1234567890-secret-value\n", encoding="utf-8")
    findings = scan_directory(tmp_path)
    assert findings[0]["rule"] == "Slack token"
    assert findings[0]["confidence"] == "high"


def test_detects_multiple_provider_tokens(tmp_path: Path) -> None:
    twilio_token = "SK" + "0123456789abcdef0123456789abcdef"
    (tmp_path / ".env").write_text(
        "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "SENDGRID=SG.abcdefghijklmnop.qrstuvwxyz1234567890\n"
        f"TWILIO={twilio_token}\n",
        encoding="utf-8",
    )
    rules = {item["rule"] for item in scan_directory(tmp_path)}
    assert {"npm access token", "SendGrid API key", "Twilio API key"} <= rules
