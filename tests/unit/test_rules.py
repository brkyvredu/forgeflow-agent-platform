from pathlib import Path

from forgeflow.domain.models import Finding
from forgeflow.scanner import discover_repository, scan_repository


def _scan(repository: Path) -> list[Finding]:
    return scan_repository(repository, discover_repository(repository))


def test_rules_detect_and_redact_security_findings(tmp_path: Path) -> None:
    secret_value = "-".join(("correct", "horse", "battery", "staple"))
    dangerous_shell_argument = "shell" + "=True"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        f'password = "{secret_value}"\n'
        f"subprocess.run(command, {dangerous_shell_argument})\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")

    findings = _scan(tmp_path)

    by_rule = {finding.rule_id: finding for finding in findings}
    assert "FF-SEC-001" in by_rule
    assert "FF-SEC-002" in by_rule
    assert secret_value not in (by_rule["FF-SEC-001"].evidence or "")
    assert "***REDACTED***" in (by_rule["FF-SEC-001"].evidence or "")


def test_rules_skip_sensitive_files_and_placeholder_values(tmp_path: Path) -> None:
    secret_value = "-".join(("real", "secret", "must", "not", "be", "read"))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(
        'api_key = "your-api-key-here"\n', encoding="utf-8"
    )
    (tmp_path / ".env").write_text(f"PASSWORD={secret_value}\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")

    findings = _scan(tmp_path)

    assert all(finding.rule_id != "FF-SEC-001" for finding in findings)


def test_rules_do_not_treat_environment_lookup_as_secret(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(
        'api_key = os.getenv("GOOGLE_API_KEY")\nclient(api_key=api_key)\n',
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")

    findings = _scan(tmp_path)

    assert all(finding.rule_id != "FF-SEC-001" for finding in findings)


def test_rules_detect_container_and_repository_gaps(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:latest\nWORKDIR /app\nCOPY . .\n", encoding="utf-8"
    )

    findings = _scan(tmp_path)
    rules = {finding.rule_id for finding in findings}

    assert {"FF-CONTAINER-001", "FF-CONTAINER-002", "FF-TEST-001", "FF-CI-001"} <= rules
