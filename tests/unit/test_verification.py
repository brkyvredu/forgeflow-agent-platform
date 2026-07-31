from pathlib import Path

from forgeflow.domain.models import Finding, Severity, ValidationStatus
from forgeflow.reporting.verification import verify_findings


def _finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "agent": "security-agent",
        "category": "Command Injection",
        "severity": Severity.HIGH,
        "title": "Shell command execution with environment variable",
        "description": "A shell command expands an environment variable.",
        "recommendation": "Avoid shell interpretation.",
        "file": Path("infra/services.yaml"),
        "line_start": 1,
        "line_end": 1,
        "evidence": 'args: [\'git clone "$REPOSITORY_URL" /workspace\']',
        "confidence": 0.8,
        "rule_id": "FF-AGENT-SEC-COMMAND",
        "validation_status": ValidationStatus.EVIDENCE_MATCHED,
    }
    payload.update(overrides)
    return Finding(**payload)


def test_quoted_environment_variable_command_claim_requires_human_review(
    tmp_path: Path,
) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "services.yaml").write_text(
        'args: [\'git clone "$REPOSITORY_URL" /workspace\']\n', encoding="utf-8"
    )

    verified = verify_findings(tmp_path, [_finding()])[0]

    assert verified.validation_status == ValidationStatus.HUMAN_REVIEW_REQUIRED
    assert verified.scoring_eligible is False
    assert verified.severity == Severity.INFO


def test_compose_default_credential_is_verified_and_downgraded(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-forgeflow}\n", encoding="utf-8"
    )
    finding = _finding(
        category="Hardcoded Credentials",
        title="Hardcoded default database credentials",
        description="A default password is configured.",
        file=Path("docker-compose.yml"),
        evidence="POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-forgeflow}",
        rule_id="FF-AGENT-SEC-CREDENTIAL",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.SEMANTICALLY_VERIFIED
    assert verified.scoring_eligible is True
    assert verified.severity == Severity.LOW


def test_deterministic_finding_is_confirmed_and_score_eligible(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    finding = _finding(
        agent="deterministic-security",
        category="unsafe-evaluation",
        file=Path("app.py"),
        evidence="eval(user_input)",
        rule_id="FF-SEC-900",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.DETERMINISTICALLY_CONFIRMED
    assert verified.scoring_eligible is True


def test_test_absence_claim_is_not_scored_when_symbol_has_tests(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "cli.py").write_text(
        "def normalize_agents(value):\n    return value\n", encoding="utf-8"
    )
    (tmp_path / "tests" / "test_cli.py").write_text(
        "from cli import normalize_agents\n\ndef test_invalid():\n    normalize_agents('bad')\n",
        encoding="utf-8",
    )
    finding = _finding(
        agent="test-agent",
        category="untested-error-path",
        severity=Severity.MEDIUM,
        title="Agent selection validation is untested",
        description="No tests cover invalid values.",
        recommendation="Add invalid value tests.",
        file=Path("cli.py"),
        line_start=1,
        evidence="def normalize_agents(value):",
        rule_id="FF-AGENT-TEST-ABSENCE",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.HUMAN_REVIEW_REQUIRED
    assert verified.scoring_eligible is False
    assert verified.severity == Severity.INFO


def test_test_absence_claim_is_verified_when_no_reference_exists(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "payment.py").write_text(
        "def charge(amount):\n    return amount > 0\n", encoding="utf-8"
    )
    (tmp_path / "tests" / "test_smoke.py").write_text(
        "def test_smoke():\n    assert True\n", encoding="utf-8"
    )
    finding = _finding(
        agent="test-agent",
        category="untested-boundary",
        severity=Severity.MEDIUM,
        title="Charge boundary is untested",
        description="No focused test covers charge.",
        recommendation="Add a focused boundary test.",
        file=Path("payment.py"),
        line_start=2,
        line_end=2,
        evidence="return amount > 0",
        rule_id="FF-AGENT-TEST-BOUNDARY",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.SEMANTICALLY_VERIFIED
    assert verified.scoring_eligible is True


def test_contradicted_redaction_test_claim_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    source = tmp_path / "tests" / "test_redaction.py"
    source.write_text(
        "def test_redaction():\n"
        "    raw = 'password = \"production-password-123\"'\n"
        "    prompt = raw.replace('production-password-123', '***REDACTED***')\n"
        "    assert 'production-password-123' not in prompt\n",
        encoding="utf-8",
    )
    finding = _finding(
        agent="test-agent",
        category="misleading-test",
        severity=Severity.MEDIUM,
        title="Credential redaction test writes pre-redacted content",
        description="The test input is already redacted and the assertion passes vacuously.",
        recommendation="Write an unredacted password before redaction.",
        file=Path("tests/test_redaction.py"),
        line_start=1,
        line_end=4,
        evidence="assert 'production-password-123' not in prompt",
        rule_id="FF-AGENT-TEST-CONTRADICTION",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.UNSUPPORTED
    assert verified.scoring_eligible is False


def test_unverified_external_route_claim_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "services.yaml").write_text(
        "httpGet: { path: /list-apps, port: 8000 }\n", encoding="utf-8"
    )
    finding = _finding(
        agent="release-agent",
        category="deployment",
        severity=Severity.MEDIUM,
        title="Invalid HTTP readiness probe path",
        description=(
            "The readiness probe uses /list-apps, but the external API server exposes /apps."
        ),
        recommendation="Change the readiness probe route to /apps.",
        file=Path("infra/services.yaml"),
        line_start=1,
        line_end=1,
        evidence="httpGet: { path: /list-apps, port: 8000 }",
        rule_id="FF-AGENT-REL-ROUTE",
    )

    verified = verify_findings(tmp_path, [finding])[0]

    assert verified.validation_status == ValidationStatus.UNSUPPORTED
    assert verified.scoring_eligible is False
