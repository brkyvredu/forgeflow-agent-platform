from pathlib import Path

from forgeflow.domain.models import Finding, Severity, ValidationStatus
from forgeflow.reporting import (
    calculate_score,
    deduplicate_findings,
    process_findings,
    validate_findings,
)


def _finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "agent": "security-agent",
        "category": "command-execution",
        "severity": Severity.HIGH,
        "title": "Shell execution enabled",
        "description": "Shell interpretation is enabled.",
        "recommendation": "Disable shell interpretation.",
        "file": Path("src/app.py"),
        "line_start": 1,
        "line_end": 1,
        "evidence": "subprocess.run(command, shell=True)",
        "confidence": 0.95,
        "rule_id": "FF-SEC-002",
    }
    payload.update(overrides)
    return Finding(**payload)


def test_validation_accepts_supported_evidence(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "subprocess.run(command, shell=True)\n", encoding="utf-8"
    )

    supported, unsupported = validate_findings(tmp_path, [_finding()])

    assert unsupported == []
    assert supported[0].validation_status == ValidationStatus.SUPPORTED


def test_validation_rejects_missing_or_unredacted_evidence(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text('password = "actual-secret"\n', encoding="utf-8")
    finding = _finding(
        category="secret-management",
        evidence='password = "actual-secret"',
        rule_id="FF-SEC-001",
    )

    supported, unsupported = validate_findings(tmp_path, [finding])

    assert supported == []
    assert unsupported[0].validation_status == ValidationStatus.UNSUPPORTED
    assert "Secret-management evidence is not redacted." in unsupported[0].validation_messages


def test_deduplication_merges_agent_sources() -> None:
    first = _finding(agent="security-agent")
    second = _finding(agent="release-agent")

    merged, duplicate_count = deduplicate_findings([first, second])

    assert duplicate_count == 1
    assert len(merged) == 1
    assert merged[0].sources == ["release-agent", "security-agent"]


def test_score_uses_bounded_severity_deductions() -> None:
    findings = [
        _finding(severity=Severity.CRITICAL, rule_id="A", title="A"),
        _finding(severity=Severity.HIGH, rule_id="B", title="B"),
        _finding(severity=Severity.MEDIUM, rule_id="C", title="C"),
        _finding(severity=Severity.LOW, rule_id="D", title="D"),
    ]

    score = calculate_score(findings)

    assert score.value == 68
    assert score.risk_level == "high"
    assert score.deductions == {
        "critical": 20,
        "high": 8,
        "medium": 3,
        "low": 1,
        "info": 0,
    }


def test_process_findings_filters_confidence_and_reports_quality(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "subprocess.run(command, shell=True)\n", encoding="utf-8"
    )
    supported = _finding(confidence=0.95)
    low_confidence = _finding(
        confidence=0.4,
        rule_id="FF-SEC-099",
        title="Low confidence candidate",
    )

    findings, quality, score = process_findings(
        tmp_path,
        [supported, low_confidence],
        min_confidence=0.8,
    )

    assert len(findings) == 1
    assert quality.raw_finding_count == 2
    assert quality.below_confidence_count == 1
    assert quality.supported_finding_count == 1
    assert score.value == 92
