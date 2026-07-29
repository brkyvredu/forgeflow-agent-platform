import json
from pathlib import Path
from typing import TYPE_CHECKING

from forgeflow.cli import _run_analyze

if TYPE_CHECKING:
    from forgeflow.domain.models import Finding
    from forgeflow.orchestration.context import RepositoryEvidence


def test_analyze_writes_deterministic_reports(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.py").write_text("print('hello')", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(repository, output)

    assert exit_code == 0
    assert (output / "review.md").exists()
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert {finding["rule_id"] for finding in findings} == {"FF-CI-001", "FF-TEST-001"}
    assert all(finding["validation_status"] == "supported" for finding in findings)
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["total_files"] == 1
    assert summary["analysis"]["finding_count"] == 2
    assert summary["analysis"]["score"]["value"] == 94
    assert summary["execution"]["status"] == "completed"


def test_analyze_rejects_missing_repository(tmp_path: Path) -> None:
    exit_code = _run_analyze(tmp_path / "missing", tmp_path / "reports")
    assert exit_code == 2


def test_analyze_quality_gate_uses_severity_threshold(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.py").write_text("print('hello')", encoding="utf-8")

    assert _run_analyze(repository, tmp_path / "high", fail_on="high") == 0
    assert _run_analyze(repository, tmp_path / "medium", fail_on="medium") == 1


def test_analyze_filters_low_confidence_findings(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.py").write_text("print('hello')", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(repository, output, min_confidence=0.8)

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert {finding["rule_id"] for finding in findings} == {"FF-CI-001"}
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["analysis"]["quality"]["below_confidence_count"] == 1


def test_analyze_excludes_existing_output_directory_from_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.py").write_text("print('hello')", encoding="utf-8")
    output = repository / "custom-analysis-output"
    output.mkdir()
    (output / "prior.json").write_text(
        '{"evidence": "subprocess.run(command, shell=True)"}', encoding="utf-8"
    )

    exit_code = _run_analyze(repository, output)

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert all(finding["rule_id"] != "FF-SEC-002" for finding in findings)


class _FakeSecurityReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        from forgeflow.domain.models import Finding, Severity

        return [
            Finding(
                agent="security-agent",
                category="unsafe-evaluation",
                severity=Severity.HIGH,
                title="Untrusted input reaches eval",
                description="The file evaluates untrusted input.",
                recommendation="Use a constrained parser.",
                file=Path("app.py"),
                line_start=1,
                line_end=1,
                evidence="eval(user_input)",
                confidence=0.95,
                rule_id="FF-AGENT-SEC-TEST",
            )
        ]


class _FailingSecurityReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        raise RuntimeError("provider unavailable")


def test_analyze_runs_security_agent_and_publishes_supported_finding(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="security",
        security_reviewer=_FakeSecurityReviewer(),
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert any(item["agent"] == "security-agent" for item in findings)
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["agent_runs"]["security"]["status"] == "completed"
    assert summary["execution"]["analyzer_mode"] == "deterministic-rules+security-agent"


def test_analyze_preserves_deterministic_results_when_security_agent_fails(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="security",
        security_reviewer=_FailingSecurityReviewer(),
    )

    assert exit_code == 0
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["status"] == "completed_with_warnings"
    assert summary["execution"]["agent_runs"]["security"]["status"] == "failed"
