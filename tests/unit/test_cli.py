import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from forgeflow.cli import _normalize_agents, _run_analyze

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
    assert all(
        finding["validation_status"] == "deterministically_confirmed"
        for finding in findings
    )
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
    assert summary["execution"]["status"] == "degraded"
    assert summary["execution"]["agent_runs"]["security"]["status"] == "failed"
    assert summary["execution"]["score_provisional"] is True
    assert summary["execution"]["specialist_coverage"] == 0.0


class _FakeTestReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        from forgeflow.domain.models import Finding, Severity

        return [
            Finding(
                agent="test-agent",
                category="missing-boundary-test",
                severity=Severity.MEDIUM,
                title="Zero amount boundary is not verified",
                description="The amount boundary lacks a focused test.",
                recommendation="Add zero and negative amount tests.",
                file=Path("payment.py"),
                line_start=2,
                line_end=2,
                evidence="return amount > 0",
                confidence=0.91,
                rule_id="FF-AGENT-TEST-TEST",
            )
        ]


class _FailingTestReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        raise RuntimeError("provider unavailable")


def test_agent_selection_accepts_comma_separated_agents() -> None:
    assert _normalize_agents("test,security") == ("security", "test")
    assert _normalize_agents(("test", "security")) == ("security", "test")
    assert _normalize_agents("none") == ()


def test_agent_selection_rejects_unknown_or_mixed_none() -> None:
    with pytest.raises(ValueError, match="Unsupported agent"):
        _normalize_agents("performance")
    with pytest.raises(ValueError, match="cannot be combined"):
        _normalize_agents("none,test")


def test_analyze_runs_test_agent_and_publishes_supported_finding(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tests").mkdir()
    (repository / "payment.py").write_text(
        "def charge(amount):\n    return amount > 0\n", encoding="utf-8"
    )
    (repository / "tests" / "test_payment.py").write_text(
        "def test_charge():\n    assert True\n", encoding="utf-8"
    )
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="test",
        test_reviewer=_FakeTestReviewer(),
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert any(item["agent"] == "test-agent" for item in findings)
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["agent_runs"]["test"]["status"] == "completed"
    assert summary["execution"]["analyzer_mode"] == "deterministic-rules+test-agent"


def test_analyze_runs_security_and_test_agents_together(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tests").mkdir()
    (repository / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    (repository / "payment.py").write_text(
        "def charge(amount):\n    return amount > 0\n", encoding="utf-8"
    )
    (repository / "tests" / "test_payment.py").write_text(
        "def test_charge():\n    assert True\n", encoding="utf-8"
    )
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="security,test",
        security_reviewer=_FakeSecurityReviewer(),
        test_reviewer=_FakeTestReviewer(),
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert {item["agent"] for item in findings} >= {"security-agent", "test-agent"}
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert set(summary["execution"]["agent_runs"]) == {"security", "test"}
    assert (
        summary["execution"]["analyzer_mode"]
        == "deterministic-rules+security-agent+test-agent"
    )


def test_test_agent_failure_does_not_discard_security_result(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="security,test",
        security_reviewer=_FakeSecurityReviewer(),
        test_reviewer=_FailingTestReviewer(),
    )

    assert exit_code == 0
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["status"] == "degraded"
    assert summary["execution"]["agent_runs"]["security"]["status"] == "completed"
    assert summary["execution"]["agent_runs"]["test"]["status"] == "failed"
    assert summary["execution"]["score_provisional"] is True
    assert summary["execution"]["completed_agent_count"] == 1
    assert summary["execution"]["failed_agent_count"] == 1
    assert summary["execution"]["specialist_coverage"] == 0.5


class _AmbiguousSecurityReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        from forgeflow.domain.models import Finding, Severity

        return [
            Finding(
                agent="security-agent",
                category="Command Injection",
                severity=Severity.HIGH,
                title="Quoted environment variable may be injectable",
                description="A shell command expands an environment variable.",
                recommendation="Review command construction.",
                file=Path("services.yaml"),
                line_start=1,
                line_end=1,
                evidence='args: [\'git clone "$REPOSITORY_URL" /workspace\']',
                confidence=0.9,
                rule_id="FF-AGENT-SEC-AMBIGUOUS",
            )
        ]


def test_quality_gate_ignores_human_review_candidate(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "services.yaml").write_text(
        'args: [\'git clone "$REPOSITORY_URL" /workspace\']\n', encoding="utf-8"
    )
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="security",
        fail_on="high",
        security_reviewer=_AmbiguousSecurityReviewer(),
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    candidate = next(item for item in findings if item["agent"] == "security-agent")
    assert candidate["validation_status"] == "human_review_required"
    assert candidate["scoring_eligible"] is False
    assert candidate["severity"] == "info"


class _FakeArchitectureReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        from forgeflow.domain.models import Finding, Severity

        return [
            Finding(
                agent="architecture-agent",
                category="dependency-direction",
                severity=Severity.MEDIUM,
                title="CLI imports a concrete adapter",
                description="The entry point directly imports infrastructure code.",
                recommendation="Introduce an application-facing protocol.",
                file=Path("cli.py"),
                line_start=1,
                line_end=1,
                evidence="from infrastructure.database import Repository",
                confidence=0.88,
                rule_id="FF-AGENT-ARCH-TEST",
            )
        ]


def test_agent_selection_accepts_architecture_agent() -> None:
    assert _normalize_agents("architecture,test,security") == (
        "security",
        "test",
        "architecture",
    )


def test_analyze_runs_architecture_agent_as_human_review_candidate(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "cli.py").write_text(
        "from infrastructure.database import Repository\n", encoding="utf-8"
    )
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="architecture",
        architecture_reviewer=_FakeArchitectureReviewer(),
        fail_on="high",
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    candidate = next(item for item in findings if item["agent"] == "architecture-agent")
    assert candidate["validation_status"] == "human_review_required"
    assert candidate["scoring_eligible"] is False
    assert candidate["severity"] == "info"
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["agent_runs"]["architecture"]["status"] == "completed"
    assert summary["execution"]["analyzer_mode"] == (
        "deterministic-rules+architecture-agent"
    )


class _FakeReleaseReviewer:
    async def review(self, evidence: "RepositoryEvidence") -> list["Finding"]:
        from forgeflow.domain.models import Finding, Severity

        return [
            Finding(
                agent="release-agent",
                category="release-reproducibility",
                severity=Severity.MEDIUM,
                title="Release action uses a mutable version tag",
                description="The workflow references a mutable action tag.",
                recommendation="Pin the action to a reviewed commit SHA.",
                file=Path(".github/workflows/release.yml"),
                line_start=3,
                line_end=3,
                evidence="uses: docker/build-push-action@v6",
                confidence=0.89,
                rule_id="FF-AGENT-REL-TEST",
            )
        ]


def test_agent_selection_accepts_release_agent() -> None:
    assert _normalize_agents("release,architecture,test,security") == (
        "security",
        "test",
        "architecture",
        "release",
    )


def test_analyze_runs_release_agent_as_human_review_candidate(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    (repository / ".github" / "workflows").mkdir(parents=True)
    (repository / ".github" / "workflows" / "release.yml").write_text(
        "name: release\nsteps:\n  - uses: docker/build-push-action@v6\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"

    exit_code = _run_analyze(
        repository,
        output,
        agents="release",
        release_reviewer=_FakeReleaseReviewer(),
        fail_on="high",
    )

    assert exit_code == 0
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    candidate = next(item for item in findings if item["agent"] == "release-agent")
    assert candidate["validation_status"] == "human_review_required"
    assert candidate["scoring_eligible"] is False
    assert candidate["severity"] == "info"
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["execution"]["agent_runs"]["release"]["status"] == "completed"
    assert summary["execution"]["analyzer_mode"] == "deterministic-rules+release-agent"


def test_analyze_rejects_invalid_agent_retry_configuration(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    assert _run_analyze(repository, tmp_path / "attempts", agent_attempts=0) == 2
    assert _run_analyze(repository, tmp_path / "backoff", agent_backoff=-0.1) == 2
