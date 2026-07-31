import argparse
import asyncio
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from pydantic import ValidationError

from forgeflow.domain.models import (
    AgentRunSummary,
    AnalysisRequest,
    AnalysisResult,
    ExecutionSummary,
    Finding,
    Severity,
)
from forgeflow.orchestration import (
    ArchitectureReviewer,
    GoogleAdkArchitectureReviewer,
    GoogleAdkReleaseReviewer,
    GoogleAdkSecurityReviewer,
    GoogleAdkTestReviewer,
    ReleaseReviewer,
    SecurityReviewer,
    SpecialistJob,
    TestReviewer,
    build_architecture_evidence,
    build_release_evidence,
    build_security_evidence,
    build_test_evidence,
    run_specialist_jobs,
)
from forgeflow.reporting import process_findings, write_analysis_reports
from forgeflow.scanner import discover_repository, scan_repository

_FAIL_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forgeflow",
        description="ForgeFlow multi-agent engineering assistant",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a local repository without modifying or executing it",
    )
    analyze.add_argument("--repo", required=True, type=Path, help="Local repository path")
    analyze.add_argument(
        "--output",
        type=Path,
        default=Path("reports"),
        help="Output directory (default: ./reports)",
    )
    analyze.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Discard findings below this confidence threshold (0.0-1.0)",
    )
    analyze.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium", "low", "info"],
        default="none",
        help="Return exit code 1 when a finding meets this severity threshold",
    )
    analyze.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a repository-relative glob; may be repeated",
    )
    analyze.add_argument(
        "--agents",
        default="none",
        metavar="LIST",
        help=(
            "Comma-separated specialist agents: security, test, architecture, release, "
            "or none"
        ),
    )
    analyze.add_argument(
        "--agent-attempts",
        type=int,
        default=3,
        help="Maximum attempts for transient specialist-provider failures (default: 3)",
    )
    analyze.add_argument(
        "--agent-backoff",
        type=float,
        default=1.0,
        help="Initial retry backoff in seconds before exponential growth (default: 1.0)",
    )
    analyze.add_argument(
        "--agent-concurrency",
        type=int,
        default=2,
        help="Maximum specialist reviews in flight at once (default: 2)",
    )
    analyze.add_argument(
        "--min-agent-coverage",
        type=float,
        default=0.0,
        help=(
            "Return exit code 1 when completed/requested specialist coverage is below "
            "this threshold (0.0-1.0; default: 0.0)"
        ),
    )
    return parser


def _normalize_agents(value: str | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(value, tuple):
        requested = [item.strip().lower() for item in value]
    else:
        requested = [item.strip().lower() for item in value.split(",")]
    requested = [item for item in requested if item]
    if not requested or requested == ["none"]:
        return ()
    if "none" in requested:
        raise ValueError("--agents none cannot be combined with specialist agents")
    supported = ("security", "test", "architecture", "release")
    invalid = sorted(set(requested) - set(supported))
    if invalid:
        raise ValueError(f"Unsupported agent(s): {', '.join(invalid)}")
    return tuple(agent for agent in supported if agent in requested)


def _quality_gate_failed(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _FAIL_ORDER[Severity(fail_on)]
    return any(
        finding.scoring_eligible and _FAIL_ORDER[finding.severity] <= threshold
        for finding in findings
    )


def _run_analyze(
    repository: Path,
    output: Path,
    *,
    min_confidence: float = 0.0,
    fail_on: str = "none",
    exclusions: list[str] | None = None,
    agents: str | tuple[str, ...] = "none",
    security_reviewer: SecurityReviewer | None = None,
    test_reviewer: TestReviewer | None = None,
    architecture_reviewer: ArchitectureReviewer | None = None,
    release_reviewer: ReleaseReviewer | None = None,
    agent_attempts: int = 3,
    agent_backoff: float = 1.0,
    agent_concurrency: int = 2,
    min_agent_coverage: float = 0.0,
) -> int:
    started_at = datetime.now(UTC)
    started_clock = perf_counter()
    try:
        if not 1 <= agent_attempts <= 5:
            raise ValueError("--agent-attempts must be between 1 and 5")
        if not 0.0 <= agent_backoff <= 30.0:
            raise ValueError("--agent-backoff must be between 0 and 30 seconds")
        if not 1 <= agent_concurrency <= 4:
            raise ValueError("--agent-concurrency must be between 1 and 4")
        if not 0.0 <= min_agent_coverage <= 1.0:
            raise ValueError("--min-agent-coverage must be between 0.0 and 1.0")
        selected_agents = _normalize_agents(agents)
        if min_agent_coverage > 0.0 and not selected_agents:
            raise ValueError(
                "--min-agent-coverage requires at least one specialist in --agents"
            )
        request = AnalysisRequest(
            repository=repository,
            output_directory=output,
            min_confidence=min_confidence,
            exclusions=exclusions or [],
        )
        effective_exclusions = list(request.exclusions)
        try:
            relative_output = request.output_directory.relative_to(request.repository)
        except ValueError:
            relative_output = None
        if relative_output == Path("."):
            raise ValueError("Output directory cannot be the repository root")
        if relative_output is not None:
            effective_exclusions.append(f"{relative_output.as_posix()}/**")

        metadata = discover_repository(request.repository, effective_exclusions)
        deterministic_findings = scan_repository(
            request.repository, metadata, effective_exclusions
        )
        raw_findings = list(deterministic_findings)
        jobs: list[SpecialistJob] = []
        if "security" in selected_agents:
            jobs.append(
                SpecialistJob(
                    name="security",
                    reviewer=security_reviewer or GoogleAdkSecurityReviewer(),
                    evidence=build_security_evidence(
                        request.repository,
                        metadata,
                        deterministic_findings,
                        effective_exclusions,
                    ),
                    max_attempts=agent_attempts,
                    retry_backoff_seconds=agent_backoff,
                )
            )
        if "test" in selected_agents:
            jobs.append(
                SpecialistJob(
                    name="test",
                    reviewer=test_reviewer or GoogleAdkTestReviewer(),
                    evidence=build_test_evidence(
                        request.repository,
                        metadata,
                        deterministic_findings,
                        effective_exclusions,
                    ),
                    max_attempts=agent_attempts,
                    retry_backoff_seconds=agent_backoff,
                )
            )
        if "architecture" in selected_agents:
            jobs.append(
                SpecialistJob(
                    name="architecture",
                    reviewer=(
                        architecture_reviewer or GoogleAdkArchitectureReviewer()
                    ),
                    evidence=build_architecture_evidence(
                        request.repository,
                        metadata,
                        deterministic_findings,
                        effective_exclusions,
                    ),
                    max_attempts=agent_attempts,
                    retry_backoff_seconds=agent_backoff,
                )
            )

        if "release" in selected_agents:
            jobs.append(
                SpecialistJob(
                    name="release",
                    reviewer=release_reviewer or GoogleAdkReleaseReviewer(),
                    evidence=build_release_evidence(
                        request.repository,
                        metadata,
                        deterministic_findings,
                        effective_exclusions,
                    ),
                    max_attempts=agent_attempts,
                    retry_backoff_seconds=agent_backoff,
                )
            )

        agent_runs: dict[str, AgentRunSummary] = {}
        agent_notes: list[str] = []
        for specialist_result in asyncio.run(
            run_specialist_jobs(jobs, max_concurrency=agent_concurrency)
        ):
            raw_findings.extend(specialist_result.findings)
            agent_runs[specialist_result.name] = specialist_result.summary
            if specialist_result.note:
                agent_notes.append(specialist_result.note)
        findings, quality, score = process_findings(
            request.repository,
            raw_findings,
            request.min_confidence,
        )
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    finished_at = datetime.now(UTC)
    duration_ms = max(0, round((perf_counter() - started_clock) * 1000))
    severity_counts = Counter(finding.severity.value for finding in findings)
    requested_agent_count = len(selected_agents)
    completed_agent_count = sum(run.status == "completed" for run in agent_runs.values())
    failed_agent_count = sum(run.status == "failed" for run in agent_runs.values())
    specialist_coverage = (
        completed_agent_count / requested_agent_count if requested_agent_count else 1.0
    )
    degraded_note = (
        f"Analysis completed in degraded mode: {failed_agent_count} of "
        f"{requested_agent_count} specialist agents failed."
        if failed_agent_count
        else None
    )
    coverage_gate_passed = specialist_coverage >= min_agent_coverage
    coverage_note = (
        f"Specialist coverage gate: {specialist_coverage:.0%} completed; "
        f"minimum required {min_agent_coverage:.0%}."
    )
    result = AnalysisResult(
        repository=metadata,
        findings=findings,
        quality=quality,
        score=score,
        execution=ExecutionSummary(
            status="degraded" if failed_agent_count else "completed",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            analyzer_mode=(
                "deterministic-rules"
                + "".join(f"+{agent}-agent" for agent in selected_agents)
            ),
            notes=[
                "Deterministic repository discovery completed.",
                f"Generated {len(deterministic_findings)} deterministic finding(s).",
                f"Published {quality.supported_finding_count} evidence-backed finding(s).",
                f"Eligible for score and quality gate: {quality.scoring_eligible_count}.",
                coverage_note,
                *([degraded_note] if degraded_note else []),
                *agent_notes,
            ],
            agent_runs=agent_runs,
            requested_agent_count=requested_agent_count,
            completed_agent_count=completed_agent_count,
            failed_agent_count=failed_agent_count,
            specialist_coverage=specialist_coverage,
            score_provisional=bool(failed_agent_count),
            specialist_concurrency=agent_concurrency,
            minimum_specialist_coverage=min_agent_coverage,
            coverage_gate_passed=coverage_gate_passed,
        ),
    )
    review_path, findings_path, summary_path = write_analysis_reports(
        result, request.output_directory
    )

    counts = ", ".join(
        f"{severity}={severity_counts[severity]}"
        for severity in ("critical", "high", "medium", "low", "info")
        if severity_counts[severity]
    )
    print(f"Repository analysis completed: {request.repository}")
    print(f"Findings: {len(findings)}" + (f" ({counts})" if counts else ""))
    provisional = " — provisional" if failed_agent_count else ""
    print(
        f"Engineering score: {score.value}/100{provisional} (risk={score.risk_level}; "
        f"eligible={quality.scoring_eligible_count})"
    )
    print(
        f"Specialist coverage: {completed_agent_count}/{requested_agent_count} "
        f"({specialist_coverage:.0%}); required={min_agent_coverage:.0%}"
    )
    if degraded_note:
        print(degraded_note)
    print(f"Review: {review_path}")
    print(f"Findings JSON: {findings_path}")
    print(f"Execution summary: {summary_path}")

    gate_failed = False
    if _quality_gate_failed(findings, fail_on):
        print(f"Quality gate failed: finding severity met --fail-on {fail_on}", file=sys.stderr)
        gate_failed = True
    if not coverage_gate_passed:
        print(
            "Quality gate failed: specialist coverage "
            f"{specialist_coverage:.0%} is below --min-agent-coverage "
            f"{min_agent_coverage:.0%}",
            file=sys.stderr,
        )
        gate_failed = True
    return 1 if gate_failed else 0


def main() -> None:
    args = _parser().parse_args()
    if args.command == "analyze":
        raise SystemExit(
            _run_analyze(
                args.repo,
                args.output,
                min_confidence=args.min_confidence,
                fail_on=args.fail_on,
                exclusions=args.exclude,
                agents=args.agents,
                agent_attempts=args.agent_attempts,
                agent_backoff=args.agent_backoff,
                agent_concurrency=args.agent_concurrency,
                min_agent_coverage=args.min_agent_coverage,
            )
        )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
