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
    GoogleAdkSecurityReviewer,
    SecurityReviewer,
    build_security_evidence,
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
        choices=["none", "security"],
        default="none",
        help="Run optional specialist agents after deterministic analysis",
    )
    return parser


def _quality_gate_failed(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _FAIL_ORDER[Severity(fail_on)]
    return any(_FAIL_ORDER[finding.severity] <= threshold for finding in findings)


def _run_analyze(
    repository: Path,
    output: Path,
    *,
    min_confidence: float = 0.0,
    fail_on: str = "none",
    exclusions: list[str] | None = None,
    agents: str = "none",
    security_reviewer: SecurityReviewer | None = None,
) -> int:
    started_at = datetime.now(UTC)
    started_clock = perf_counter()
    try:
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
        agent_runs: dict[str, AgentRunSummary] = {}
        agent_notes: list[str] = []
        if agents == "security":
            evidence = build_security_evidence(
                request.repository,
                metadata,
                deterministic_findings,
                effective_exclusions,
            )
            reviewer = security_reviewer or GoogleAdkSecurityReviewer()
            agent_started = perf_counter()
            try:
                agent_findings = asyncio.run(reviewer.review(evidence))
            except Exception as exc:  # noqa: BLE001 - specialist failure must be isolated
                agent_runs["security"] = AgentRunSummary(
                    status="failed",
                    duration_ms=max(0, round((perf_counter() - agent_started) * 1000)),
                    context_files=len(evidence.files),
                    context_chars=evidence.character_count,
                    prompt_risk_files=len(evidence.prompt_risk_files),
                    message=f"{type(exc).__name__}: review failed",
                )
                agent_notes.append("Security agent failed; deterministic analysis was preserved.")
            else:
                raw_findings.extend(agent_findings)
                agent_runs["security"] = AgentRunSummary(
                    status="completed",
                    finding_count=len(agent_findings),
                    duration_ms=max(0, round((perf_counter() - agent_started) * 1000)),
                    context_files=len(evidence.files),
                    context_chars=evidence.character_count,
                    prompt_risk_files=len(evidence.prompt_risk_files),
                    message="Evidence bundle was truncated." if evidence.truncated else None,
                )
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
    result = AnalysisResult(
        repository=metadata,
        findings=findings,
        quality=quality,
        score=score,
        execution=ExecutionSummary(
            status=(
                "completed_with_warnings"
                if any(run.status == "failed" for run in agent_runs.values())
                else "completed"
            ),
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            analyzer_mode=(
                "deterministic-rules+security-agent"
                if agents == "security"
                else "deterministic-rules"
            ),
            notes=[
                "Deterministic repository discovery completed.",
                f"Generated {len(deterministic_findings)} deterministic finding(s).",
                f"Published {quality.supported_finding_count} supported finding(s).",
                *agent_notes,
            ],
            agent_runs=agent_runs,
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
    print(f"Engineering score: {score.value}/100 (risk={score.risk_level})")
    print(f"Review: {review_path}")
    print(f"Findings JSON: {findings_path}")
    print(f"Execution summary: {summary_path}")

    if _quality_gate_failed(findings, fail_on):
        print(f"Quality gate failed: finding severity met --fail-on {fail_on}", file=sys.stderr)
        return 1
    return 0


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
            )
        )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
