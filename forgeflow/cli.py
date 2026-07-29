import argparse
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from pydantic import ValidationError

from forgeflow.domain.models import AnalysisRequest, AnalysisResult, ExecutionSummary
from forgeflow.reporting import write_analysis_reports
from forgeflow.scanner import discover_repository, scan_repository


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
    return parser


def _run_analyze(repository: Path, output: Path) -> int:
    started_at = datetime.now(UTC)
    started_clock = perf_counter()
    try:
        request = AnalysisRequest(repository=repository, output_directory=output)
        metadata = discover_repository(request.repository)
        findings = scan_repository(request.repository, metadata)
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    finished_at = datetime.now(UTC)
    duration_ms = max(0, round((perf_counter() - started_clock) * 1000))
    severity_counts = Counter(finding.severity.value for finding in findings)
    result = AnalysisResult(
        repository=metadata,
        findings=findings,
        execution=ExecutionSummary(
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            notes=[
                "Deterministic repository discovery completed.",
                f"Generated {len(findings)} deterministic finding(s).",
                "Specialist-agent analysis is not enabled in this increment.",
            ],
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
    print(f"Review: {review_path}")
    print(f"Findings JSON: {findings_path}")
    print(f"Execution summary: {summary_path}")
    return 0


def main() -> None:
    args = _parser().parse_args()
    if args.command == "analyze":
        raise SystemExit(_run_analyze(args.repo, args.output))
    raise SystemExit(2)


if __name__ == "__main__":
    main()
