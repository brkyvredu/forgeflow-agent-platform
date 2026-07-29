import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from pydantic import ValidationError

from forgeflow.domain.models import AnalysisRequest, AnalysisResult, ExecutionSummary
from forgeflow.reporting import write_analysis_reports
from forgeflow.scanner import discover_repository


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
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    finished_at = datetime.now(UTC)
    duration_ms = max(0, round((perf_counter() - started_clock) * 1000))
    result = AnalysisResult(
        repository=metadata,
        findings=[],
        execution=ExecutionSummary(
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            notes=[
                "Deterministic repository discovery completed.",
                "Specialist-agent analysis is not enabled in this increment.",
            ],
        ),
    )
    review_path, findings_path, summary_path = write_analysis_reports(
        result, request.output_directory
    )

    print(f"Repository discovery completed: {request.repository}")
    print(f"Review: {review_path}")
    print(f"Findings: {findings_path}")
    print(f"Execution summary: {summary_path}")
    return 0


def main() -> None:
    args = _parser().parse_args()
    if args.command == "analyze":
        raise SystemExit(_run_analyze(args.repo, args.output))
    raise SystemExit(2)


if __name__ == "__main__":
    main()
