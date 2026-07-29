import json
from pathlib import Path

from forgeflow.domain.models import AnalysisResult


def _markdown_report(result: AnalysisResult) -> str:
    repository = result.repository
    languages = "\n".join(
        f"- {language}: {count} file(s)" for language, count in repository.languages.items()
    ) or "- No recognized source files"
    manifests = "\n".join(f"- `{item}`" for item in repository.manifests) or "- None detected"

    return f"""# ForgeFlow Repository Review

## Analysis status

This report contains deterministic repository discovery only. Specialist-agent findings will be
added in the next v0.2 development increment. No repository code was executed or modified.

## Repository

- Root: `{repository.root}`
- Files scanned: {repository.total_files}
- Aggregate bytes: {repository.total_bytes}
- Sensitive files skipped: {repository.skipped_sensitive_files}
- Symlinks skipped: {repository.skipped_symlinks}

## Languages

{languages}

## Dependency manifests

{manifests}

## Engineering surfaces

- Test directories: {len(repository.test_directories)}
- CI files: {len(repository.ci_files)}
- Container files: {len(repository.container_files)}
- Kubernetes files: {len(repository.kubernetes_files)}

## Findings

No engineering findings were generated in this discovery-only increment.
"""


def write_analysis_reports(result: AnalysisResult, output_directory: Path) -> tuple[Path, Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    findings_path = output_directory / "findings.json"
    summary_path = output_directory / "execution-summary.json"
    review_path = output_directory / "review.md"

    findings_path.write_text(
        json.dumps(result.findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    summary_payload = {
        "repository": result.repository.model_dump(mode="json"),
        "execution": result.execution.model_dump(mode="json"),
    }
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    review_path.write_text(_markdown_report(result), encoding="utf-8")
    return review_path, findings_path, summary_path
