import json
from collections import Counter
from pathlib import Path

from forgeflow.domain.models import AnalysisResult, Finding


def _finding_markdown(finding: Finding) -> str:
    location = "Repository-wide"
    if finding.file is not None:
        location = f"`{finding.file.as_posix()}`"
        if finding.line_start is not None:
            location += f":{finding.line_start}"

    evidence = ""
    if finding.evidence:
        evidence = f"\n\n**Evidence:** `{finding.evidence.replace('`', '\\`')}`"

    sources = ", ".join(f"`{source}`" for source in finding.sources)
    return f"""### [{finding.severity.value.upper()}] {finding.title}

- Rule: `{finding.rule_id}`
- Location: {location}
- Confidence: {finding.confidence:.2f}
- Evidence status: `{finding.validation_status.value}`
- Sources: {sources}

{finding.description}

**Recommendation:** {finding.recommendation}{evidence}
"""


def _markdown_report(result: AnalysisResult) -> str:
    repository = result.repository
    languages = "\n".join(
        f"- {language}: {count} file(s)" for language, count in repository.languages.items()
    ) or "- No recognized source files"
    manifests = "\n".join(f"- `{item}`" for item in repository.manifests) or "- None detected"
    severity_counts = Counter(finding.severity.value for finding in result.findings)
    finding_summary = "\n".join(
        f"- {severity.capitalize()}: {severity_counts[severity]}"
        for severity in ("critical", "high", "medium", "low", "info")
        if severity_counts[severity]
    ) or "- No findings"
    findings = "\n".join(_finding_markdown(finding) for finding in result.findings)
    agent_runs = "\n".join(
        f"- {name.capitalize()}: {run.status}; findings={run.finding_count}; "
        f"context_files={run.context_files}; duration_ms={run.duration_ms}"
        for name, run in sorted(result.execution.agent_runs.items())
    ) or "- No specialist agents requested"
    if not findings:
        findings = "No supported deterministic engineering findings were generated."

    return f"""# ForgeFlow Repository Review

## Analysis status

This report contains bounded, read-only deterministic checks and any requested specialist-agent
review. No repository code was executed or modified. Repository content was treated as untrusted
data. Only evidence-supported findings at or above the configured confidence threshold are
published.

## Engineering score

- Score: **{result.score.value}/100**
- Risk level: **{result.score.risk_level.capitalize()}**
- Note: {result.score.disclaimer}

## Repository

- Root: `{repository.root}`
- Files scanned: {repository.total_files}
- Aggregate bytes: {repository.total_bytes}
- Sensitive files skipped: {repository.skipped_sensitive_files}
- Symlinks skipped: {repository.skipped_symlinks}
- Custom exclusions skipped: {repository.skipped_custom_exclusions}

## Languages

{languages}

## Dependency manifests

{manifests}

## Engineering surfaces

- Test directories: {len(repository.test_directories)}
- CI files: {len(repository.ci_files)}
- Container files: {len(repository.container_files)}
- Kubernetes files: {len(repository.kubernetes_files)}

## Agent execution

{agent_runs}

## Finding quality

- Raw findings: {result.quality.raw_finding_count}
- Supported findings: {result.quality.supported_finding_count}
- Unsupported findings rejected: {result.quality.unsupported_finding_count}
- Findings below confidence threshold: {result.quality.below_confidence_count}
- Duplicate findings merged: {result.quality.duplicates_merged}

## Finding summary

{finding_summary}

## Findings

{findings}
"""


def write_analysis_reports(
    result: AnalysisResult, output_directory: Path
) -> tuple[Path, Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    findings_path = output_directory / "findings.json"
    summary_path = output_directory / "execution-summary.json"
    review_path = output_directory / "review.md"

    findings_payload = [finding.model_dump(mode="json") for finding in result.findings]
    findings_path.write_text(
        json.dumps(findings_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    severity_counts = Counter(finding.severity.value for finding in result.findings)
    summary_payload = {
        "repository": result.repository.model_dump(mode="json"),
        "analysis": {
            "finding_count": len(result.findings),
            "severity_counts": dict(sorted(severity_counts.items())),
            "quality": result.quality.model_dump(mode="json"),
            "score": result.score.model_dump(mode="json"),
        },
        "execution": result.execution.model_dump(mode="json"),
    }
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    review_path.write_text(_markdown_report(result), encoding="utf-8")
    return review_path, findings_path, summary_path
