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
        escaped = finding.evidence.replace("`", "\\`")
        evidence = f"\n\n**Evidence:** `{escaped}`"

    messages = ""
    if finding.validation_messages:
        rendered = "\n".join(f"  - {message}" for message in finding.validation_messages)
        messages = f"\n- Verification notes:\n{rendered}"

    sources = ", ".join(f"`{source}`" for source in finding.sources)
    eligible = "yes" if finding.scoring_eligible else "no"
    return f"""### [{finding.severity.value.upper()}] {finding.title}

- Rule: `{finding.rule_id}`
- Location: {location}
- Confidence: {finding.confidence:.2f}
- Verification status: `{finding.validation_status.value}`
- Scoring and quality-gate eligible: **{eligible}**
- Sources: {sources}{messages}

{finding.description}

**Recommendation:** {finding.recommendation}{evidence}
"""


def _severity_summary(findings: list[Finding]) -> str:
    severity_counts = Counter(finding.severity.value for finding in findings)
    return "\n".join(
        f"- {severity.capitalize()}: {severity_counts[severity]}"
        for severity in ("critical", "high", "medium", "low", "info")
        if severity_counts[severity]
    ) or "- No findings"


def _render_findings(findings: list[Finding], empty_message: str) -> str:
    return "\n".join(_finding_markdown(finding) for finding in findings) or empty_message


def _markdown_report(result: AnalysisResult) -> str:
    repository = result.repository
    languages = "\n".join(
        f"- {language}: {count} file(s)" for language, count in repository.languages.items()
    ) or "- No recognized source files"
    manifests = "\n".join(f"- `{item}`" for item in repository.manifests) or "- None detected"
    eligible_findings = [finding for finding in result.findings if finding.scoring_eligible]
    review_findings = [finding for finding in result.findings if not finding.scoring_eligible]
    agent_runs = "\n".join(
        f"- {name.capitalize()}: {run.status}; findings={run.finding_count}; "
        f"attempts={run.attempt_count}; context_files={run.context_files}; "
        f"duration_ms={run.duration_ms}"
        + (f"; error={run.error_type}" if run.error_type else "")
        for name, run in sorted(result.execution.agent_runs.items())
    ) or "- No specialist agents requested"
    score_suffix = " — provisional" if result.execution.score_provisional else ""
    coverage_percent = round(result.execution.specialist_coverage * 100)
    coverage_label = (
        "not requested"
        if result.execution.requested_agent_count == 0
        else (
            f"{result.execution.completed_agent_count}/"
            f"{result.execution.requested_agent_count} ({coverage_percent}%)"
        )
    )

    return f"""# ForgeFlow Repository Review

## Analysis status

This report contains bounded, read-only deterministic checks and any requested specialist-agent
review. No repository code was executed or modified. Repository content was treated as untrusted
data. Evidence matching, semantic verification, and deterministic confirmation are reported
separately. Only scoring-eligible findings affect the engineering score and `--fail-on` gate.

## Engineering score

- Score: **{result.score.value}/100{score_suffix}**
- Risk level: **{result.score.risk_level.capitalize()}**
- Scoring-eligible findings: **{result.quality.scoring_eligible_count}**
- Human-review candidates: **{result.quality.human_review_count}**
- Analysis status: **{result.execution.status}**
- Specialist coverage: **{coverage_label}**
- Note: {result.score.disclaimer}

## Repository

- Root: `{repository.root}`
- Files scanned: {repository.total_files}
- Aggregate bytes: {repository.total_bytes}
- Sensitive files skipped: {repository.skipped_sensitive_files}
- Symlinks skipped: {repository.skipped_symlinks}
- Custom exclusions skipped: {repository.skipped_custom_exclusions}
- Generated report directories skipped: {repository.skipped_generated_directories}

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
- Published evidence-backed findings: {result.quality.supported_finding_count}
- Deterministically confirmed: {result.quality.deterministically_confirmed_count}
- Semantically verified: {result.quality.semantically_verified_count}
- Evidence matched only: {result.quality.evidence_matched_count}
- Human review required: {result.quality.human_review_count}
- Scoring eligible: {result.quality.scoring_eligible_count}
- Unsupported findings rejected: {result.quality.unsupported_finding_count}
- Findings below confidence threshold: {result.quality.below_confidence_count}
- Duplicate findings merged: {result.quality.duplicates_merged}

## Scoring-eligible finding summary

{_severity_summary(eligible_findings)}

## Verified findings

{_render_findings(eligible_findings, "No scoring-eligible findings were generated.")}

## Human review candidates

{_render_findings(review_findings, "No human-review candidates were generated.")}
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
    eligible_counts = Counter(
        finding.severity.value for finding in result.findings if finding.scoring_eligible
    )
    summary_payload = {
        "repository": result.repository.model_dump(mode="json"),
        "analysis": {
            "finding_count": len(result.findings),
            "severity_counts": dict(sorted(severity_counts.items())),
            "scoring_eligible_severity_counts": dict(sorted(eligible_counts.items())),
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
