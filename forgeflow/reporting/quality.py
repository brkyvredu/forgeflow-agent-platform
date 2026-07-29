from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from forgeflow.domain.models import (
    AnalysisQuality,
    AnalysisScore,
    Finding,
    Severity,
    ValidationStatus,
)
from forgeflow.reporting.verification import verify_findings

_SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 8,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_VALIDATION_ORDER = {
    ValidationStatus.DETERMINISTICALLY_CONFIRMED: 0,
    ValidationStatus.SEMANTICALLY_VERIFIED: 1,
    ValidationStatus.EVIDENCE_MATCHED: 2,
    ValidationStatus.HUMAN_REVIEW_REQUIRED: 3,
    ValidationStatus.UNVALIDATED: 4,
    ValidationStatus.UNSUPPORTED: 5,
}


def _safe_finding_path(repository: Path, relative_path: Path) -> Path | None:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        return None
    candidate = (repository / relative_path).resolve()
    try:
        candidate.relative_to(repository)
    except ValueError:
        return None
    return candidate


def _redacted_evidence_matches(evidence: str, source: str) -> bool:
    marker = "***REDACTED***"
    if marker not in evidence:
        return evidence.strip() in source
    prefix, suffix = evidence.split(marker, maxsplit=1)
    prefix_index = source.find(prefix.strip()) if prefix.strip() else 0
    if prefix_index < 0:
        return False
    suffix_start = prefix_index + len(prefix.strip())
    return not suffix.strip() or source.find(suffix.strip(), suffix_start) >= 0


def validate_findings(
    repository: Path, findings: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Validate file, line, evidence, and redaction support for candidate findings."""
    root = repository.expanduser().resolve(strict=True)
    supported: list[Finding] = []
    unsupported: list[Finding] = []

    for candidate in findings:
        finding = candidate.model_copy(deep=True)
        messages: list[str] = []

        if finding.file is None:
            if finding.line_start is not None or finding.line_end is not None:
                messages.append("Repository-wide finding cannot include a line range.")
            if finding.evidence:
                messages.append("Repository-wide evidence cannot be verified against a file.")
        else:
            path = _safe_finding_path(root, finding.file)
            if path is None:
                messages.append("Finding path escapes the repository root.")
            elif not path.is_file():
                messages.append("Finding file does not exist.")
            else:
                try:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    messages.append("Finding file could not be read.")
                    lines = []

                if finding.line_start is not None:
                    end = finding.line_end or finding.line_start
                    if finding.line_start > len(lines) or end > len(lines):
                        messages.append("Finding line range is outside the file.")
                    elif finding.evidence:
                        source = "\n".join(lines[finding.line_start - 1 : end])
                        if not _redacted_evidence_matches(finding.evidence, source):
                            messages.append(
                                "Evidence is not supported by the referenced line range."
                            )
                elif finding.evidence:
                    messages.append("Evidence requires a line range.")

        if finding.category == "secret-management" and finding.evidence:
            if "***REDACTED***" not in finding.evidence:
                messages.append("Secret-management evidence is not redacted.")

        finding.validation_messages = messages
        if messages:
            finding.validation_status = ValidationStatus.UNSUPPORTED
            unsupported.append(finding)
        else:
            finding.validation_status = ValidationStatus.EVIDENCE_MATCHED
            supported.append(finding)

    return supported, unsupported


def deduplicate_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge findings with the same stable fingerprint and retain all contributing sources."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.fingerprint].append(finding)

    merged: list[Finding] = []
    duplicate_count = 0
    for group in grouped.values():
        primary = min(group, key=lambda item: _SEVERITY_ORDER[item.severity]).model_copy(deep=True)
        primary.confidence = max(item.confidence for item in group)
        primary.sources = sorted({source for item in group for source in item.sources})
        primary.agent = primary.sources[0]
        strongest = min(group, key=lambda item: _VALIDATION_ORDER[item.validation_status])
        primary.validation_status = strongest.validation_status
        primary.scoring_eligible = any(item.scoring_eligible for item in group)
        primary.validation_messages = sorted(
            {message for item in group for message in item.validation_messages}
        )
        merged.append(primary)
        duplicate_count += len(group) - 1

    merged.sort(
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.file.as_posix() if finding.file else "",
            finding.line_start or 0,
            finding.rule_id,
        )
    )
    return merged, duplicate_count


def calculate_score(findings: list[Finding]) -> AnalysisScore:
    deductions = {severity.value: 0 for severity in Severity}
    for finding in findings:
        if finding.scoring_eligible:
            deductions[finding.severity.value] += _SEVERITY_DEDUCTIONS[finding.severity]

    value = max(0, 100 - sum(deductions.values()))
    if value >= 90:
        risk_level = "low"
    elif value >= 75:
        risk_level = "moderate"
    elif value >= 50:
        risk_level = "high"
    else:
        risk_level = "critical"
    return AnalysisScore(value=value, risk_level=risk_level, deductions=deductions)


def process_findings(
    repository: Path,
    findings: list[Finding],
    min_confidence: float,
) -> tuple[list[Finding], AnalysisQuality, AnalysisScore]:
    raw_count = len(findings)
    confidence_filtered = [item for item in findings if item.confidence >= min_confidence]
    below_confidence_count = raw_count - len(confidence_filtered)
    evidence_matched, unsupported = validate_findings(repository, confidence_filtered)
    verified = verify_findings(repository, evidence_matched)
    deduplicated, duplicates_merged = deduplicate_findings(verified)
    quality = AnalysisQuality(
        raw_finding_count=raw_count,
        supported_finding_count=len(deduplicated),
        unsupported_finding_count=len(unsupported),
        duplicates_merged=duplicates_merged,
        below_confidence_count=below_confidence_count,
        evidence_matched_count=sum(
            item.validation_status == ValidationStatus.EVIDENCE_MATCHED
            for item in deduplicated
        ),
        semantically_verified_count=sum(
            item.validation_status == ValidationStatus.SEMANTICALLY_VERIFIED
            for item in deduplicated
        ),
        deterministically_confirmed_count=sum(
            item.validation_status == ValidationStatus.DETERMINISTICALLY_CONFIRMED
            for item in deduplicated
        ),
        human_review_count=sum(
            item.validation_status == ValidationStatus.HUMAN_REVIEW_REQUIRED
            for item in deduplicated
        ),
        scoring_eligible_count=sum(item.scoring_eligible for item in deduplicated),
    )
    return deduplicated, quality, calculate_score(deduplicated)
