from __future__ import annotations

import os
import re
from pathlib import Path

from forgeflow.domain.models import Finding, RepositoryMetadata, Severity
from forgeflow.scanner.policy import (
    is_excluded_directory,
    is_scannable_text_file,
    is_sensitive_file,
)

_MAX_FILE_BYTES = 512_000
_MAX_FINDINGS_PER_RULE = 50

_SECRET_KEY = (
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret"
)
_QUOTED_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)[\"']?\b({_SECRET_KEY})\b[\"']?\s*[:=]\s*([\"'])([^\"']{{8,}})\2"
)
_UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)^\s*({_SECRET_KEY})\s*[:=]\s*([^\s#;,]{{8,}})\s*$"
)
_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")
_DOCKER_LATEST = re.compile(r"(?i)^\s*FROM\s+\S+:latest(?:\s|$)")
_DOCKER_FROM = re.compile(r"(?i)^\s*FROM\s+")
_DOCKER_USER = re.compile(r"(?i)^\s*USER\s+([^\s#]+)")

_PLACEHOLDER_MARKERS = (
    "${",
    "{",
    "{{",
    "<",
    "changeme",
    "dummy",
    "example",
    "fake",
    "placeholder",
    "replace-me",
    "replace_me",
    "redacted",
    "test",
    "your-",
    "your_",
)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _relative(path: Path, root: Path) -> Path:
    return Path(path.relative_to(root).as_posix())


def _iter_safe_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not is_excluded_directory(name) and not (current / name).is_symlink()
        ]
        for file_name in file_names:
            path = current / file_name
            if path.is_symlink() or is_sensitive_file(path) or not is_scannable_text_file(path):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
    return sorted(files)


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return not lowered or any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _mask_value(line: str, value: str) -> str:
    return line.replace(value, "***REDACTED***", 1).strip()[:240]


def _secret_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    config_suffixes = {".conf", ".properties", ".toml", ".yaml", ".yml"}
    for line_number, line in enumerate(lines, start=1):
        match = _QUOTED_SECRET_ASSIGNMENT.search(line)
        value_group = 3
        if match is None and path.suffix.lower() in config_suffixes:
            match = _UNQUOTED_SECRET_ASSIGNMENT.search(line)
            value_group = 2
        if match is None:
            continue
        value = match.group(value_group)
        if _looks_like_placeholder(value):
            continue
        findings.append(
            Finding(
                agent="deterministic-security",
                category="secret-management",
                severity=Severity.HIGH,
                title="Possible hard-coded credential",
                description=(
                    "A credential-like value appears to be embedded in a source-controlled "
                    "text file."
                ),
                recommendation=(
                    "Load the value from an environment variable or secret manager and rotate it "
                    "if it has been used outside a test environment."
                ),
                file=_relative(path, root),
                line_start=line_number,
                line_end=line_number,
                evidence=_mask_value(line, value),
                confidence=0.9,
                rule_id="FF-SEC-001",
            )
        )
        if len(findings) >= _MAX_FINDINGS_PER_RULE:
            break
    return findings


def _shell_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _SHELL_TRUE.search(line) is None:
            continue
        findings.append(
            Finding(
                agent="deterministic-security",
                category="command-execution",
                severity=Severity.HIGH,
                title="Shell execution enabled",
                description=(
                    "The code enables shell command interpretation, which can permit command "
                    "injection when any command fragment is influenced by untrusted input."
                ),
                recommendation=(
                    "Pass arguments as a list with shell execution disabled and validate all "
                    "external input."
                ),
                file=_relative(path, root),
                line_start=line_number,
                line_end=line_number,
                evidence=line.strip()[:240],
                confidence=0.97,
                rule_id="FF-SEC-002",
            )
        )
        if len(findings) >= _MAX_FINDINGS_PER_RULE:
            break
    return findings


def _docker_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    last_from_line = 0
    final_user: tuple[int, str] | None = None

    for line_number, line in enumerate(lines, start=1):
        if _DOCKER_FROM.search(line):
            last_from_line = line_number
            final_user = None
        if _DOCKER_LATEST.search(line):
            findings.append(
                Finding(
                    agent="deterministic-release",
                    category="container-supply-chain",
                    severity=Severity.MEDIUM,
                    title="Docker base image uses the latest tag",
                    description=(
                        "The latest tag is mutable and can make builds non-reproducible or "
                        "introduce unexpected upstream changes."
                    ),
                    recommendation=(
                        "Pin the base image to a versioned tag and preferably an image digest."
                    ),
                    file=_relative(path, root),
                    line_start=line_number,
                    line_end=line_number,
                    evidence=line.strip()[:240],
                    confidence=0.99,
                    rule_id="FF-CONTAINER-001",
                )
            )
        user_match = _DOCKER_USER.search(line)
        if user_match is not None and line_number > last_from_line:
            final_user = (line_number, user_match.group(1))

    if last_from_line:
        if final_user is None:
            findings.append(
                Finding(
                    agent="deterministic-release",
                    category="container-runtime",
                    severity=Severity.MEDIUM,
                    title="Final container stage has no non-root user",
                    description=(
                        "No USER instruction was found in the final image stage, so the container "
                        "will normally run with root privileges."
                    ),
                    recommendation=(
                        "Create a dedicated unprivileged user and set it with USER in the final "
                        "stage."
                    ),
                    file=_relative(path, root),
                    line_start=last_from_line,
                    line_end=last_from_line,
                    evidence=lines[last_from_line - 1].strip()[:240],
                    confidence=0.96,
                    rule_id="FF-CONTAINER-002",
                )
            )
        elif final_user[1].lower() in {"0", "root"}:
            findings.append(
                Finding(
                    agent="deterministic-release",
                    category="container-runtime",
                    severity=Severity.MEDIUM,
                    title="Final container stage explicitly runs as root",
                    description="The final image stage explicitly selects the root user.",
                    recommendation=(
                        "Create a dedicated unprivileged user and set it with USER in the final "
                        "stage."
                    ),
                    file=_relative(path, root),
                    line_start=final_user[0],
                    line_end=final_user[0],
                    evidence=lines[final_user[0] - 1].strip()[:240],
                    confidence=0.99,
                    rule_id="FF-CONTAINER-002",
                )
            )
    return findings


def _repository_findings(metadata: RepositoryMetadata) -> list[Finding]:
    findings: list[Finding] = []
    if metadata.languages and not metadata.test_directories:
        findings.append(
            Finding(
                agent="deterministic-test",
                category="test-coverage",
                severity=Severity.MEDIUM,
                title="No conventional test directory detected",
                description=(
                    "Source files were detected, but no conventional test directory was found "
                    "in the repository."
                ),
                recommendation=(
                    "Add automated tests and run them in CI. Configure ForgeFlow explicitly later "
                    "if the project uses a non-standard test layout."
                ),
                confidence=0.75,
                rule_id="FF-TEST-001",
            )
        )
    if not metadata.ci_files:
        findings.append(
            Finding(
                agent="deterministic-release",
                category="continuous-integration",
                severity=Severity.MEDIUM,
                title="No supported CI workflow detected",
                description=(
                    "No GitHub Actions, GitLab CI, Azure Pipelines, or Jenkins workflow was "
                    "detected."
                ),
                recommendation=(
                    "Add a CI workflow that runs tests, static analysis, and dependency checks "
                    "for every change."
                ),
                confidence=0.9,
                rule_id="FF-CI-001",
            )
        )
    return findings


def scan_repository(repository: Path, metadata: RepositoryMetadata) -> list[Finding]:
    """Run bounded, read-only deterministic checks over safe repository text files."""
    root = repository.expanduser().resolve(strict=True)
    findings = _repository_findings(metadata)

    for path in _iter_safe_text_files(root):
        lines = _read_lines(path)
        if not lines:
            continue
        findings.extend(_secret_findings(path, root, lines))
        findings.extend(_shell_findings(path, root, lines))
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            findings.extend(_docker_findings(path, root, lines))

    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.file.as_posix() if finding.file else "",
            finding.line_start or 0,
            finding.rule_id,
        ),
    )
