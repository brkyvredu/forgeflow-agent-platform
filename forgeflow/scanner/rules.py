from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from forgeflow.domain.models import Finding, RepositoryMetadata, Severity
from forgeflow.scanner.policy import (
    is_excluded_directory,
    is_forgeflow_report_file,
    is_scannable_text_file,
    is_sensitive_file,
    matches_custom_exclusion,
)

_MAX_FILE_BYTES = 512_000
_MAX_FINDINGS_PER_RULE = 50

_CREDENTIAL_KEY_PATTERN = (
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret"
)
_QUOTED_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)[\"']?\b({_CREDENTIAL_KEY_PATTERN})\b[\"']?\s*[:=]\s*([\"'])([^\"']{{8,}})\2"
)
_UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)^\s*({_CREDENTIAL_KEY_PATTERN})\s*[:=]\s*([^\s#;,]{{8,}})\s*$"
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


def _iter_safe_text_files(
    root: Path, exclusions: list[str] | tuple[str, ...] = ()
) -> list[Path]:
    files: list[Path] = []
    for current_directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not is_excluded_directory(name)
            and not (current / name).is_symlink()
            and not matches_custom_exclusion(
                (current / name).relative_to(root).as_posix(), exclusions
            )
        ]
        for file_name in file_names:
            path = current / file_name
            if (
                path.is_symlink()
                or is_forgeflow_report_file(path)
                or matches_custom_exclusion(path.relative_to(root).as_posix(), exclusions)
                or is_sensitive_file(path)
                or not is_scannable_text_file(path)
            ):
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


def _credential_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    return None


def _literal_string(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_credential_name(name: str | None) -> bool:
    return bool(name and re.search(_CREDENTIAL_KEY_PATTERN, name, re.IGNORECASE))


def _python_secret_candidates(tree: ast.AST) -> list[tuple[ast.AST, str]]:
    candidates: list[tuple[ast.AST, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = _literal_string(node.value)
            if value is None:
                continue
            for target in node.targets:
                if _is_credential_name(_credential_name(target)):
                    candidates.append((node, value))
        elif isinstance(node, ast.AnnAssign):
            value = _literal_string(node.value)
            if value is not None and _is_credential_name(_credential_name(node.target)):
                candidates.append((node, value))
        elif isinstance(node, ast.NamedExpr):
            value = _literal_string(node.value)
            if value is not None and _is_credential_name(_credential_name(node.target)):
                candidates.append((node, value))
        elif isinstance(node, ast.Dict):
            for key, value_node in zip(node.keys, node.values, strict=False):
                key_value = _literal_string(key)
                value = _literal_string(value_node)
                if value is not None and _is_credential_name(key_value):
                    candidates.append((value_node, value))
    return candidates


def _python_subprocess_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    modules = {"subprocess"}
    functions: set[str] = set()
    supported = {
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "run",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for alias in node.names:
                if alias.name in supported:
                    functions.add(alias.asname or alias.name)
    return modules, functions


def _is_subprocess_call(
    call: ast.Call, module_aliases: set[str], function_aliases: set[str]
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in function_aliases
    if not isinstance(call.func, ast.Attribute):
        return False
    return (
        isinstance(call.func.value, ast.Name)
        and call.func.value.id in module_aliases
        and call.func.attr
        in {
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
            "run",
        }
    )


def _source_line(lines: list[str], node: ast.AST) -> str:
    line_number = getattr(node, "lineno", 0)
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _secret_finding(
    path: Path,
    root: Path,
    line_number: int,
    line_end: int,
    line: str,
    value: str,
) -> Finding:
    return Finding(
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
        line_end=line_end,
        evidence=_mask_value(line, value),
        confidence=0.9,
        rule_id="FF-SEC-001",
    )


def _python_security_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
    source = "\n".join(lines)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node, value in _python_secret_candidates(tree):
        if len(value) < 8 or _looks_like_placeholder(value):
            continue
        line_number = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_number) or line_number
        findings.append(
            _secret_finding(
                path,
                root,
                line_number,
                line_end,
                _source_line(lines, node),
                value,
            )
        )
        if len(findings) >= _MAX_FINDINGS_PER_RULE:
            break

    module_aliases, function_aliases = _python_subprocess_aliases(tree)
    shell_count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_subprocess_call(
            node, module_aliases, function_aliases
        ):
            continue
        shell_enabled = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        if not shell_enabled:
            continue
        line_number = node.lineno
        line_end = node.end_lineno or line_number
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
                line_end=line_end,
                evidence=_source_line(lines, node).strip()[:240],
                confidence=0.97,
                rule_id="FF-SEC-002",
            )
        )
        shell_count += 1
        if shell_count >= _MAX_FINDINGS_PER_RULE:
            break
    return findings


def _text_secret_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
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
            _secret_finding(path, root, line_number, line_number, line, value)
        )
        if len(findings) >= _MAX_FINDINGS_PER_RULE:
            break
    return findings


def _text_shell_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
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


def _security_findings(path: Path, root: Path, lines: list[str]) -> list[Finding]:
    if path.suffix.lower() in {".py", ".pyi"}:
        return _python_security_findings(path, root, lines)
    return [
        *_text_secret_findings(path, root, lines),
        *_text_shell_findings(path, root, lines),
    ]

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


def scan_repository(
    repository: Path,
    metadata: RepositoryMetadata,
    exclusions: list[str] | tuple[str, ...] = (),
) -> list[Finding]:
    """Run bounded, read-only deterministic checks over safe repository text files."""
    root = repository.expanduser().resolve(strict=True)
    findings = _repository_findings(metadata)

    for path in _iter_safe_text_files(root, exclusions):
        lines = _read_lines(path)
        if not lines:
            continue
        findings.extend(_security_findings(path, root, lines))
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
