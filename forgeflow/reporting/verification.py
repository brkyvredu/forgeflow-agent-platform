from __future__ import annotations

import ast
import re
from pathlib import Path

from forgeflow.domain.models import Finding, Severity, ValidationStatus
from forgeflow.scanner.policy import (
    EXCLUDED_DIRECTORIES,
    is_forgeflow_report_directory,
)

_QUOTED_ENV_REFERENCE = re.compile(r'''["']\$(?:\{)?[A-Z_][A-Z0-9_]*(?:\})?["']''')
_COMPOSE_DEFAULT = re.compile(r"\$\{[A-Z_][A-Z0-9_]*:-[^}]+\}")
_TEST_SUFFIXES = {".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".kt", ".cs", ".rb"}
_HTTP_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+/?)+")
_RAW_CREDENTIAL = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|secret)\b[^\n]{0,40}?[=:]\s*[\"'](?!\*\*\*REDACTED\*\*\*)"
    r"[^\"'\n]{6,}[\"']"
)
_ROUTE_SOURCE_SUFFIXES = {".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".cs", ".rb"}
_ROUTE_DEFINITION = re.compile(
    r"(?:@(?:app|router)\.(?:get|post|put|patch|delete|head|options)|"
    r"\b(?:app|router)\.(?:get|post|put|patch|delete|head|options)|"
    r"add_api_route|\b(?:route|path)\s*\(|"
    r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping)"
)
_FILE_LIKE_PATH_SUFFIXES = (
    ".yaml", ".yml", ".json", ".toml", ".xml", ".py", ".java", ".js", ".ts", ".md"
)


def _is_deterministic(finding: Finding) -> bool:
    return finding.agent.startswith("deterministic-") or any(
        source.startswith("deterministic-") for source in finding.sources
    )


def _is_test_path(path: Path) -> bool:
    lowered_parts = {part.lower() for part in path.parts}
    lowered_name = path.name.lower()
    return bool(
        lowered_parts & {"test", "tests", "__tests__", "spec", "specs"}
        or lowered_name.startswith(("test_", "spec_"))
        or any(
            lowered_name.endswith(suffix)
            for suffix in (
                "_test.py",
                "_tests.py",
                "_spec.py",
                ".test.js",
                ".test.ts",
                ".spec.js",
                ".spec.ts",
                "test.java",
                "tests.java",
            )
        )
    )


def _iter_test_files(repository: Path) -> list[Path]:
    files: list[Path] = []
    for path in repository.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TEST_SUFFIXES:
            continue
        relative = path.relative_to(repository)
        if any(part.lower() in EXCLUDED_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if any(
            is_forgeflow_report_directory(repository.joinpath(*relative.parts[:index]))
            for index in range(1, len(relative.parts))
        ):
            continue
        if _is_test_path(relative):
            files.append(path)
    return files


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > 1_000_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _python_symbol_at_line(path: Path, line: int) -> str | None:
    if path.suffix.lower() != ".py":
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None

    candidates: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        end = node.end_lineno or node.lineno
        if node.lineno <= line <= end:
            candidates.append((end - node.lineno, node.name))
    return min(candidates, default=(0, ""))[1] or None


def _tests_reference_symbol(test_sources: list[str], symbol: str | None) -> bool:
    if not symbol:
        return False
    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    return any(pattern.search(source) for source in test_sources)


def _tests_cover_named_concept(finding: Finding, test_sources: list[str]) -> bool:
    claim = " ".join(
        [finding.category, finding.title, finding.description, finding.recommendation]
    ).lower()
    joined = "\n".join(test_sources).lower()

    path_claim = any(term in claim for term in ("path traversal", "path escape"))
    path_coverage = any(
        term in joined
        for term in ("../outside", "path escapes", "parent path", "absolute path")
    )
    line_claim = any(
        term in claim for term in ("line boundary", "out-of-bounds", "outside the file")
    )
    line_coverage = "line_start" in joined and any(
        term in joined for term in ("outside the file", "out-of-bounds", "999")
    )
    return (path_claim and path_coverage) or (line_claim and line_coverage)




def _python_enclosing_source(path: Path, line: int) -> str:
    if path.suffix.lower() != ".py":
        return _read_text(path)
    source = _read_text(path)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    candidates: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        end = node.end_lineno or node.lineno
        if node.lineno <= line <= end:
            candidates.append((node.lineno, end))
    if not candidates:
        return source
    start, end = min(candidates, key=lambda item: item[1] - item[0])
    return "\n".join(source.splitlines()[start - 1 : end])


def _mark_unsupported(finding: Finding, message: str) -> Finding:
    finding.validation_status = ValidationStatus.UNSUPPORTED
    finding.scoring_eligible = False
    finding.validation_messages.append(message)
    return finding


def _test_claim_is_contradicted(repository: Path, finding: Finding) -> bool:
    if finding.file is None or finding.line_start is None:
        return False
    claim = " ".join(
        [finding.category, finding.title, finding.description, finding.recommendation]
    ).lower()
    redaction_claim_markers = (
        "pre-redacted",
        "already redacted",
        "redacted evidence",
        "contains the redaction marker",
        "string was never written",
        "passes vacuously",
    )
    if not any(marker in claim for marker in redaction_claim_markers):
        return False
    source = _python_enclosing_source(repository / finding.file, finding.line_start)
    return bool(_RAW_CREDENTIAL.search(source))


def _http_paths(text: str) -> set[str]:
    return {
        item.rstrip(".,;:)")
        for item in _HTTP_PATH.findall(text)
        if not item.lower().rstrip(".,;:)").endswith(_FILE_LIKE_PATH_SUFFIXES)
    }


def _repository_defines_http_path(repository: Path, path_value: str) -> bool:
    for path in repository.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _ROUTE_SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(repository)
        if any(part.lower() in EXCLUDED_DIRECTORIES for part in relative.parts[:-1]):
            continue
        for line in _read_text(path).splitlines():
            if path_value in line and _ROUTE_DEFINITION.search(line):
                return True
    return False


def _unverified_external_route_claim(repository: Path, finding: Finding) -> bool:
    claim = " ".join([finding.category, finding.title, finding.description, finding.recommendation])
    lowered = claim.lower()
    if not any(
        marker in lowered
        for marker in ("readiness probe", "health check", "http endpoint", "api endpoint", "route")
    ):
        return False
    evidence_paths = _http_paths(finding.evidence or "")
    claimed_paths = _http_paths(claim)
    alternatives = claimed_paths - evidence_paths
    return bool(alternatives) and not all(
        _repository_defines_http_path(repository, item) for item in alternatives
    )


def _mark_human_review(finding: Finding, message: str) -> Finding:
    finding.validation_status = ValidationStatus.HUMAN_REVIEW_REQUIRED
    finding.scoring_eligible = False
    finding.severity = Severity.INFO
    finding.validation_messages.append(message)
    return finding


def _verify_security_finding(repository: Path, finding: Finding) -> Finding:
    claim = " ".join([finding.category, finding.title, finding.description]).lower()
    evidence = finding.evidence or ""
    relative = finding.file or Path()

    if "command injection" in claim and relative.suffix.lower() in {".yaml", ".yml"}:
        if _QUOTED_ENV_REFERENCE.search(evidence):
            return _mark_human_review(
                finding,
                "Quoted environment-variable expansion alone does not establish shell command "
                "injection; review the surrounding command construction manually.",
            )

    if any(term in claim for term in ("credential", "password", "secret")):
        if _COMPOSE_DEFAULT.search(evidence):
            finding.validation_status = ValidationStatus.SEMANTICALLY_VERIFIED
            finding.scoring_eligible = True
            if relative.name.lower().startswith("docker-compose"):
                finding.severity = Severity.LOW
                finding.validation_messages.append(
                    "Default credential fallback was verified in a development Compose file and "
                    "downgraded to low severity."
                )
            return finding

    if "eval(" in evidence or "shell=true" in evidence.lower():
        finding.validation_status = ValidationStatus.SEMANTICALLY_VERIFIED
        finding.scoring_eligible = True
        return finding

    return _mark_human_review(
        finding,
        "The evidence excerpt exists, but no deterministic semantic verifier confirmed the "
        "security claim.",
    )


def _verify_test_finding(repository: Path, finding: Finding) -> Finding:
    if _test_claim_is_contradicted(repository, finding):
        return _mark_unsupported(
            finding,
            "The claim is contradicted by the enclosing test, which supplies an unredacted "
            "credential and asserts the expected redaction behavior.",
        )
    if finding.file is None or finding.line_start is None:
        return _mark_human_review(
            finding,
            "A repository-wide test absence claim requires human review.",
        )

    source_path = repository / finding.file
    symbol = _python_symbol_at_line(source_path, finding.line_start)
    test_sources = [_read_text(path) for path in _iter_test_files(repository)]
    if _tests_reference_symbol(test_sources, symbol) or _tests_cover_named_concept(
        finding, test_sources
    ):
        return _mark_human_review(
            finding,
            "Related test coverage was found in the repository, so the asserted absence was not "
            "semantically confirmed.",
        )

    finding.validation_status = ValidationStatus.SEMANTICALLY_VERIFIED
    finding.scoring_eligible = True
    finding.validation_messages.append(
        "No direct test reference or matching boundary scenario was found in repository test files."
    )
    return finding


def _verify_architecture_finding(repository: Path, finding: Finding) -> Finding:
    del repository
    return _mark_human_review(
        finding,
        "Architecture concerns require an explicit repository policy or human design review "
        "before they can affect scoring.",
    )


def _verify_release_finding(repository: Path, finding: Finding) -> Finding:
    if _unverified_external_route_claim(repository, finding):
        return _mark_unsupported(
            finding,
            "The finding asserts external HTTP route behavior that is not defined or verified "
            "by repository source evidence.",
        )
    return _mark_human_review(
        finding,
        "Release-readiness concerns require repository policy, external artifact state, or "
        "human operational review before they can affect scoring.",
    )


def verify_findings(repository: Path, findings: list[Finding]) -> list[Finding]:
    """Assign semantic verification and scoring eligibility after evidence matching."""
    root = repository.expanduser().resolve(strict=True)
    verified: list[Finding] = []
    for candidate in findings:
        finding = candidate.model_copy(deep=True)
        if _is_deterministic(finding):
            finding.validation_status = ValidationStatus.DETERMINISTICALLY_CONFIRMED
            finding.scoring_eligible = True
        elif finding.agent == "security-agent":
            finding = _verify_security_finding(root, finding)
        elif finding.agent == "test-agent":
            finding = _verify_test_finding(root, finding)
        elif finding.agent == "architecture-agent":
            finding = _verify_architecture_finding(root, finding)
        elif finding.agent == "release-agent":
            finding = _verify_release_finding(root, finding)
        else:
            finding = _mark_human_review(
                finding,
                "No semantic verifier is registered for this specialist agent.",
            )
        verified.append(finding)
    return verified
