from pathlib import Path

import pytest
from pydantic import ValidationError

from forgeflow.domain.models import Finding, Severity


def _finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "agent": "deterministic-security",
        "category": "secret-management",
        "severity": Severity.HIGH,
        "title": "Possible hard-coded credential",
        "description": "A credential-like value was detected.",
        "recommendation": "Use a secret manager.",
        "file": Path("src/app.py"),
        "line_start": 4,
        "line_end": 4,
        "evidence": "password=***REDACTED***",
        "confidence": 0.9,
        "rule_id": "FF-SEC-001",
    }
    payload.update(overrides)
    return Finding(**payload)


def test_finding_generates_stable_identifiers() -> None:
    first = _finding()
    second = _finding()

    assert first.id == second.id
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint.startswith("sha256:")


def test_finding_rejects_invalid_line_range() -> None:
    with pytest.raises(ValidationError):
        _finding(line_start=8, line_end=3)
