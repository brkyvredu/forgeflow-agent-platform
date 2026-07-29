from pathlib import Path

from forgeflow.domain.models import Severity
from forgeflow.orchestration.security import (
    SecurityFindingCandidate,
    SecurityReviewOutput,
    candidates_to_findings,
)


def test_security_candidates_are_normalized_to_findings() -> None:
    output = SecurityReviewOutput(
        findings=[
            SecurityFindingCandidate(
                category="unsafe-evaluation",
                severity=Severity.HIGH,
                title="Untrusted input reaches eval",
                description="The file evaluates externally controlled input.",
                recommendation="Replace eval with a constrained parser.",
                file="src\\app.py",
                line_start=3,
                evidence="eval(user_input)",
                confidence=0.93,
            )
        ]
    )

    findings = candidates_to_findings(output)

    assert len(findings) == 1
    assert findings[0].agent == "security-agent"
    assert findings[0].file == Path("src/app.py")
    assert findings[0].line_end == 3
    assert findings[0].rule_id.startswith("FF-AGENT-SEC-")
