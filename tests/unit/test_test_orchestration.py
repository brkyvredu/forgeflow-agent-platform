from pathlib import Path

from forgeflow.domain.models import Severity
from forgeflow.orchestration.test_review import (
    TestFindingCandidate as FindingCandidate,
    TestReviewOutput as ReviewOutput,
    candidates_to_findings,
)


def test_test_candidates_are_normalized_to_findings() -> None:
    output = ReviewOutput(
        findings=[
            FindingCandidate(
                category="missing-boundary-test",
                severity=Severity.MEDIUM,
                title="Zero amount boundary is not verified",
                description=(
                    "The charge function has a zero-value boundary without a matching test."
                ),
                recommendation="Add a test for zero and negative amounts.",
                file="src\\payment.py",
                line_start=2,
                evidence="return amount > 0",
                confidence=0.91,
            )
        ]
    )

    findings = candidates_to_findings(output)

    assert len(findings) == 1
    assert findings[0].agent == "test-agent"
    assert findings[0].file == Path("src/payment.py")
    assert findings[0].line_end == 2
    assert findings[0].rule_id.startswith("FF-AGENT-TEST-")
