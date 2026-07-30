from pathlib import Path

from forgeflow.domain.models import Severity
from forgeflow.orchestration.release import (
    ReleaseFindingCandidate,
    ReleaseReviewOutput,
    candidates_to_findings,
)


def test_release_candidates_are_normalized_to_findings() -> None:
    output = ReleaseReviewOutput(
        findings=[
            ReleaseFindingCandidate(
                category="release-reproducibility",
                severity=Severity.MEDIUM,
                title="Container publishing action is not pinned to an immutable revision",
                description=(
                    "The release workflow references a mutable action tag, so identical source "
                    "revisions may execute different upstream action code over time."
                ),
                recommendation="Pin the action to a reviewed commit SHA.",
                file=".github\\workflows\\release.yml",
                line_start=24,
                evidence="uses: docker/build-push-action@v6",
                confidence=0.87,
            )
        ]
    )

    findings = candidates_to_findings(output)

    assert len(findings) == 1
    assert findings[0].agent == "release-agent"
    assert findings[0].file == Path(".github/workflows/release.yml")
    assert findings[0].line_end == 24
    assert findings[0].rule_id.startswith("FF-AGENT-REL-")
