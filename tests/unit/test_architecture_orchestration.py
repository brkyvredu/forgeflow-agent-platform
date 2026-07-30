from pathlib import Path

from forgeflow.domain.models import Severity
from forgeflow.orchestration.architecture import (
    ArchitectureFindingCandidate,
    ArchitectureReviewOutput,
    candidates_to_findings,
)


def test_architecture_candidates_are_normalized_to_findings() -> None:
    output = ArchitectureReviewOutput(
        findings=[
            ArchitectureFindingCandidate(
                category="dependency-direction",
                severity=Severity.MEDIUM,
                title="CLI layer imports a concrete infrastructure adapter",
                description=(
                    "The CLI module directly imports a concrete storage adapter, coupling the "
                    "entry point to infrastructure details."
                ),
                recommendation="Depend on an application-facing protocol instead.",
                file="src\\cli.py",
                line_start=4,
                evidence="from infrastructure.database import Repository",
                confidence=0.86,
            )
        ]
    )

    findings = candidates_to_findings(output)

    assert len(findings) == 1
    assert findings[0].agent == "architecture-agent"
    assert findings[0].file == Path("src/cli.py")
    assert findings[0].line_end == 4
    assert findings[0].rule_id.startswith("FF-AGENT-ARCH-")
