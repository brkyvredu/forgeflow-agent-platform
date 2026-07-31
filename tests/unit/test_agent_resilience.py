import asyncio
import logging

import pytest

from forgeflow.orchestration.context import RepositoryEvidence
from forgeflow.orchestration.runner import SpecialistJob, run_specialist_jobs


class _TransientProviderError(RuntimeError):
    status_code = 503


class _EventuallySuccessfulReviewer:
    def __init__(self) -> None:
        self.calls = 0

    async def review(self, evidence: RepositoryEvidence) -> list[object]:
        del evidence
        self.calls += 1
        if self.calls < 3:
            raise _TransientProviderError("503 UNAVAILABLE: high demand")
        return []


class _PermanentReviewer:
    def __init__(self) -> None:
        self.calls = 0

    async def review(self, evidence: RepositoryEvidence) -> list[object]:
        del evidence
        self.calls += 1
        raise ValueError("invalid structured output")


def _evidence() -> RepositoryEvidence:
    return RepositoryEvidence(
        prompt="bounded evidence",
        files=("app.py",),
        character_count=16,
        truncated=False,
        prompt_risk_files=(),
    )


def test_transient_provider_failure_is_retried() -> None:
    reviewer = _EventuallySuccessfulReviewer()
    result = asyncio.run(
        run_specialist_jobs(
            [
                SpecialistJob(
                    name="security",
                    reviewer=reviewer,  # type: ignore[arg-type]
                    evidence=_evidence(),
                    max_attempts=3,
                    retry_backoff_seconds=0,
                )
            ]
        )
    )[0]

    assert reviewer.calls == 3
    assert result.summary.status == "completed"
    assert result.summary.attempt_count == 3
    assert result.summary.retryable is True
    assert result.note == "Security agent completed after 3 attempts."


def test_non_retryable_failure_stops_after_one_attempt() -> None:
    reviewer = _PermanentReviewer()
    result = asyncio.run(
        run_specialist_jobs(
            [
                SpecialistJob(
                    name="test",
                    reviewer=reviewer,  # type: ignore[arg-type]
                    evidence=_evidence(),
                    max_attempts=3,
                    retry_backoff_seconds=0,
                )
            ]
        )
    )[0]

    assert reviewer.calls == 1
    assert result.summary.status == "failed"
    assert result.summary.attempt_count == 1
    assert result.summary.retryable is False
    assert result.summary.error_type == "ValueError"


class _NoisyReviewer:
    async def review(self, evidence: RepositoryEvidence) -> list[object]:
        del evidence
        logger = logging.getLogger("google_adk.google.adk.workflow._node_runner")
        try:
            raise RuntimeError("provider stack")
        except RuntimeError:
            logger.exception("provider traceback")
        raise ValueError("invalid structured output")


def test_provider_traceback_logging_is_suppressed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR):
        result = asyncio.run(
            run_specialist_jobs(
                [
                    SpecialistJob(
                        name="release",
                        reviewer=_NoisyReviewer(),  # type: ignore[arg-type]
                        evidence=_evidence(),
                        max_attempts=1,
                        retry_backoff_seconds=0,
                    )
                ]
            )
        )[0]

    assert result.summary.status == "failed"
    assert "provider traceback" not in caplog.text


class _ConcurrencyState:
    def __init__(self) -> None:
        self.active = 0
        self.maximum = 0


class _TrackingReviewer:
    def __init__(self, state: _ConcurrencyState) -> None:
        self.state = state

    async def review(self, evidence: RepositoryEvidence) -> list[object]:
        del evidence
        self.state.active += 1
        self.state.maximum = max(self.state.maximum, self.state.active)
        await asyncio.sleep(0.01)
        self.state.active -= 1
        return []


def test_specialist_concurrency_is_bounded() -> None:
    state = _ConcurrencyState()
    jobs = [
        SpecialistJob(
            name=f"agent-{index}",
            reviewer=_TrackingReviewer(state),  # type: ignore[arg-type]
            evidence=_evidence(),
            max_attempts=1,
            retry_backoff_seconds=0,
        )
        for index in range(4)
    ]

    results = asyncio.run(run_specialist_jobs(jobs, max_concurrency=2))

    assert [result.name for result in results] == [
        "agent-0",
        "agent-1",
        "agent-2",
        "agent-3",
    ]
    assert state.maximum == 2


def test_specialist_concurrency_rejects_zero() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        asyncio.run(
            run_specialist_jobs(
                [
                    SpecialistJob(
                        name="security",
                        reviewer=_PermanentReviewer(),  # type: ignore[arg-type]
                        evidence=_evidence(),
                    )
                ],
                max_concurrency=0,
            )
        )
