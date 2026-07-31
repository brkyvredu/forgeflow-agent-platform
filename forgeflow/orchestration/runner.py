from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol

from forgeflow.domain.models import AgentRunSummary, Finding
from forgeflow.orchestration.context import RepositoryEvidence

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_PROVIDER_LOGGERS = (
    "google_adk",
    "google.genai",
    "google_genai",
)


class SpecialistReviewer(Protocol):
    async def review(self, evidence: RepositoryEvidence) -> list[Finding]: ...


@dataclass(frozen=True)
class SpecialistJob:
    name: str
    reviewer: SpecialistReviewer
    evidence: RepositoryEvidence
    max_attempts: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class SpecialistResult:
    name: str
    findings: tuple[Finding, ...]
    summary: AgentRunSummary
    note: str | None = None


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _status_code(exc: BaseException) -> int | None:
    for current in _exception_chain(exc):
        for attribute in ("status_code", "code"):
            value = getattr(current, attribute, None)
            if isinstance(value, int):
                return value
        response = getattr(current, "response", None)
        value = getattr(response, "status_code", None)
        if isinstance(value, int):
            return value
    return None


def _is_retryable_exception(exc: BaseException) -> tuple[bool, int | None]:
    status_code = _status_code(exc)
    if status_code in _RETRYABLE_STATUS_CODES:
        return True, status_code

    message = " ".join(str(item) for item in _exception_chain(exc)).lower()
    retry_markers = (
        "resource_exhausted",
        "rate limit",
        "too many requests",
        "temporarily unavailable",
        "high demand",
        "503 unavailable",
        "service unavailable",
        "gateway timeout",
    )
    return any(marker in message for marker in retry_markers), status_code


def _retry_delay(job: SpecialistJob, attempt: int) -> float:
    if job.retry_backoff_seconds <= 0:
        return 0.0

    exponent: int = max(0, attempt - 1)
    multiplier: float = pow(2.0, exponent)
    exponential: float = job.retry_backoff_seconds * multiplier
    jitter: float = float(secrets.randbelow(251)) / 1000.0
    delay: float = exponential + jitter
    return delay


@contextmanager
def _suppress_provider_tracebacks() -> Iterator[None]:
    previous: list[tuple[logging.Logger, int]] = []
    for name in _PROVIDER_LOGGERS:
        logger = logging.getLogger(name)
        previous.append((logger, logger.level))
        logger.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        for logger, level in previous:
            logger.setLevel(level)


async def _run_job(job: SpecialistJob) -> SpecialistResult:
    started = perf_counter()
    max_attempts = max(1, job.max_attempts)
    last_exception: Exception | None = None
    last_retryable = False
    last_status_code: int | None = None
    attempt_count = 0

    for attempt_count in range(1, max_attempts + 1):
        try:
            findings = await job.reviewer.review(job.evidence)
        except Exception as exc:  # noqa: BLE001 - one specialist must not abort the analysis
            last_exception = exc
            last_retryable, last_status_code = _is_retryable_exception(exc)
            if not last_retryable or attempt_count >= max_attempts:
                break
            await asyncio.sleep(_retry_delay(job, attempt_count))
            continue

        messages: list[str] = []
        if job.evidence.truncated:
            messages.append("Evidence bundle was truncated.")
        if attempt_count > 1:
            messages.append(f"Completed after {attempt_count} attempts.")
        summary = AgentRunSummary(
            status="completed",
            finding_count=len(findings),
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            context_files=len(job.evidence.files),
            context_chars=job.evidence.character_count,
            prompt_risk_files=len(job.evidence.prompt_risk_files),
            message=" ".join(messages) or None,
            attempt_count=attempt_count,
            retryable=attempt_count > 1,
            error_status_code=last_status_code,
        )
        note = None
        if attempt_count > 1:
            note = (
                f"{job.name.capitalize()} agent completed after {attempt_count} attempts."
            )
        return SpecialistResult(
            name=job.name,
            findings=tuple(findings),
            summary=summary,
            note=note,
        )

    assert last_exception is not None
    error_type = type(last_exception).__name__
    retry_description = "transient provider error" if last_retryable else "review error"
    status_suffix = (
        f" (status={last_status_code})" if last_status_code is not None else ""
    )
    summary = AgentRunSummary(
        status="failed",
        duration_ms=max(0, round((perf_counter() - started) * 1000)),
        context_files=len(job.evidence.files),
        context_chars=job.evidence.character_count,
        prompt_risk_files=len(job.evidence.prompt_risk_files),
        message=(
            f"{error_type}: {retry_description} after {attempt_count} attempt(s)"
            f"{status_suffix}"
        ),
        attempt_count=attempt_count,
        retryable=last_retryable,
        error_type=error_type,
        error_status_code=last_status_code,
    )
    return SpecialistResult(
        name=job.name,
        findings=(),
        summary=summary,
        note=(
            f"{job.name.capitalize()} agent failed after {attempt_count} attempt(s); "
            "deterministic analysis was preserved."
        ),
    )


async def run_specialist_jobs(
    jobs: list[SpecialistJob],
    *,
    max_concurrency: int | None = None,
) -> list[SpecialistResult]:
    """Run isolated specialist reviews with bounded concurrency and partial success."""
    if not jobs:
        return []

    concurrency = len(jobs) if max_concurrency is None else max_concurrency
    if concurrency < 1:
        raise ValueError("max_concurrency must be at least 1")
    semaphore = asyncio.Semaphore(min(concurrency, len(jobs)))

    async def run_limited(job: SpecialistJob) -> SpecialistResult:
        async with semaphore:
            return await _run_job(job)

    with _suppress_provider_tracebacks():
        return list(await asyncio.gather(*(run_limited(job) for job in jobs)))
