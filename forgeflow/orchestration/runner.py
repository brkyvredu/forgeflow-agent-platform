from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol

from forgeflow.domain.models import AgentRunSummary, Finding
from forgeflow.orchestration.context import RepositoryEvidence


class SpecialistReviewer(Protocol):
    async def review(self, evidence: RepositoryEvidence) -> list[Finding]: ...


@dataclass(frozen=True)
class SpecialistJob:
    name: str
    reviewer: SpecialistReviewer
    evidence: RepositoryEvidence


@dataclass(frozen=True)
class SpecialistResult:
    name: str
    findings: tuple[Finding, ...]
    summary: AgentRunSummary
    note: str | None = None


async def _run_job(job: SpecialistJob) -> SpecialistResult:
    started = perf_counter()
    try:
        findings = await job.reviewer.review(job.evidence)
    except Exception as exc:  # noqa: BLE001 - one specialist must not abort the analysis
        summary = AgentRunSummary(
            status="failed",
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            context_files=len(job.evidence.files),
            context_chars=job.evidence.character_count,
            prompt_risk_files=len(job.evidence.prompt_risk_files),
            message=f"{type(exc).__name__}: review failed",
        )
        return SpecialistResult(
            name=job.name,
            findings=(),
            summary=summary,
            note=f"{job.name.capitalize()} agent failed; deterministic analysis was preserved.",
        )

    summary = AgentRunSummary(
        status="completed",
        finding_count=len(findings),
        duration_ms=max(0, round((perf_counter() - started) * 1000)),
        context_files=len(job.evidence.files),
        context_chars=job.evidence.character_count,
        prompt_risk_files=len(job.evidence.prompt_risk_files),
        message="Evidence bundle was truncated." if job.evidence.truncated else None,
    )
    return SpecialistResult(
        name=job.name,
        findings=tuple(findings),
        summary=summary,
    )


async def run_specialist_jobs(jobs: list[SpecialistJob]) -> list[SpecialistResult]:
    """Run isolated specialist reviews concurrently and preserve partial success."""
    if not jobs:
        return []
    return list(await asyncio.gather(*(_run_job(job) for job in jobs)))
