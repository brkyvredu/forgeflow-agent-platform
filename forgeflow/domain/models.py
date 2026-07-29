from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    id: str = ""
    agent: str
    category: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    file: Path | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    evidence: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str
    fingerprint: str = ""

    @model_validator(mode="after")
    def validate_and_identify(self) -> Finding:
        if self.line_start is not None and self.file is None:
            raise ValueError("A file is required when line_start is set")
        if self.line_end is not None and self.line_start is None:
            raise ValueError("line_start is required when line_end is set")
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must be greater than or equal to line_start")

        canonical = "|".join(
            [
                self.rule_id,
                self.file.as_posix() if self.file else "repository",
                str(self.line_start or 0),
                self.title.strip().lower(),
            ]
        )
        digest = sha256(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()
        if not self.fingerprint:
            self.fingerprint = f"sha256:{digest}"
        if not self.id:
            self.id = f"{self.rule_id}-{digest[:12]}"
        return self


class AnalysisRequest(BaseModel):
    repository: Path
    output_directory: Path

    @model_validator(mode="after")
    def validate_repository(self) -> AnalysisRequest:
        repository = self.repository.expanduser().resolve()
        if not repository.exists():
            raise ValueError(f"Repository does not exist: {repository}")
        if not repository.is_dir():
            raise ValueError(f"Repository is not a directory: {repository}")
        self.repository = repository
        self.output_directory = self.output_directory.expanduser().resolve()
        return self


class RepositoryMetadata(BaseModel):
    root: Path
    total_files: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    languages: dict[str, int]
    manifests: list[str]
    test_directories: list[str]
    ci_files: list[str]
    container_files: list[str]
    kubernetes_files: list[str]
    skipped_sensitive_files: int = Field(default=0, ge=0)
    skipped_symlinks: int = Field(default=0, ge=0)


class ExecutionSummary(BaseModel):
    status: str
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(ge=0)
    analyzer_mode: str = "deterministic-rules"
    notes: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    findings: list[Finding] = Field(default_factory=list)
    execution: ExecutionSummary
