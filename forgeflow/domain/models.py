from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field, model_validator


class AnalysisRequest(BaseModel):
    repository: Path
    output_directory: Path

    @model_validator(mode="after")
    def validate_repository(self) -> "AnalysisRequest":
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
    analyzer_mode: str = "deterministic-discovery"
    notes: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    findings: list[dict[str, object]] = Field(default_factory=list)
    execution: ExecutionSummary
