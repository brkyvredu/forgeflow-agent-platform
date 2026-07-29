from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    model: str = Field(default="gemini-3.6-flash", alias="FORGEFLOW_MODEL")
    embedding_model: str = Field(
        default="gemini-embedding-001", alias="FORGEFLOW_EMBEDDING_MODEL"
    )
    embedding_dimension: int = Field(default=768, alias="FORGEFLOW_EMBEDDING_DIMENSION")
    mcp_server_url: str = Field(default="http://localhost:8001/mcp", alias="MCP_SERVER_URL")
    java_analysis_url: str = Field(
        default="http://localhost:8080", alias="JAVA_ANALYSIS_URL"
    )
    database_url: str = Field(
        default="postgresql://forgeflow:forgeflow@localhost:5432/forgeflow",
        alias="DATABASE_URL",
    )
    request_timeout_seconds: float = 20.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
