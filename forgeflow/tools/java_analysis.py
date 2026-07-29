from typing import Any

import httpx
from opentelemetry import trace

from forgeflow.config import get_settings
from forgeflow.security import enforce_safe_prompt

_tracer = trace.get_tracer(__name__)


async def analyze_java_source(source_code: str) -> dict[str, Any]:
    """Analyze Java source and return bounded structural metrics.

    Use this tool for Java files or Java snippets. It performs static metrics only and never executes
    supplied code.
    """
    enforce_safe_prompt(source_code)
    settings = get_settings()
    if len(source_code) > 200_000:
        raise ValueError("Java source exceeds the 200,000 character limit")

    with _tracer.start_as_current_span("tool.java_analysis"):
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post(
                f"{settings.java_analysis_url}/api/v1/java/analyze",
                json={"sourceCode": source_code},
            )
            response.raise_for_status()
            return response.json()
