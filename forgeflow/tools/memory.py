import json
import os
from typing import Any

import psycopg
from google import genai
from google.genai import types
from pgvector.psycopg import register_vector

from forgeflow.config import get_settings


def _embedding(text: str) -> list[float]:
    settings = get_settings()
    api_key = os.getenv("GOOGLE_API_KEY")
    project = os.getenv("GOOGLE_CLOUD_PROJECT")
    location = os.getenv("GOOGLE_CLOUD_LOCATION", "europe-west4")
    if api_key:
        client = genai.Client(api_key=api_key)
    elif project:
        client = genai.Client(vertexai=True, project=project, location=location)
    else:
        client = genai.Client()
    result = client.models.embed_content(
        model=settings.embedding_model,
        contents=text,
        config=types.EmbedContentConfig(output_dimensionality=settings.embedding_dimension),
    )
    if not result.embeddings or result.embeddings[0].values is None:
        raise RuntimeError("Embedding provider returned no vector")
    return list(result.embeddings[0].values)


def save_engineering_note(title: str, content: str, metadata_json: str = "{}") -> dict[str, Any]:
    """Save a durable engineering decision or finding to semantic memory.

    Store only concise, non-secret information that will be useful in later engineering work.
    `metadata_json` must contain a JSON object.
    """
    settings = get_settings()
    metadata = json.loads(metadata_json)
    if not isinstance(metadata, dict):
        raise ValueError("metadata_json must contain a JSON object")
    if len(title) > 200 or len(content) > 20_000:
        raise ValueError("Engineering note exceeds configured size limits")
    vector = _embedding(f"{title}\n{content}")

    with psycopg.connect(settings.database_url) as connection:
        register_vector(connection)
        row = connection.execute(
            """
            INSERT INTO engineering_memory(title, content, metadata, embedding)
            VALUES (%s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (title, content, json.dumps(metadata), vector),
        ).fetchone()
        connection.commit()
    assert row is not None
    return {"id": str(row[0]), "created_at": row[1].isoformat()}


def search_engineering_memory(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Search durable engineering memory by semantic similarity."""
    settings = get_settings()
    bounded_limit = min(max(limit, 1), 10)
    vector = _embedding(query)

    with psycopg.connect(settings.database_url) as connection:
        register_vector(connection)
        rows = connection.execute(
            """
            SELECT id, title, content, metadata, 1 - (embedding <=> %s) AS similarity
            FROM engineering_memory
            ORDER BY embedding <=> %s
            LIMIT %s
            """,
            (vector, vector, bounded_limit),
        ).fetchall()

    return [
        {
            "id": str(row[0]),
            "title": row[1],
            "content": row[2],
            "metadata": row[3],
            "similarity": float(row[4]),
        }
        for row in rows
    ]
