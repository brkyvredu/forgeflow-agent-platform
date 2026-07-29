from __future__ import annotations

import re
from typing import Any

from forgeflow_mcp.policy import (
    is_binary,
    is_ignored,
    is_sensitive,
    repository_root,
    resolve_safe_path,
)

TEXT_LIMIT = 100_000
MAX_SCANNED_FILES = 5_000


def list_repository_tree(relative_path: str = ".", max_depth: int = 3) -> dict[str, Any]:
    """List a bounded repository tree without reading file contents."""
    start = resolve_safe_path(relative_path)
    if not start.exists():
        raise FileNotFoundError(relative_path)
    depth_limit = min(max(max_depth, 0), 8)
    entries: list[dict[str, Any]] = []
    root = repository_root()

    if start.is_file():
        return {"root": ".", "entries": [{"path": str(start.relative_to(root)), "type": "file"}]}

    for path in sorted(start.rglob("*")):
        if is_ignored(path):
            continue
        relative = path.relative_to(start)
        if len(relative.parts) > depth_limit:
            continue
        entries.append(
            {
                "path": str(path.relative_to(root)),
                "type": "directory" if path.is_dir() else "file",
                "size": path.stat().st_size if path.is_file() else None,
            }
        )
        if len(entries) >= 2_000:
            break
    return {"root": ".", "truncated": len(entries) >= 2_000, "entries": entries}


def read_text_file(relative_path: str, max_chars: int = 30_000) -> dict[str, Any]:
    """Read an allowlisted text file under the configured repository root."""
    path = resolve_safe_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(relative_path)
    if is_sensitive(path):
        raise PermissionError("Sensitive files cannot be read")
    if is_binary(path):
        raise ValueError("Binary files are not supported")
    if path.stat().st_size > TEXT_LIMIT:
        raise ValueError(f"File exceeds the {TEXT_LIMIT} byte safety limit")

    limit = min(max(max_chars, 1), TEXT_LIMIT)
    text = path.read_text(encoding="utf-8", errors="replace")
    return {
        "path": relative_path,
        "content": text[:limit],
        "truncated": len(text) > limit,
        "characters": len(text),
    }


def search_repository(
    query: str,
    relative_path: str = ".",
    include_extensions: list[str] | None = None,
    max_results: int = 50,
) -> dict[str, Any]:
    """Search text files for a literal, case-insensitive query."""
    if not query or len(query) > 200:
        raise ValueError("Query must contain 1 to 200 characters")
    start = resolve_safe_path(relative_path)
    extensions = {
        item.lower() if item.startswith(".") else f".{item.lower()}"
        for item in (include_extensions or [])
    }
    result_limit = min(max(max_results, 1), 200)
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    root = repository_root()
    results: list[dict[str, Any]] = []

    paths = [start] if start.is_file() else start.rglob("*")
    files_scanned = 0
    for path in paths:
        if not path.is_file() or is_ignored(path) or is_sensitive(path) or is_binary(path):
            continue
        if extensions and path.suffix.lower() not in extensions:
            continue
        files_scanned += 1
        if files_scanned > MAX_SCANNED_FILES:
            return {
                "query": query,
                "truncated": True,
                "files_scanned": MAX_SCANNED_FILES,
                "results": results,
            }
        if path.stat().st_size > TEXT_LIMIT:
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, 1):
            if pattern.search(line):
                results.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": number,
                        "preview": line.strip()[:500],
                    }
                )
                if len(results) >= result_limit:
                    return {
                        "query": query,
                        "truncated": True,
                        "files_scanned": files_scanned,
                        "results": results,
                    }
    return {
        "query": query,
        "truncated": False,
        "files_scanned": files_scanned,
        "results": results,
    }


def summarize_dependency_manifests(relative_path: str = ".") -> dict[str, Any]:
    """Return bounded contents of common dependency manifests for architecture analysis."""
    start = resolve_safe_path(relative_path)
    manifest_names = {
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "Cargo.toml",
        "composer.json",
        "Gemfile",
    }
    root = repository_root()
    manifests: list[dict[str, Any]] = []
    paths = [start] if start.is_file() else start.rglob("*")
    for path in paths:
        if path.is_file() and path.name in manifest_names and not is_ignored(path):
            text = path.read_text(encoding="utf-8", errors="replace")
            manifests.append(
                {
                    "path": str(path.relative_to(root)),
                    "content": text[:20_000],
                    "truncated": len(text) > 20_000,
                }
            )
        if len(manifests) >= 30:
            break
    return {"manifests": manifests, "truncated": len(manifests) >= 30}
