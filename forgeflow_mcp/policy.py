from __future__ import annotations

import os
from pathlib import Path

SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SENSITIVE_PREFIXES = (".env.", "credentials.", "secrets.", "service-account.", "service_account.")
SENSITIVE_STEMS = {
    "credentials",
    "secrets",
    "service-account",
    "service_account",
    "private-key",
    "private_key",
}
BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".jar",
    ".class",
    ".dll",
    ".so",
    ".dylib",
    ".exe",
    ".bin",
    ".parquet",
}
IGNORED_DIRECTORIES = {
    ".git",
    ".idea",
    ".vscode",
    ".venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
}


def repository_root() -> Path:
    return Path(os.getenv("REPOSITORY_ROOT", ".")).expanduser().resolve()


def resolve_safe_path(relative_path: str) -> Path:
    root = repository_root()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes the configured repository root") from exc
    return candidate


def is_sensitive(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in SENSITIVE_NAMES
        or name.startswith(SENSITIVE_PREFIXES)
        or path.stem.lower() in SENSITIVE_STEMS
        or path.suffix.lower() in SENSITIVE_SUFFIXES
    )


def is_binary(path: Path) -> bool:
    return path.suffix.lower() in BINARY_SUFFIXES


def is_ignored(path: Path) -> bool:
    return any(part in IGNORED_DIRECTORIES for part in path.parts)
