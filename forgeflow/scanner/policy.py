from pathlib import Path

EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".idea",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "reports",
        "target",
        "venv",
    }
)

SENSITIVE_EXACT_NAMES = frozenset(
    {
        ".env",
        "credentials.json",
        "service-account.json",
        "secrets.json",
        "id_rsa",
        "id_ed25519",
    }
)
SENSITIVE_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".jks", ".keystore")

SCANNABLE_TEXT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".conf",
        ".cpp",
        ".cs",
        ".env.example",
        ".go",
        ".gradle",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".kts",
        ".php",
        ".properties",
        ".py",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".sql",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".vue",
        ".xml",
        ".yaml",
        ".yml",
    }
)


def is_excluded_directory(name: str) -> bool:
    return name.lower() in EXCLUDED_DIRECTORIES


def is_sensitive_file(path: Path) -> bool:
    lowered = path.name.lower()
    return (
        lowered in SENSITIVE_EXACT_NAMES
        or lowered.startswith(".env.") and lowered != ".env.example"
        or lowered.endswith(SENSITIVE_SUFFIXES)
    )


def is_scannable_text_file(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered == "dockerfile" or lowered.startswith("dockerfile."):
        return True
    if lowered in {"jenkinsfile", "makefile"}:
        return True
    return lowered == ".env.example" or path.suffix.lower() in SCANNABLE_TEXT_SUFFIXES
