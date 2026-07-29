import os
from collections import Counter
from pathlib import Path

from forgeflow.domain.models import RepositoryMetadata
from forgeflow.scanner.policy import (
    is_excluded_directory,
    is_sensitive_file,
    matches_custom_exclusion,
)

_LANGUAGE_BY_SUFFIX = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
}

_MANIFEST_NAMES = frozenset(
    {
        "build.gradle",
        "build.gradle.kts",
        "cargo.toml",
        "composer.json",
        "go.mod",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "settings.gradle",
        "settings.gradle.kts",
    }
)

_CONTAINER_NAMES = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_test_directory(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered in {"test", "tests", "spec", "specs", "__tests__"}


def _is_ci_file(relative_path: str) -> bool:
    lowered = relative_path.lower()
    return (
        lowered.startswith(".github/workflows/")
        or lowered == ".gitlab-ci.yml"
        or lowered == "azure-pipelines.yml"
        or lowered == "jenkinsfile"
    )


def _is_container_file(path: Path) -> bool:
    lowered = path.name.lower()
    return (
        lowered == "dockerfile"
        or lowered.startswith("dockerfile.")
        or lowered in _CONTAINER_NAMES
    )


def _is_kubernetes_file(relative_path: str) -> bool:
    lowered = relative_path.lower()
    return (
        lowered.startswith("k8s/")
        or lowered.startswith("kubernetes/")
        or lowered.startswith("infra/k8s/")
        or "/k8s/" in lowered
        or "/kubernetes/" in lowered
    ) and lowered.endswith((".yaml", ".yml"))


def discover_repository(
    repository: Path, exclusions: list[str] | tuple[str, ...] = ()
) -> RepositoryMetadata:
    """Discover bounded repository metadata without opening file contents.

    Symlinks, generated directories, common secret files, and private-key formats are skipped.
    The scanner records file names and aggregate sizes only; it never executes repository code.
    """
    root = repository.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Repository is not a directory: {root}")

    languages: Counter[str] = Counter()
    manifests: list[str] = []
    test_directories: set[str] = set()
    ci_files: list[str] = []
    container_files: list[str] = []
    kubernetes_files: list[str] = []
    total_files = 0
    total_bytes = 0
    skipped_sensitive_files = 0
    skipped_symlinks = 0
    skipped_custom_exclusions = 0

    for current_directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_directory)

        safe_directories: list[str] = []
        for directory_name in directory_names:
            candidate = current / directory_name
            relative_directory = _relative(candidate, root)
            if is_excluded_directory(directory_name):
                continue
            if matches_custom_exclusion(relative_directory, exclusions):
                skipped_custom_exclusions += 1
                continue
            if candidate.is_symlink():
                skipped_symlinks += 1
                continue
            safe_directories.append(directory_name)
            if _is_test_directory(candidate):
                test_directories.add(_relative(candidate, root))
        directory_names[:] = safe_directories

        for file_name in file_names:
            path = current / file_name
            if path.is_symlink():
                skipped_symlinks += 1
                continue
            relative_path = _relative(path, root)
            if matches_custom_exclusion(relative_path, exclusions):
                skipped_custom_exclusions += 1
                continue
            if is_sensitive_file(path):
                skipped_sensitive_files += 1
                continue

            try:
                stat = path.stat()
            except OSError:
                continue

            lowered_name = path.name.lower()
            total_files += 1
            total_bytes += stat.st_size

            language = _LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
            if language:
                languages[language] += 1
            if lowered_name in _MANIFEST_NAMES:
                manifests.append(relative_path)
            if _is_ci_file(relative_path):
                ci_files.append(relative_path)
            if _is_container_file(path):
                container_files.append(relative_path)
            if _is_kubernetes_file(relative_path):
                kubernetes_files.append(relative_path)

    return RepositoryMetadata(
        root=root,
        total_files=total_files,
        total_bytes=total_bytes,
        languages=dict(sorted(languages.items(), key=lambda item: (-item[1], item[0]))),
        manifests=sorted(manifests),
        test_directories=sorted(test_directories),
        ci_files=sorted(ci_files),
        container_files=sorted(container_files),
        kubernetes_files=sorted(kubernetes_files),
        skipped_sensitive_files=skipped_sensitive_files,
        skipped_symlinks=skipped_symlinks,
        skipped_custom_exclusions=skipped_custom_exclusions,
    )
