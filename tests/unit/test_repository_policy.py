from pathlib import Path

import pytest

from forgeflow_mcp.policy import resolve_safe_path
from forgeflow_mcp.tools import read_text_file, search_repository


def test_path_traversal_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSITORY_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="escapes"):
        resolve_safe_path("../outside.txt")


def test_sensitive_file_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSITORY_ROOT", str(tmp_path))
    (tmp_path / ".env").write_text("TOKEN=secret", encoding="utf-8")
    with pytest.raises(PermissionError):
        read_text_file(".env")


def test_search_is_literal_and_bounded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSITORY_ROOT", str(tmp_path))
    (tmp_path / "app.py").write_text("alpha.*beta\nalpha.*beta\n", encoding="utf-8")
    result = search_repository("alpha.*beta", max_results=1)
    assert result["truncated"] is True
    assert len(result["results"]) == 1


def test_env_variant_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSITORY_ROOT", str(tmp_path))
    (tmp_path / ".env.test").write_text("TOKEN=secret", encoding="utf-8")
    with pytest.raises(PermissionError):
        read_text_file(".env.test")


def test_binary_file_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSITORY_ROOT", str(tmp_path))
    (tmp_path / "artifact.jar").write_bytes(b"PK\\x03\\x04")
    with pytest.raises(ValueError, match="Binary"):
        read_text_file("artifact.jar")


def test_symlink_escape_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (repository / "link.txt").symlink_to(outside)
    monkeypatch.setenv("REPOSITORY_ROOT", str(repository))
    with pytest.raises(ValueError, match="escapes"):
        resolve_safe_path("link.txt")
