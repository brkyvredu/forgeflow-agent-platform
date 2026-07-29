from pathlib import Path

from forgeflow.scanner import discover_repository


def test_discovery_skips_generated_sensitive_and_symlink_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('safe')", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_ok(): pass", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]", encoding="utf-8")

    outside = tmp_path.parent / "outside-forgeflow.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "outside-link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pass

    metadata = discover_repository(tmp_path)

    assert metadata.total_files == 3
    assert metadata.languages == {"Python": 2}
    assert metadata.manifests == ["pyproject.toml"]
    assert metadata.test_directories == ["tests"]
    assert metadata.skipped_sensitive_files == 1
    assert "node_modules/ignored.js" not in metadata.manifests
