import json
from pathlib import Path

from forgeflow.cli import _run_analyze


def test_analyze_writes_deterministic_reports(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "main.py").write_text("print('hello')", encoding="utf-8")
    output = tmp_path / "reports"

    exit_code = _run_analyze(repository, output)

    assert exit_code == 0
    assert (output / "review.md").exists()
    findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert {finding["rule_id"] for finding in findings} == {"FF-CI-001", "FF-TEST-001"}
    summary = json.loads((output / "execution-summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["total_files"] == 1
    assert summary["analysis"]["finding_count"] == 2
    assert summary["execution"]["status"] == "completed"


def test_analyze_rejects_missing_repository(tmp_path: Path) -> None:
    exit_code = _run_analyze(tmp_path / "missing", tmp_path / "reports")
    assert exit_code == 2
