from pathlib import Path

from forgeflow.scanner import discover_repository, scan_repository


def test_custom_exclusion_applies_to_discovery_and_rules(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "unsafe.py").write_text(
        'password = "production-password"\n', encoding="utf-8"
    )
    (tmp_path / "safe.py").write_text("print('safe')\n", encoding="utf-8")

    metadata = discover_repository(tmp_path, ["src/**"])
    findings = scan_repository(tmp_path, metadata, ["src/**"])

    assert metadata.total_files == 1
    assert metadata.skipped_custom_exclusions == 1
    assert all(finding.rule_id != "FF-SEC-001" for finding in findings)


def test_prior_forgeflow_reports_are_not_rescanned(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / "old-output").mkdir()
    (tmp_path / "old-output" / "findings.json").write_text(
        '{"evidence": "subprocess.run(command, shell=True)"}', encoding="utf-8"
    )

    metadata = discover_repository(tmp_path)
    findings = scan_repository(tmp_path, metadata)

    assert all(finding.rule_id != "FF-SEC-002" for finding in findings)
