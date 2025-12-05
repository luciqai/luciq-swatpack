import json
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from luciq_swatpack.cli import app

RUNNER = CliRunner()
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SCHEMA = Path(__file__).resolve().parent.parent / "schema_v0_1.json"


def test_dry_run_prints_manifest(tmp_path):
    fixture = FIXTURES / "luciq_not_installed"
    result = RUNNER.invoke(app, ["scan", str(fixture), "--dry-run"])
    assert result.exit_code == 0
    assert "Capture Manifest" in result.stdout
    assert not any(tmp_path.iterdir())


def test_spm_scan_produces_outputs(tmp_path):
    fixture = FIXTURES / "spm_only"
    out_dir = tmp_path / "out"
    result = RUNNER.invoke(
        app,
        ["scan", str(fixture), "--output-dir", str(out_dir), "--include-ci-hints"],
    )
    assert result.exit_code == 0
    json_path = out_dir / "luciq_swatpack.json"
    report_path = out_dir / "luciq_swatpack_report.md"
    assert json_path.exists()
    assert report_path.exists()
    data = json.loads(json_path.read_text())
    schema = json.loads(SCHEMA.read_text())
    jsonschema.validate(instance=data, schema=schema)
    assert data["luciq_sdk"]["luciq_installed"] is True
    assert data["luciq_usage"]["init_found"] is True
    assert "ci_hints" in data
    assert data["feature_flag_summary"]["events_detected"] >= 1
    assert data["invocation_summary"]["programmatic_invocations"]
    assert data["custom_logging"]["log_calls"]
    ios_perms = data["permissions_summary"]["ios_usage_descriptions"]
    assert ios_perms["microphone"] is True
    assert ios_perms.get("photo_library", False) is False
    missing_perms = data["attachment_summary"]["required_permissions_missing"]
    assert "photo_library" in missing_perms
    assert data["release_artifacts"]["app_store_keys_detected"] == []


def test_no_luciq_detected(tmp_path):
    fixture = FIXTURES / "luciq_not_installed"
    out_dir = tmp_path / "out"
    RUNNER.invoke(app, ["scan", str(fixture), "--output-dir", str(out_dir)])
    data = json.loads((out_dir / "luciq_swatpack.json").read_text())
    assert data["luciq_sdk"]["luciq_installed"] is False


def test_files_allowlist_is_honored():
    fixture = FIXTURES / "spm_only"
    result = RUNNER.invoke(
        app,
        [
            "scan",
            str(fixture),
            "--dry-run",
            "--files-allowlist",
            "*App/App.swift",
            "--files-allowlist",
            "*App/Info.plist",
        ],
    )
    assert result.exit_code == 0
    assert "Custom file allowlist patterns in effect" in result.stdout
