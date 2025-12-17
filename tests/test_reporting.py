"""
Tests for reporting.py - Output structure and format tests.

These tests verify that the reporting functions produce correct
markdown and JSON output.
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, Any

import pytest

from luciq_swatpack.reporting import (
    write_json_snapshot,
    write_markdown_report,
    _build_recommendations,
    _build_executive_summary,
)


def _create_minimal_snapshot() -> Dict[str, Any]:
    """Create a minimal valid snapshot for testing."""
    return {
        "run_metadata": {
            "tool_version": "0.1.0",
            "schema_version": "0.1",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "run_id": "test-run-id",
            "platform_detected": "ios",
            "scan_root": "/test/path",
            "cli_arguments": {},
            "typer_version": "0.9.0",
        },
        "project_identity": {
            "app_name": "TestApp",
            "bundle_id": "com.test.app",
            "xcodeproj_paths": [],
            "workspace_paths": [],
            "build_systems_detected": [],
            "deployment_targets_detected": [],
            "swift_versions_detected": [],
        },
        "luciq_sdk": {
            "luciq_installed": False,
            "integration_method": "none",
            "sdk_versions_detected": [],
            "sdk_sources": [],
        },
        "luciq_usage": {
            "init_found": False,
            "init_locations": [],
            "invocation_events_detected": [],
            "network_logging_found": False,
            "network_masking_found": False,
            "screenshot_masking_found": False,
            "repro_steps_found": False,
            "identify_hooks_found": False,
            "logout_hooks_found": False,
            "usage_locations": [],
            "feature_flag_calls": [],
        },
        "module_states": {
            "bug_reporting_enabled": None,
            "crash_reporting_enabled": None,
            "session_replay_enabled": None,
            "surveys_enabled": None,
            "feature_requests_enabled": None,
            "in_app_replies_enabled": None,
            "in_app_chat_enabled": None,
            "apm_enabled": None,
            "network_logs_enabled": None,
            "user_steps_enabled": None,
            "sdk_globally_disabled": None,
            "debug_logs_enabled": None,
            "ndk_module_present": None,
            "react_native_integration_detected": None,
            "flutter_integration_detected": None,
            "oom_monitor_enabled": None,
            "anr_monitor_enabled": None,
            "force_restart_enabled": None,
            "network_auto_masking_enabled": None,
        },
        "privacy_settings": {
            "auto_masking_calls": [],
            "private_view_calls_found": False,
            "compose_private_modifiers_found": False,
            "network_masking_rules_found": False,
            "masked_header_terms": [],
            "masked_body_terms": [],
            "missing_header_terms": [],
            "missing_body_terms": [],
        },
        "token_analysis": {
            "tokens_detected": [],
            "multiple_tokens_detected": False,
            "placeholder_token_detected": False,
        },
        "symbolication": {
            "dsym_upload_detected": False,
            "dsym_locations": [],
            "mapping_or_sourcemap_detected": False,
            "mapping_locations": [],
        },
        "symbol_pipeline": {
            "ios": {"scripts_detected": [], "endpoints": [], "app_tokens": [], "issues": []},
            "android": {"mapping_tasks": [], "endpoints": [], "app_tokens": [], "issues": []},
            "react_native": {"dependencies": [], "env_flags": [], "sourcemap_paths": [], "issues": []},
        },
        "environment": {
            "macos_version": None,
            "xcode_version": None,
            "swift_version": None,
            "cocoapods_version": None,
            "carthage_version": None,
        },
        "privacy_disclosure": {
            "files_read": [],
            "fields_captured": ["Run metadata"],
            "fields_not_captured": ["Source code"],
        },
        "extra_findings": [],
        "feature_flag_summary": {
            "events_detected": 0,
            "flags_tracked": [],
            "operation_breakdown": {},
            "clear_on_logout_detected": False,
        },
        "invocation_summary": {
            "gesture_events": [],
            "programmatic_invocations": [],
            "issues": [],
        },
        "custom_logging": {
            "log_calls": [],
            "custom_data_calls": [],
        },
        "attachment_summary": {
            "attachment_api_detected": False,
            "options": {},
            "required_permissions_missing": [],
        },
        "permissions_summary": {
            "ios_usage_descriptions": {},
            "android_permissions": {},
        },
        "release_artifacts": {
            "app_store_keys_detected": [],
            "play_service_accounts_detected": [],
            "team_config_files": [],
        },
    }


# =============================================================================
# JSON OUTPUT TESTS
# =============================================================================


class TestWriteJsonSnapshot:
    """Tests for write_json_snapshot function."""

    def test_creates_json_file(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_json_snapshot(tmp, snapshot)

            assert path.exists()
            assert path.name == "luciq_swatpack.json"
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_json_is_valid(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_json_snapshot(tmp, snapshot)

            content = path.read_text()
            parsed = json.loads(content)
            assert parsed["run_metadata"]["tool_version"] == "0.1.0"
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_json_is_indented(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_json_snapshot(tmp, snapshot)

            content = path.read_text()
            # Indented JSON should have newlines
            assert "\n" in content
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# =============================================================================
# MARKDOWN OUTPUT TESTS
# =============================================================================


class TestWriteMarkdownReport:
    """Tests for write_markdown_report function."""

    def test_creates_markdown_file(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_markdown_report(tmp, snapshot)

            assert path.exists()
            assert path.name == "luciq_swatpack_report.md"
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_has_title(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_markdown_report(tmp, snapshot)

            content = path.read_text()
            assert "# Luciq SWAT Pack Report" in content
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_has_executive_summary(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_markdown_report(tmp, snapshot)

            content = path.read_text()
            assert "## Executive Summary" in content
            assert "Quick Health Check" in content
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_has_all_sections(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            path = write_markdown_report(tmp, snapshot)

            content = path.read_text()

            expected_sections = [
                "## Executive Summary",
                "## Run Metadata",
                "## Project Identity",
                "## Luciq SDK",
                "## Luciq Usage",
                "## Module States",
                "## Privacy & Masking",
                "## Custom Logging",
                "## Attachments & Permissions",
                "## Token Analysis",
                "## Symbolication",
                "## Environment",
                "## Symbol Pipeline",
                "## Release Artifacts",
                "## Privacy Disclosure",
            ]

            for section in expected_sections:
                assert section in content, f"Missing section: {section}"
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# =============================================================================
# EXECUTIVE SUMMARY TESTS
# =============================================================================


class TestBuildExecutiveSummary:
    """Tests for _build_executive_summary function."""

    def test_returns_list_of_strings(self):
        snapshot = _create_minimal_snapshot()
        result = _build_executive_summary(snapshot)
        assert isinstance(result, list)
        assert all(isinstance(line, str) for line in result)

    def test_contains_health_check_table(self):
        snapshot = _create_minimal_snapshot()
        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "| Check | Status |" in content
        assert "SDK Installed" in content
        assert "Luciq.start()" in content

    def test_shows_sdk_installed_status(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = True

        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "Installed" in content

    def test_shows_sdk_not_found_status(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = False

        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "NOT FOUND" in content

    def test_shows_invocation_events(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_usage"]["invocation_events_detected"] = ["shake", "screenshot"]

        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "shake" in content or "screenshot" in content

    def test_shows_token_status_placeholder(self):
        snapshot = _create_minimal_snapshot()
        snapshot["token_analysis"]["placeholder_token_detected"] = True

        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "PLACEHOLDER DETECTED" in content

    def test_shows_integration_method(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["integration_method"] = "spm"

        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        assert "spm" in content


# =============================================================================
# RECOMMENDATIONS TESTS
# =============================================================================


class TestBuildRecommendations:
    """Tests for _build_recommendations function."""

    def test_returns_list_of_strings(self):
        snapshot = _create_minimal_snapshot()
        result = _build_recommendations(snapshot)
        assert isinstance(result, list)
        assert all(isinstance(line, str) for line in result)

    def test_critical_when_sdk_installed_but_no_init(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = True
        snapshot["luciq_usage"]["init_found"] = False

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "CRITICAL" in content
        assert "Luciq.start" in content

    def test_critical_when_placeholder_token(self):
        snapshot = _create_minimal_snapshot()
        snapshot["token_analysis"]["placeholder_token_detected"] = True

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "CRITICAL" in content
        assert "Placeholder token" in content

    def test_warning_when_multiple_tokens(self):
        snapshot = _create_minimal_snapshot()
        snapshot["token_analysis"]["multiple_tokens_detected"] = True

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "WARNING" in content
        assert "Multiple tokens" in content

    def test_recommends_network_masking(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_usage"]["network_logging_found"] = True
        snapshot["luciq_usage"]["network_masking_found"] = False

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "Network logging" in content
        assert "obfuscation" in content.lower() or "masking" in content.lower()

    def test_recommends_identify_user(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_usage"]["init_found"] = True
        snapshot["luciq_usage"]["identify_hooks_found"] = False

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "identifyUser" in content or "identification" in content.lower()

    def test_recommends_logout(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_usage"]["identify_hooks_found"] = True
        snapshot["luciq_usage"]["logout_hooks_found"] = False

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "logOut" in content or "logout" in content.lower()

    def test_recommends_dsym_upload(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = True
        snapshot["symbolication"]["dsym_upload_detected"] = False

        result = _build_recommendations(snapshot)
        content = "\n".join(result)

        assert "dSYM" in content or "symbolication" in content.lower()

    def test_no_recommendations_for_well_configured_project(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = True
        snapshot["luciq_usage"]["init_found"] = True
        snapshot["luciq_usage"]["invocation_events_detected"] = ["shake"]
        snapshot["luciq_usage"]["identify_hooks_found"] = True
        snapshot["luciq_usage"]["logout_hooks_found"] = True
        snapshot["luciq_usage"]["network_logging_found"] = True
        snapshot["luciq_usage"]["network_masking_found"] = True
        snapshot["luciq_usage"]["screenshot_masking_found"] = True
        snapshot["symbolication"]["dsym_upload_detected"] = True

        result = _build_recommendations(snapshot)

        # Should have minimal or no recommendations
        assert len(result) <= 2  # Maybe environment warnings


# =============================================================================
# RECOMMENDATION PRIORITY TESTS
# =============================================================================


class TestRecommendationPriority:
    """Tests for recommendation ordering and priority."""

    def test_critical_issues_first(self):
        snapshot = _create_minimal_snapshot()
        snapshot["luciq_sdk"]["luciq_installed"] = True
        snapshot["luciq_usage"]["init_found"] = False
        snapshot["token_analysis"]["placeholder_token_detected"] = True
        snapshot["luciq_usage"]["network_logging_found"] = True
        snapshot["luciq_usage"]["network_masking_found"] = False

        result = _build_recommendations(snapshot)

        # CRITICAL issues should appear before non-critical
        critical_indices = [i for i, r in enumerate(result) if "CRITICAL" in r]
        non_critical_indices = [i for i, r in enumerate(result) if "CRITICAL" not in r and "WARNING" not in r]

        if critical_indices and non_critical_indices:
            assert max(critical_indices) < min(non_critical_indices), \
                "CRITICAL recommendations should come before non-critical"


# =============================================================================
# OUTPUT FORMAT TESTS
# =============================================================================


class TestOutputFormat:
    """Tests for correct output formatting."""

    def test_markdown_tables_are_valid(self):
        """Executive summary tables should have proper markdown format."""
        snapshot = _create_minimal_snapshot()
        result = _build_executive_summary(snapshot)
        content = "\n".join(result)

        # Should have header row and separator
        lines = content.split("\n")
        table_lines = [l for l in lines if "|" in l]

        if len(table_lines) >= 2:
            # Second line should be separator
            separator = table_lines[1]
            assert "-" in separator, "Table should have separator row"

    def test_code_snippets_in_fenced_blocks(self):
        """Code snippets should be in fenced code blocks."""
        tmp = Path(tempfile.mkdtemp())
        try:
            snapshot = _create_minimal_snapshot()
            snapshot["luciq_usage"]["usage_locations"] = [{
                "file": "App.swift",
                "line": 10,
                "snippet_type": "Luciq.start",
                "code_snippet": 'Luciq.start(withToken: "test")',
            }]

            path = write_markdown_report(tmp, snapshot)
            content = path.read_text()

            # Should have fenced code blocks
            assert "```swift" in content or "```" in content
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
