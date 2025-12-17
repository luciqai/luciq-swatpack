from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .analysis import analyze_project


def write_json_snapshot(output_dir: Path, snapshot: Dict[str, Any]) -> Path:
    output_path = output_dir / "luciq_swatpack.json"
    with output_path.open("w", encoding="utf-8") as fp:
        json.dump(snapshot, fp, indent=2, sort_keys=True)
        fp.write("\n")
    return output_path


def write_markdown_report(
    output_dir: Path, snapshot: Dict[str, Any]
) -> Path:
    report_path = output_dir / "luciq_swatpack_report.md"
    lines: List[str] = []
    lines.append("# Luciq SWAT Pack Report")
    lines.append("")

    # Executive Summary at the top for quick assessment
    lines.extend(_build_executive_summary(snapshot))
    lines.append("")

    # Recommendations near the top (actionable items)
    recommendations = _build_recommendations(snapshot)
    if recommendations:
        lines.append("## Recommendations")
        for rec in recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    run_metadata = snapshot["run_metadata"]
    lines.append("## Run Metadata")
    lines.append(f"- Timestamp (UTC): {run_metadata['timestamp_utc']}")
    lines.append(f"- Run ID: {run_metadata['run_id']}")
    lines.append(f"- Tool version: {run_metadata['tool_version']}")
    lines.append(f"- Schema version: {run_metadata['schema_version']}")
    lines.append(f"- Scan root: {run_metadata['scan_root']}")
    lines.append(f"- Typer version: {run_metadata.get('typer_version', 'unknown')}")
    cli_args = run_metadata.get("cli_arguments", {})
    if cli_args:
        lines.append("- CLI arguments:")
        for key, value in cli_args.items():
            lines.append(f"  - {key}: {value}")
    lines.append("")

    project_identity = snapshot["project_identity"]
    lines.append("## Project Identity")
    lines.append(f"- App name: {project_identity['app_name']}")
    lines.append(f"- Bundle ID: {project_identity['bundle_id']}")
    lines.append(
        f"- Build systems detected: {', '.join(project_identity['build_systems_detected']) or 'none'}"
    )
    if project_identity["xcodeproj_paths"]:
        lines.append("- Xcode projects:")
        for path in project_identity["xcodeproj_paths"]:
            lines.append(f"  - {path}")
    if project_identity["workspace_paths"]:
        lines.append("- Xcode workspaces:")
        for path in project_identity["workspace_paths"]:
            lines.append(f"  - {path}")
    lines.append(
        f"- Deployment targets: {', '.join(project_identity['deployment_targets_detected']) or 'n/a'}"
    )
    lines.append(
        f"- Swift versions: {', '.join(project_identity['swift_versions_detected']) or 'n/a'}"
    )
    lines.append("")

    luciq_sdk = snapshot["luciq_sdk"]
    lines.append("## Luciq SDK")
    lines.append(f"- Luciq installed: {luciq_sdk['luciq_installed']}")
    lines.append(
        f"- Integration method: {luciq_sdk['integration_method']}"
    )
    lines.append(
        f"- Versions detected: {', '.join(luciq_sdk['sdk_versions_detected']) or 'n/a'}"
    )
    lines.append(
        f"- Sources: {', '.join(luciq_sdk['sdk_sources']) or 'n/a'}"
    )
    lines.append("")

    usage = snapshot["luciq_usage"]
    lines.append("## Luciq Usage")
    lines.append(f"- Luciq.start found: {usage['init_found']}")
    if usage["init_locations"]:
        lines.append("  - init locations:")
        for loc in usage["init_locations"]:
            lines.append(f"    - {loc['file']}:{loc['line']}")
    lines.append(
        f"- Invocation events: {', '.join(usage['invocation_events_detected']) or 'n/a'}"
    )
    lines.append(f"- Network logging: {usage['network_logging_found']}")
    lines.append(f"- Network masking: {usage['network_masking_found']}")
    lines.append(
        f"- Screenshot masking: {usage['screenshot_masking_found']}"
    )
    lines.append(f"- Repro steps configured: {usage['repro_steps_found']}")
    lines.append(f"- identify hooks: {usage['identify_hooks_found']}")
    lines.append(f"- logout hooks: {usage['logout_hooks_found']}")
    lines.append("")

    if usage["usage_locations"]:
        lines.append("### Luciq API Calls")
        for call in usage["usage_locations"]:
            lines.append(
                f"- `{call['snippet_type']}` at {call['file']}:{call['line']}"
            )
            snippet = call.get("code_snippet")
            if snippet:
                lines.extend(_format_snippet_block(snippet, indent="  "))
        lines.append("")
    if usage.get("feature_flag_calls"):
        lines.append("### Feature Flag / Remote Config Calls")
        for call in usage["feature_flag_calls"]:
            lines.append(f"- `{call['operation']}` at {call['file']}:{call['line']}")
            if call.get("flag_name"):
                variant = call.get("variant") or "n/a"
                lines.append(
                    f"  flag `{call['flag_name']}` variant `{variant}`"
                )
            snippet = call.get("code_snippet")
            if snippet:
                lines.extend(_format_snippet_block(snippet, indent="  "))
        lines.append("")
    feature_flag_summary = snapshot["feature_flag_summary"]
    lines.append("### Feature Flag Summary")
    lines.append(f"- Events detected: {feature_flag_summary['events_detected']}")
    tracked = ", ".join(feature_flag_summary["flags_tracked"]) or "none"
    lines.append(f"- Flags tracked: {tracked}")
    op_breakdown = feature_flag_summary["operation_breakdown"]
    if op_breakdown:
        lines.append("- Operation breakdown:")
        for op, count in op_breakdown.items():
            lines.append(f"  - {op}: {count}")
    lines.append(
        f"- Flags cleared on logout: {feature_flag_summary['clear_on_logout_detected']}"
    )
    lines.append("")
    invocation_summary = snapshot["invocation_summary"]
    lines.append("### Invocation Summary")
    lines.append(
        f"- Gesture events: {', '.join(invocation_summary['gesture_events']) or 'none'}"
    )
    if invocation_summary["programmatic_invocations"]:
        lines.append("- Programmatic invocations:")
        for call in invocation_summary["programmatic_invocations"]:
            lines.append(f"  - `{call['call']}` at {call['file']}:{call['line']}")
    else:
        lines.append("- Programmatic invocations: none")
    if invocation_summary["issues"]:
        lines.append("- Issues:")
        for issue in invocation_summary["issues"]:
            lines.append(f"  - {issue}")
    lines.append("")

    module_states = snapshot["module_states"]
    lines.append("## Module States")
    for key, value in module_states.items():
        label = key.replace("_", " ").title()
        rendered = "unknown" if value is None else str(value)
        lines.append(f"- {label}: {rendered}")
    lines.append("")

    privacy_settings = snapshot["privacy_settings"]
    lines.append("## Privacy & Masking")
    auto_calls = privacy_settings["auto_masking_calls"]
    if auto_calls:
        lines.append("- Auto-masking calls:")
        for call in auto_calls:
            label = call.get("call", "Luciq.setAutoMaskScreenshots")
            args = call.get("arguments", "")
            lines.append(
                f"  - `{label}` at {call['file']}:{call['line']} (args: {args or 'n/a'})"
            )
            snippet = call.get("code_snippet")
            if snippet:
                lines.extend(_format_snippet_block(snippet, indent="    "))
    else:
        lines.append("- Auto-masking calls: none")
    lines.append(
        f"- Private view tags found: {privacy_settings['private_view_calls_found']}"
    )
    lines.append(
        f"- Compose masking modifiers: {privacy_settings['compose_private_modifiers_found']}"
    )
    lines.append(
        f"- Network masking rules: {privacy_settings['network_masking_rules_found']}"
    )
    masked_headers = ", ".join(privacy_settings.get("masked_header_terms", [])) or "none"
    lines.append(f"- Masked header terms: {masked_headers}")
    masked_body = ", ".join(privacy_settings.get("masked_body_terms", [])) or "none"
    lines.append(f"- Masked body fields: {masked_body}")
    missing_headers = ", ".join(privacy_settings.get("missing_header_terms", [])) or "none"
    lines.append(f"- Missing header masks: {missing_headers}")
    missing_body = ", ".join(privacy_settings.get("missing_body_terms", [])) or "none"
    lines.append(f"- Missing body masks: {missing_body}")
    lines.append("")
    custom_logging = snapshot["custom_logging"]
    lines.append("## Custom Logging")
    if custom_logging["log_calls"]:
        lines.append("- Log calls:")
        for call in custom_logging["log_calls"]:
            lines.append(f"  - `{call['call']}` at {call['file']}:{call['line']}")
    else:
        lines.append("- Log calls: none")
    if custom_logging["custom_data_calls"]:
        lines.append("- Custom data calls:")
        for call in custom_logging["custom_data_calls"]:
            lines.append(f"  - `{call['call']}` at {call['file']}:{call['line']}")
    else:
        lines.append("- Custom data calls: none")
    lines.append("")

    attachment_summary = snapshot["attachment_summary"]
    permissions_summary = snapshot["permissions_summary"]
    lines.append("## Attachments & Permissions")
    lines.append(
        f"- Attachment API detected: {attachment_summary['attachment_api_detected']}"
    )
    if attachment_summary["options"]:
        lines.append("- Attachment options:")
        for key, value in attachment_summary["options"].items():
            lines.append(f"  - {key}: {value}")
    ios_perms = permissions_summary["ios_usage_descriptions"]
    lines.append("- iOS usage descriptions:")
    for key, value in ios_perms.items():
        lines.append(f"  - {key}: {value}")
    android_perms = permissions_summary["android_permissions"]
    lines.append("- Android permissions:")
    for key, value in android_perms.items():
        lines.append(f"  - {key}: {value}")
    missing_perms = ", ".join(attachment_summary["required_permissions_missing"]) or "none"
    lines.append(f"- Missing attachment permissions: {missing_perms}")
    lines.append("")

    token_info = snapshot["token_analysis"]
    lines.append("## Token Analysis")
    if token_info["tokens_detected"]:
        lines.append("- Tokens observed (masked):")
        for entry in token_info["tokens_detected"]:
            lines.append(
                f"  - {entry['value_masked']} from {entry['file']}:{entry['line']}"
            )
    else:
        lines.append("- Tokens observed: none")
    lines.append(
        f"- Multiple tokens detected: {token_info['multiple_tokens_detected']}"
    )
    lines.append(
        f"- Placeholder token detected: {token_info['placeholder_token_detected']}"
    )
    lines.append("")

    symbolication = snapshot["symbolication"]
    lines.append("## Symbolication")
    lines.append(
        f"- dSYM upload detected: {symbolication['dsym_upload_detected']}"
    )
    if symbolication["dsym_locations"]:
        lines.append("- dSYM locations:")
        for loc in symbolication["dsym_locations"]:
            lines.append(f"  - {loc}")
    lines.append(
        f"- Mapping/sourcemap detected: {symbolication['mapping_or_sourcemap_detected']}"
    )
    if symbolication["mapping_locations"]:
        lines.append("- Mapping locations:")
        for loc in symbolication["mapping_locations"]:
            lines.append(f"  - {loc}")
    lines.append("")

    if "ci_hints" in snapshot:
        ci_hints = snapshot["ci_hints"]
        lines.append("## CI Hints")
        lines.append(
            f"- CI systems detected: {', '.join(ci_hints['ci_systems_detected']) or 'none'}"
        )
        if ci_hints["config_paths"]:
            lines.append("- Config files:")
            for path in ci_hints["config_paths"]:
                lines.append(f"  - {path}")
        lines.append("")

    environment = snapshot["environment"]
    lines.append("## Environment")
    for key, value in environment.items():
        lines.append(f"- {key.replace('_', ' ')}: {value or 'unavailable'}")
    lines.append("")

    # Note: Recommendations are now shown at the top of the report

    if snapshot["extra_findings"]:
        lines.append("## Extra Findings")
        for finding in snapshot["extra_findings"]:
            lines.append(
                f"- {finding['label']}: {finding['value']} ({finding['rationale']})"
            )
        lines.append("")

    pipeline = snapshot["symbol_pipeline"]
    lines.append("## Symbol Pipeline")
    ios_info = pipeline["ios"]
    lines.append("- iOS:")
    lines.append(
        f"  - Scripts: {', '.join(ios_info['scripts_detected']) if ios_info['scripts_detected'] else 'none'}"
    )
    lines.append(
        f"  - Endpoints: {', '.join(ios_info['endpoints']) if ios_info['endpoints'] else 'none'}"
    )
    lines.append(
        f"  - Tokens: {', '.join(ios_info['app_tokens']) if ios_info['app_tokens'] else 'none'}"
    )
    if ios_info["issues"]:
        lines.append("  - Issues:")
        for issue in ios_info["issues"]:
            lines.append(f"    - {issue}")
    android_info = pipeline["android"]
    lines.append("- Android:")
    lines.append(
        f"  - Mapping tasks: {', '.join(android_info['mapping_tasks']) if android_info['mapping_tasks'] else 'none'}"
    )
    lines.append(
        f"  - Endpoints: {', '.join(android_info['endpoints']) if android_info['endpoints'] else 'none'}"
    )
    lines.append(
        f"  - Tokens: {', '.join(android_info['app_tokens']) if android_info['app_tokens'] else 'none'}"
    )
    if android_info["issues"]:
        lines.append("  - Issues:")
        for issue in android_info["issues"]:
            lines.append(f"    - {issue}")
    rn_info = pipeline["react_native"]
    lines.append("- React Native:")
    lines.append(
        f"  - Dependencies: {', '.join(rn_info['dependencies']) if rn_info['dependencies'] else 'none'}"
    )
    lines.append(
        f"  - Env flags: {', '.join(rn_info['env_flags']) if rn_info['env_flags'] else 'none'}"
    )
    lines.append(
        f"  - Sourcemap paths: {', '.join(rn_info['sourcemap_paths']) if rn_info['sourcemap_paths'] else 'none'}"
    )
    if rn_info["issues"]:
        lines.append("  - Issues:")
        for issue in rn_info["issues"]:
            lines.append(f"    - {issue}")
    lines.append("")
    release_artifacts = snapshot["release_artifacts"]
    lines.append("## Release Artifacts")
    if release_artifacts["app_store_keys_detected"]:
        lines.append("- App Store Connect keys:")
        for path in release_artifacts["app_store_keys_detected"]:
            lines.append(f"  - {path}")
    else:
        lines.append("- App Store Connect keys: none")
    if release_artifacts["play_service_accounts_detected"]:
        lines.append("- Play service accounts:")
        for path in release_artifacts["play_service_accounts_detected"]:
            lines.append(f"  - {path}")
    else:
        lines.append("- Play service accounts: none")
    if release_artifacts["team_config_files"]:
        lines.append("- Team ownership configs:")
        for path in release_artifacts["team_config_files"]:
            lines.append(f"  - {path}")
    else:
        lines.append("- Team ownership configs: none")
    lines.append("")

    privacy = snapshot["privacy_disclosure"]
    lines.append("## Privacy Disclosure")
    lines.append("- Files read:")
    if privacy["files_read"]:
        for path in privacy["files_read"]:
            lines.append(f"  - {path}")
    else:
        lines.append("  - (none)")
    lines.append("- Fields captured:")
    for field_label in privacy["fields_captured"]:
        lines.append(f"  - {field_label}")
    lines.append("- Fields NOT captured:")
    for field_label in privacy["fields_not_captured"]:
        lines.append(f"  - {field_label}")

    with report_path.open("w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    return report_path


def _build_recommendations(snapshot: Dict[str, Any]) -> List[str]:
    """Build actionable recommendations based on detected configuration."""
    recs: List[str] = []
    usage = snapshot["luciq_usage"]
    sdk = snapshot["luciq_sdk"]
    env = snapshot["environment"]
    project = snapshot["project_identity"]
    token_info = snapshot["token_analysis"]
    symbolication = snapshot["symbolication"]
    privacy = snapshot["privacy_settings"]

    # Critical issues first
    if sdk["luciq_installed"] and not usage["init_found"]:
        recs.append(
            "**CRITICAL:** Luciq SDK detected but Luciq.start was not found. "
            "Ensure initialization occurs before reproducing issues."
        )

    if token_info["placeholder_token_detected"]:
        recs.append(
            "**CRITICAL:** Placeholder token detected (e.g., 'YOUR-TOKEN-HERE'). "
            "Replace with actual app token from dashboard."
        )

    if token_info["multiple_tokens_detected"]:
        recs.append(
            "**WARNING:** Multiple tokens detected. Verify the correct token is being used "
            "for the target environment."
        )

    # Invocation issues
    if usage["init_found"] and not usage["invocation_events_detected"]:
        recs.append(
            "Luciq.start uses manual invocation only (no shake/screenshot/floatingButton). "
            "Confirm Support knows how to trigger Luciq in this build."
        )

    # Privacy/masking issues
    if usage["network_logging_found"] and not usage["network_masking_found"]:
        recs.append(
            "Network logging detected without request obfuscation. "
            "Consider enabling NetworkLogger.setRequestObfuscationHandler to mask sensitive headers."
        )

    if usage["network_logging_found"] and not usage["screenshot_masking_found"]:
        recs.append(
            "Network logging detected without screenshot masking. "
            "Verify Luciq.setAutoMaskScreenshots is intentionally disabled or configure masking."
        )

    # Missing masking for sensitive headers
    missing_headers = privacy.get("missing_header_terms", [])
    if missing_headers:
        recs.append(
            f"Network masking may be incomplete. Consider masking these headers: {', '.join(missing_headers)}"
        )

    # User identification
    if usage["init_found"] and not usage["identify_hooks_found"]:
        recs.append(
            "No Luciq.identifyUser calls detected. User identification helps correlate "
            "reports with specific users in the dashboard."
        )

    if usage["identify_hooks_found"] and not usage["logout_hooks_found"]:
        recs.append(
            "identifyUser detected but no logOut call found. Consider calling Luciq.logOut() "
            "when users sign out to properly clear user context."
        )

    # Symbolication
    if sdk["luciq_installed"] and not symbolication["dsym_upload_detected"]:
        recs.append(
            "No dSYM upload script detected. Crash reports may not be properly symbolicated. "
            "See: https://docs.luciq.ai/docs/ios-symbolication"
        )

    # Environment checks
    if "cocoapods" in project["build_systems_detected"] and not env.get("cocoapods_version"):
        recs.append(
            "CocoaPods project detected but `pod --version` not available on this host."
        )

    if "carthage" in project["build_systems_detected"] and not env.get("carthage_version"):
        recs.append(
            "Carthage project detected but `carthage version` not available on this host."
        )

    return recs


def _format_snippet_block(snippet: str, indent: str = "") -> List[str]:
    snippet_lines = snippet.splitlines() or [snippet]
    block = [f"{indent}```swift"]
    block.extend(f"{indent}{line}" for line in snippet_lines)
    block.append(f"{indent}```")
    return block


def _build_executive_summary(snapshot: Dict[str, Any]) -> List[str]:
    """Build a quick at-a-glance summary for SWAT team assessment."""
    lines: List[str] = []
    lines.append("## Executive Summary")
    lines.append("")

    sdk = snapshot["luciq_sdk"]
    usage = snapshot["luciq_usage"]
    module_states = snapshot["module_states"]
    privacy = snapshot["privacy_settings"]
    token_info = snapshot["token_analysis"]
    symbolication = snapshot["symbolication"]

    # Quick health indicators
    lines.append("### Quick Health Check")
    lines.append("")
    lines.append("| Check | Status |")
    lines.append("|-------|--------|")

    # SDK Installation
    sdk_status = "Installed" if sdk["luciq_installed"] else "NOT FOUND"
    lines.append(f"| SDK Installed | {sdk_status} |")

    # Initialization
    init_status = "Found" if usage["init_found"] else "NOT FOUND"
    lines.append(f"| Luciq.start() | {init_status} |")

    # Invocation events
    events = usage["invocation_events_detected"]
    events_status = ", ".join(events) if events else "NONE"
    lines.append(f"| Invocation Events | {events_status} |")

    # User identification
    identify_status = "Configured" if usage["identify_hooks_found"] else "Not detected"
    lines.append(f"| User Identification | {identify_status} |")

    # Network masking
    if usage["network_logging_found"]:
        mask_status = "Configured" if usage["network_masking_found"] else "MISSING"
    else:
        mask_status = "N/A (no network logging)"
    lines.append(f"| Network Masking | {mask_status} |")

    # Screenshot masking
    screenshot_status = "Configured" if usage["screenshot_masking_found"] else "Not detected"
    lines.append(f"| Screenshot Masking | {screenshot_status} |")

    # Symbolication
    dsym_status = "Configured" if symbolication["dsym_upload_detected"] else "Not detected"
    lines.append(f"| dSYM Upload | {dsym_status} |")

    # Token status
    if token_info["placeholder_token_detected"]:
        token_status = "PLACEHOLDER DETECTED"
    elif token_info["multiple_tokens_detected"]:
        token_status = "Multiple tokens found"
    elif token_info["tokens_detected"]:
        token_status = "OK"
    else:
        token_status = "Not detected in code"
    lines.append(f"| Token Status | {token_status} |")

    lines.append("")

    # Integration summary
    lines.append(f"**Integration Method:** {sdk['integration_method']}")
    if sdk["sdk_versions_detected"]:
        versions = ", ".join(sdk["sdk_versions_detected"])
        lines.append(f"**SDK Version(s):** {versions}")

    # Count issues
    issues_count = 0
    if snapshot.get("extra_findings"):
        issues_count += len(snapshot["extra_findings"])
    pipeline = snapshot.get("symbol_pipeline", {})
    for platform_info in pipeline.values():
        if isinstance(platform_info, dict) and platform_info.get("issues"):
            issues_count += len(platform_info["issues"])

    if issues_count > 0:
        lines.append(f"**Issues Detected:** {issues_count}")

    return lines

