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
    lines.append(
        f"- Auto-masking calls: {', '.join(auto_calls) if auto_calls else 'none'}"
    )
    lines.append(
        f"- Private view tags found: {privacy_settings['private_view_calls_found']}"
    )
    lines.append(
        f"- Compose masking modifiers: {privacy_settings['compose_private_modifiers_found']}"
    )
    lines.append(
        f"- Network masking rules: {privacy_settings['network_masking_rules_found']}"
    )
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

    recommendations = _build_recommendations(snapshot)
    if recommendations:
        lines.append("## Recommendations")
        for rec in recommendations:
            lines.append(f"- {rec}")
        lines.append("")

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
    recs: List[str] = []
    usage = snapshot["luciq_usage"]
    sdk = snapshot["luciq_sdk"]
    env = snapshot["environment"]
    project = snapshot["project_identity"]

    if usage["network_logging_found"] and not usage["network_masking_found"]:
        recs.append(
            "Network logging detected without request obfuscation. Consider enabling NetworkLogger.setRequestObfuscationHandler."
        )
    if usage["network_logging_found"] and not usage["screenshot_masking_found"]:
        recs.append(
            "Network logging detected without screenshot masking; verify Luciq.setAutoMaskScreenshots is intentionally disabled."
        )
    if usage["init_found"] and not usage["invocation_events_detected"]:
        recs.append(
            "Luciq.start uses manual invocation only. Confirm Support knows how to trigger Luciq in this build."
        )
    if sdk["luciq_installed"] and not usage["init_found"]:
        recs.append(
            "Luciq SDK detected but Luciq.start was not found. Ensure initialization occurs before reproducing issues."
        )
    if "cocoapods" in project["build_systems_detected"] and not env.get(
        "cocoapods_version"
    ):
        recs.append("CocoaPods project detected but `pod --version` not available on this host.")
    if "carthage" in project["build_systems_detected"] and not env.get(
        "carthage_version"
    ):
        recs.append("Carthage project detected but `carthage version` not available on this host.")
    return recs

