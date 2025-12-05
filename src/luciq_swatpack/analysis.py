from __future__ import annotations

import json
import plistlib
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .plan import CapturePlan
from .utils import redact_home, relative_path, run_command
from . import __version__

INVOCATION_EVENT_PATTERN = re.compile(r"\.(shake|screenshot|floatingButton)")

FEATURE_API_PATTERNS = {
    "Luciq.addFeatureFlag": "add_feature_flag",
    "Luciq.addFeatureFlags": "add_feature_flags",
    "Luciq.removeFeatureFlag": "remove_feature_flag",
    "Luciq.removeFeatureFlags": "remove_feature_flags",
    "Luciq.removeAllFeatureFlags": "remove_all_feature_flags",
    "Luciq.checkFeatures": "check_features",
}

MODULE_DEFAULT_TRUE = {
    "bug_reporting_enabled",
    "crash_reporting_enabled",
    "anr_monitor_enabled",
    "session_replay_enabled",
    "apm_enabled",
    "network_logs_enabled",
    "user_steps_enabled",
    "surveys_enabled",
    "feature_requests_enabled",
    "in_app_replies_enabled",
    "in_app_chat_enabled",
    "oom_monitor_enabled",
}

MODULE_DEFAULT_FALSE = {
    "sdk_globally_disabled",
    "debug_logs_enabled",
}

NETWORK_SENSITIVE_HEADERS = [
    "Authorization",
    "Cookie",
    "X-API-Key",
    "Set-Cookie",
]
NETWORK_SENSITIVE_BODY_FIELDS = [
    "password",
    "token",
    "access_token",
    "refresh_token",
    "ssn",
    "email",
]

IOS_USAGE_DESCRIPTION_KEYS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSPhotoLibraryUsageDescription": "photo_library",
    "NSPhotoLibraryAddUsageDescription": "photo_library_add",
}

ANDROID_PERMISSION_KEYS = {
    "android.permission.INTERNET": "internet",
    "android.permission.ACCESS_NETWORK_STATE": "network_state",
    "android.permission.RECORD_AUDIO": "record_audio",
    "android.permission.READ_EXTERNAL_STORAGE": "read_storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "write_storage",
    "android.permission.POST_NOTIFICATIONS": "post_notifications",
}

ATTACHMENT_PERMISSION_MAP = {
    "gallery_image": "photo_library",
    "voice_note": "microphone",
}

ATTACHMENT_LABELS = {
    "screenshot": ["screenshot", "screenShot"],
    "extra_screenshot": ["extraScreenshot", "extraScreenShot"],
    "gallery_image": ["galleryImage", "gallery"],
    "voice_note": ["voiceNote"],
    "screen_recording": ["screenRecording"],
}

PROGRAMMATIC_INVOCATION_PATTERNS = [
    "Luciq.show(",
    "Luciq.invoke(",
    "BugReporting.show(",
    "BugReporting.invoke(",
]

CUSTOM_LOG_PATTERNS = [
    "Luciq.log(",
    "Luciq.logVerbose(",
    "Luciq.logInfo(",
    "Luciq.logWarn(",
    "Luciq.logError(",
    "Luciq.logDebug(",
]

CUSTOM_DATA_PATTERNS = [
    "Luciq.setCustomData",
    "Luciq.addUserAttribute",
    "Luciq.setUserAttribute",
]

MODULE_TOGGLE_PATTERNS = {
    "bug_reporting_enabled": [
        "Luciq.setBugReportingEnabled",
        "BugReporting.enabled",
        "BugReporting.setState",
    ],
    "crash_reporting_enabled": [
        "Luciq.setCrashReportingEnabled",
        "CrashReporting.enabled",
        "CrashReporting.setState",
    ],
    "session_replay_enabled": [
        "Luciq.setSessionReplayEnabled",
        "SessionReplay.enabled",
    ],
    "surveys_enabled": [
        "Luciq.setSurveysEnabled",
        "Surveys.enabled",
    ],
    "feature_requests_enabled": [
        "Luciq.setFeatureRequestsEnabled",
        "FeatureRequests.enabled",
    ],
    "in_app_replies_enabled": [
        "Luciq.setRepliesEnabled",
        "Replies.enabled",
        "Luciq.setChatsEnabled",
    ],
    "in_app_chat_enabled": [
        "Luciq.setChatsEnabled",
        "Chats.enabled",
    ],
    "apm_enabled": [
        "Luciq.setAPMEnabled",
    ],
    "network_logs_enabled": [
        "SessionReplay.setNetworkLogsEnabled",
    ],
    "user_steps_enabled": [
        "SessionReplay.setUserStepsEnabled",
    ],
    "oom_monitor_enabled": [
        "CrashReporting.oomEnabled",
    ],
    "anr_monitor_enabled": [
        "CrashReporting.setAnrState",
    ],
}


@dataclass
class AnalysisContext:
    root: Path
    plan: CapturePlan
    include_ci_hints: bool
    cli_arguments: Dict[str, Any] = field(default_factory=dict)
    typer_version: str = "unknown"
    files_read: Set[Path] = field(default_factory=set)
    pbx_text_cache: Dict[Path, str] = field(default_factory=dict)
    gradle_text_cache: Dict[Path, str] = field(default_factory=dict)
    package_json_cache: Dict[Path, Dict[str, Any]] = field(default_factory=dict)

    def record_read(self, path: Path) -> None:
        self.files_read.add(path.resolve())


def analyze_project(ctx: AnalysisContext) -> Dict[str, Any]:
    project_identity, build_systems, manual_hint = _collect_project_identity(ctx)
    luciq_sdk = _collect_luciq_sdk(ctx, build_systems, manual_hint)
    (
        usage_data,
        module_states,
        privacy_settings,
        token_analysis,
        scan_meta,
    ) = _scan_luciq_usage(ctx)
    symbolication = _detect_symbolication(ctx.root)
    symbol_pipeline = _collect_symbol_pipeline(ctx)
    ci_hints = (
        _detect_ci_hints(ctx) if ctx.include_ci_hints else None
    )
    environment = _collect_environment()
    privacy = _build_privacy_disclosure(ctx)
    feature_flag_summary = _summarize_feature_flags(
        scan_meta["feature_flag_events"], scan_meta["clear_feature_flags_on_logout"]
    )
    invocation_summary = _summarize_invocations(
        usage_data["invocation_events_detected"],
        scan_meta["programmatic_invocations"],
    )
    custom_logging = _summarize_custom_logging(
        scan_meta["custom_log_calls"], scan_meta["custom_data_calls"]
    )
    attachment_summary = _summarize_attachments(scan_meta["attachment_options"])
    permissions_summary = _collect_permissions(ctx)
    _annotate_attachment_permissions(attachment_summary, permissions_summary)
    release_artifacts = _collect_release_artifacts(ctx)
    extra_findings = _derive_extra_findings(
        luciq_sdk,
        usage_data,
        token_analysis,
        symbol_pipeline,
        module_states,
        permissions_summary,
        attachment_summary,
        privacy_settings,
    )

    run_metadata = {
        "tool_version": __version__,
        "schema_version": "0.1",
        "timestamp_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "run_id": _generate_uuid(),
        "platform_detected": "ios",
        "scan_root": redact_home(ctx.root),
        "cli_arguments": ctx.cli_arguments,
        "typer_version": ctx.typer_version,
    }

    result: Dict[str, Any] = {
        "run_metadata": run_metadata,
        "project_identity": project_identity,
        "luciq_sdk": luciq_sdk,
        "luciq_usage": usage_data,
        "module_states": module_states,
        "privacy_settings": privacy_settings,
        "token_analysis": token_analysis,
        "symbolication": symbolication,
        "symbol_pipeline": symbol_pipeline,
        "environment": environment,
        "privacy_disclosure": privacy,
        "extra_findings": extra_findings,
        "feature_flag_summary": feature_flag_summary,
        "invocation_summary": invocation_summary,
        "custom_logging": custom_logging,
        "attachment_summary": attachment_summary,
        "permissions_summary": permissions_summary,
        "release_artifacts": release_artifacts,
    }
    if ci_hints is not None:
        result["ci_hints"] = ci_hints
    return result


def _collect_project_identity(
    ctx: AnalysisContext,
) -> Tuple[Dict[str, Any], List[str], bool]:
    app_name = "unknown"
    bundle_id = "unknown"
    for info_plist in ctx.plan.files_by_role.get("info_plists", []):
        data = _read_plist(ctx, info_plist)
        if not data:
            continue
        if app_name == "unknown":
            app_name = data.get("CFBundleName") or app_name
        if bundle_id == "unknown":
            bundle_id = data.get("CFBundleIdentifier") or bundle_id
        if app_name != "unknown" and bundle_id != "unknown":
            break

    xcodeproj_paths = sorted(
        {
            relative_path(path.parent, ctx.root)
            for path in ctx.plan.files_by_role.get("xcodeproj", [])
        }
    )
    workspace_paths = sorted(
        {
            relative_path(path, ctx.root)
            for path in ctx.root.rglob("*.xcworkspace")
            if "DerivedData" not in path.parts and ".git" not in path.parts
        }
    )

    deployment_targets: Set[str] = set()
    swift_versions: Set[str] = set()
    manual_embed_hint = False

    pbx_dt_pattern = re.compile(r"IPHONEOS_DEPLOYMENT_TARGET = ([0-9.]+);")
    pbx_swift_pattern = re.compile(r"SWIFT_VERSION = ([0-9.]+);")
    for project in ctx.plan.files_by_role.get("xcodeproj", []):
        text = _safe_read_text(ctx, project)
        if text is None:
            continue
        ctx.pbx_text_cache[project] = text
        deployment_targets.update(pbx_dt_pattern.findall(text))
        swift_versions.update(pbx_swift_pattern.findall(text))
        if "LuciqSDK.xcframework" in text or "LuciqSDK.framework" in text:
            manual_embed_hint = True

    build_systems = []
    if ctx.plan.files_by_role.get("package_resolved"):
        build_systems.append("spm")
    if ctx.plan.files_by_role.get("podfiles"):
        build_systems.append("cocoapods")
    if ctx.plan.files_by_role.get("cartfiles"):
        build_systems.append("carthage")

    manual_embed = manual_embed_hint or any(
        "LuciqSDK.xcframework" in str(path)
        for path in ctx.root.rglob("LuciqSDK.xcframework")
    )
    if manual_embed:
        build_systems.append("manual")

    identity = {
        "app_name": app_name,
        "bundle_id": bundle_id,
        "xcodeproj_paths": xcodeproj_paths,
        "workspace_paths": workspace_paths,
        "build_systems_detected": sorted(dict.fromkeys(build_systems)),
        "deployment_targets_detected": sorted(deployment_targets),
        "swift_versions_detected": sorted(swift_versions),
    }
    return identity, identity["build_systems_detected"], manual_embed_hint


def _collect_luciq_sdk(
    ctx: AnalysisContext, build_systems: List[str], manual_hint: bool
) -> Dict[str, Any]:
    versions: Set[str] = set()
    sources: Set[str] = set()
    luciq_installed = False
    manual_detected = manual_hint or _detect_manual_embed(
        ctx, skip_project_scan=manual_hint
    )
    if manual_detected:
        luciq_installed = True
        manual_version = _detect_manual_sdk_version(ctx)
        if manual_version:
            versions.add(manual_version)
        else:
            versions.add("unknown")
        sources.add("manual_detection")

    spm_versions = _parse_package_resolved(ctx)
    if spm_versions:
        versions.update(spm_versions)
        sources.add("Package.resolved")
        luciq_installed = True

    pod_versions = _parse_podfile_lock(ctx)
    if pod_versions:
        versions.update(pod_versions)
        sources.add("Podfile.lock")
        luciq_installed = True

    carthage_versions = _parse_carthage_resolved(ctx)
    if carthage_versions:
        versions.update(carthage_versions)
        sources.add("Cartfile.resolved")
        luciq_installed = True

    integration_method = "unknown"
    if luciq_installed:
        if manual_detected and len(build_systems) == 0:
            integration_method = "manual"
        elif len(build_systems) == 1:
            integration_method = build_systems[0]

    return {
        "luciq_installed": luciq_installed,
        "integration_method": integration_method,
        "sdk_versions_detected": sorted(v for v in versions if v),
        "sdk_sources": sorted(sources),
    }


def _scan_luciq_usage(
    ctx: AnalysisContext,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Optional[bool]],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    init_locations: List[Dict[str, Any]] = []
    usage_locations: List[Dict[str, Any]] = []
    invocation_events: Set[str] = set()
    init_found = False
    network_logging_found = False
    network_masking_found = False
    screenshot_masking_found = False
    repro_steps_found = False
    identify_hooks_found = False
    logout_hooks_found = False
    tokens_detected: List[Dict[str, Any]] = []
    token_values: Set[str] = set()
    placeholder_token_detected = False

    module_states: Dict[str, Optional[bool]] = {
        "bug_reporting_enabled": None,
        "crash_reporting_enabled": None,
        "anr_monitor_enabled": None,
        "session_replay_enabled": None,
        "apm_enabled": None,
        "network_logs_enabled": None,
        "user_steps_enabled": None,
        "sdk_globally_disabled": None,
        "debug_logs_enabled": None,
        "ndk_module_present": None,
        "react_native_integration_detected": None,
        "flutter_integration_detected": None,
        "surveys_enabled": None,
        "feature_requests_enabled": None,
        "in_app_replies_enabled": None,
        "in_app_chat_enabled": None,
        "oom_monitor_enabled": None,
    }

    privacy_settings = {
        "auto_masking_calls": [],
        "private_view_calls_found": False,
        "compose_private_modifiers_found": False,
        "network_masking_rules_found": False,
    }

    feature_flag_calls: List[Dict[str, Any]] = []
    programmatic_invocations: List[Dict[str, Any]] = []
    custom_log_calls: List[Dict[str, Any]] = []
    custom_data_calls: List[Dict[str, Any]] = []
    network_mask_headers: Set[str] = set()
    network_mask_body: Set[str] = set()
    attachment_options: Optional[Dict[str, Optional[bool]]] = None
    remove_all_feature_flag_calls: List[Dict[str, Any]] = []
    clear_feature_flags_on_logout = False

    swift_files = ctx.plan.files_by_role.get("swift_sources", [])
    for path in swift_files:
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        lines = text.splitlines()
        token_candidates = _extract_token_candidates(text)
        func_pattern = re.compile(r"^\s*(?:@objc\s+)?(?:private|fileprivate|public|internal)?\s*(?:static\s+)?func\s+([A-Za-z0-9_]+)")
        current_function = None
        for idx, line in enumerate(lines, start=1):
            rel = relative_path(path, ctx.root)
            window = "\n".join(lines[idx - 1 : idx + 2])
            snippet = _format_snippet(window)
            func_match = func_pattern.match(line.strip())
            if func_match:
                current_function = func_match.group(1).lower()
            for needle, label in FEATURE_API_PATTERNS.items():
                if needle in line:
                    context_block = _gather_context(lines, idx)
                    flag_name, variant = _extract_feature_flag_details(label, context_block)
                    event = {
                        "file": rel,
                        "line": idx,
                        "operation": label,
                        "flag_name": flag_name,
                        "variant": variant,
                        "code_snippet": snippet,
                    }
                    feature_flag_calls.append(event)
                    if label == "remove_all_feature_flags":
                        remove_all_feature_flag_calls.append(event)
                        if current_function and any(
                            token in current_function for token in ("logout", "signout")
                        ):
                            clear_feature_flags_on_logout = True
                    break
            for module_key, patterns in MODULE_TOGGLE_PATTERNS.items():
                if any(pattern in line for pattern in patterns):
                    inferred = _bool_from_line(line)
                    if inferred is not None:
                        module_states[module_key] = inferred
                    continue
            for invocation_pattern in PROGRAMMATIC_INVOCATION_PATTERNS:
                if invocation_pattern in line:
                    programmatic_invocations.append(
                        {
                            "file": rel,
                            "line": idx,
                            "call": invocation_pattern.rstrip("("),
                            "code_snippet": snippet,
                        }
                    )
                    break
            for log_pattern in CUSTOM_LOG_PATTERNS:
                if log_pattern in line:
                    custom_log_calls.append(
                        {
                            "file": rel,
                            "line": idx,
                            "call": log_pattern.rstrip("("),
                            "code_snippet": snippet,
                        }
                    )
                    break
            for data_pattern in CUSTOM_DATA_PATTERNS:
                if data_pattern in line:
                    custom_data_calls.append(
                        {
                            "file": rel,
                            "line": idx,
                            "call": data_pattern,
                            "code_snippet": snippet,
                        }
                    )
                    break
            if _is_probable_code_use(line, "Luciq.start"):
                init_found = True
                init_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.start",
                        "code_snippet": snippet,
                    }
                )
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.start",
                        "code_snippet": snippet,
                    }
                )
                invocation_events.update(
                    INVOCATION_EVENT_PATTERN.findall(window)
                )
                token = _resolve_token_value(window, token_candidates)
                if token:
                    masked = _mask_token(token)
                    tokens_detected.append(
                        {"file": rel, "line": idx, "value_masked": masked}
                    )
                    token_values.add(token)
                    if _looks_like_placeholder_token(token):
                        placeholder_token_detected = True
            if _is_probable_code_use(line, "Luciq.setAutoMaskScreenshots"):
                screenshot_masking_found = True
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.setAutoMaskScreenshots",
                        "code_snippet": snippet,
                    }
                )
                privacy_settings["auto_masking_calls"].append(
                    {
                        "file": rel,
                        "line": idx,
                        "call": "Luciq.setAutoMaskScreenshots",
                        "arguments": _extract_masking_arguments(window),
                        "code_snippet": snippet,
                    }
                )
            if _is_probable_code_use(line, "Luciq.setReproStepsFor"):
                repro_steps_found = True
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.setReproStepsFor",
                        "code_snippet": snippet,
                    }
                )
            if _is_probable_code_use(line, "Luciq.identifyUser"):
                identify_hooks_found = True
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.identifyUser",
                        "code_snippet": snippet,
                    }
                )
            if _is_probable_code_use(line, "Luciq.logOut"):
                logout_hooks_found = True
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.logOut",
                        "code_snippet": snippet,
                    }
                )
            if _is_probable_code_use(line, "NetworkLogger"):
                network_logging_found = True
                usage_locations.append(
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "NetworkLogger",
                        "code_snippet": snippet,
                    }
                )
            if _is_probable_code_use(line, "NetworkLogger.setRequestObfuscationHandler"):
                network_masking_found = True
                privacy_settings["network_masking_rules_found"] = True
                context_block = _gather_context(lines, idx, after=25)
                headers_found, body_found = _extract_masking_terms(context_block)
                network_mask_headers.update(headers_found)
                network_mask_body.update(body_found)
            if "setAttachmentTypesEnabled" in line:
                context_block = _gather_context(lines, idx, after=20)
                attachment_options = _extract_attachment_options(context_block)
            if _is_probable_code_use(line, "Luciq.disable"):
                module_states["sdk_globally_disabled"] = True
            if _is_probable_code_use(line, "Luciq.enable") and module_states["sdk_globally_disabled"] is None:
                module_states["sdk_globally_disabled"] = False
            if _is_probable_code_use(line, "Luciq.setDebugEnabled"):
                module_states["debug_logs_enabled"] = _bool_from_line(line)
            if _is_probable_code_use(line, "Luciq.setAutoMaskingLevel"):
                privacy_settings["auto_masking_calls"].append(
                    {
                        "file": rel,
                        "line": idx,
                        "call": "Luciq.setAutoMaskingLevel",
                        "arguments": _extract_masking_arguments(window),
                        "code_snippet": snippet,
                    }
                )
            if ".luciqPrivate" in line or "Luciq.setPrivateView" in line:
                privacy_settings["private_view_calls_found"] = True
            if ".luciqPrivate" in line:
                privacy_settings["compose_private_modifiers_found"] = True

    if _detect_react_native_dependency(ctx):
        module_states["react_native_integration_detected"] = True
    if _detect_flutter_dependency(ctx):
        module_states["flutter_integration_detected"] = True
    if _gradle_has_ndk_dependency(ctx):
        module_states["ndk_module_present"] = True

    if init_found:
        for key in MODULE_DEFAULT_TRUE:
            if module_states.get(key) is None:
                module_states[key] = True
        for key in MODULE_DEFAULT_FALSE:
            if module_states.get(key) is None:
                module_states[key] = False

    masked_header_terms = sorted(dict.fromkeys(network_mask_headers))
    masked_body_terms = sorted(dict.fromkeys(network_mask_body))
    privacy_settings["masked_header_terms"] = masked_header_terms
    privacy_settings["masked_body_terms"] = masked_body_terms
    privacy_settings["missing_header_terms"] = [
        header
        for header in NETWORK_SENSITIVE_HEADERS
        if header not in network_mask_headers
    ]
    privacy_settings["missing_body_terms"] = [
        field for field in NETWORK_SENSITIVE_BODY_FIELDS if field not in network_mask_body
    ]

    usage_locations_list = sorted(
        usage_locations,
        key=lambda entry: (entry["file"], entry["line"], entry["snippet_type"]),
    )
    usage = {
        "init_found": init_found,
        "init_locations": init_locations,
        "invocation_events_detected": sorted(invocation_events),
        "network_logging_found": network_logging_found,
        "network_masking_found": network_masking_found,
        "screenshot_masking_found": screenshot_masking_found,
        "repro_steps_found": repro_steps_found,
        "identify_hooks_found": identify_hooks_found,
        "logout_hooks_found": logout_hooks_found,
        "usage_locations": usage_locations_list,
        "feature_flag_calls": feature_flag_calls,
    }
    token_info = {
        "tokens_detected": tokens_detected,
        "multiple_tokens_detected": len(token_values) > 1,
        "placeholder_token_detected": placeholder_token_detected,
    }
    scan_meta = {
        "programmatic_invocations": programmatic_invocations,
        "custom_log_calls": custom_log_calls,
        "custom_data_calls": custom_data_calls,
        "attachment_options": attachment_options,
        "feature_flag_events": feature_flag_calls,
        "clear_feature_flags_on_logout": clear_feature_flags_on_logout,
    }
    return usage, module_states, privacy_settings, token_info, scan_meta


def _detect_symbolication(root: Path) -> Dict[str, Any]:
    dsym_locations = sorted(
        {
            relative_path(path, root)
            for path in root.rglob("*.dSYM")
            if "DerivedData" not in path.parts
        }
    )
    upload_scripts = sorted(
        {
            relative_path(path, root)
            for path in root.rglob("*upload-symbols*")
        }
    )
    mapping_locations = sorted(
        {
            relative_path(path, root)
            for path in root.rglob("*mapping*")
            if path.is_file()
        }
    )
    mapping_locations += sorted(
        {
            relative_path(path, root)
            for path in root.rglob("*sourcemap*")
            if path.is_file()
        }
    )
    mapping_locations = sorted(dict.fromkeys(mapping_locations))
    return {
        "dsym_upload_detected": bool(upload_scripts or dsym_locations),
        "dsym_locations": dsym_locations or upload_scripts,
        "mapping_or_sourcemap_detected": bool(mapping_locations),
        "mapping_locations": mapping_locations,
    }


ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"']*instabug\.com[^\s\"']*")
TOKEN_ENV_PATTERN = re.compile(r"(INSTABUG|LUCIQ)_APP_TOKEN\s*=?\s*['\"]?([A-Za-z0-9_\-]+)")
APP_TOKEN_PATTERN = re.compile(r"appToken\s*=\s*['\"]([^\"']+)['\"]")


def _collect_symbol_pipeline(ctx: AnalysisContext) -> Dict[str, Any]:
    ios_info = _extract_ios_symbol_pipeline(ctx)
    android_info = _extract_android_symbol_pipeline(ctx)
    react_native_info = _extract_react_native_symbol_pipeline(ctx)
    return {
        "ios": ios_info,
        "android": android_info,
        "react_native": react_native_info,
    }


def _detect_ci_hints(ctx: AnalysisContext) -> Dict[str, Any]:
    systems: Set[str] = set()
    paths: List[str] = []
    for path in ctx.plan.files_by_role.get("ci_configs", []):
        rel = relative_path(path, ctx.root)
        paths.append(rel)
        lower = rel.lower()
        if "fastfile" in lower or "fastlane" in lower:
            systems.add("fastlane")
        elif ".github/workflows" in lower:
            systems.add("github_actions")
        elif "bitrise" in lower:
            systems.add("bitrise")
        elif "circleci" in lower or "circle.yml" in lower or "config.yml" in lower:
            systems.add("circleci")
        elif "jenkins" in lower:
            systems.add("jenkins")
        else:
            systems.add("other")
    return {
        "ci_systems_detected": sorted(systems),
        "config_paths": sorted(dict.fromkeys(paths)),
    }


def _collect_environment() -> Dict[str, Optional[str]]:
    return {
        "macos_version": run_command(["sw_vers", "-productVersion"]),
        "xcode_version": run_command(["xcodebuild", "-version"]),
        "swift_version": run_command(["swift", "--version"]),
        "cocoapods_version": run_command(["pod", "--version"]),
        "carthage_version": run_command(["carthage", "version"]),
    }


def _build_privacy_disclosure(ctx: AnalysisContext) -> Dict[str, Any]:
    files = sorted(
        {relative_path(path, ctx.root) for path in ctx.files_read}
    )
    return {
        "files_read": files,
        "fields_captured": ctx.plan.fields_to_capture(),
        "fields_not_captured": ctx.plan.fields_not_captured(),
    }


def _derive_extra_findings(
    luciq_sdk: Dict[str, Any],
    luciq_usage: Dict[str, Any],
    token_info: Dict[str, Any],
    symbol_pipeline: Dict[str, Any],
    module_states: Dict[str, Optional[bool]],
    permissions_summary: Dict[str, Any],
    attachment_summary: Dict[str, Any],
    privacy_settings: Dict[str, Any],
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    if luciq_sdk["luciq_installed"] and not luciq_usage["init_found"]:
        findings.append(
            {
                "label": "missing_luciq_init",
                "value": "not_detected",
                "rationale": "Luciq SDK files detected but Luciq.start was not found.",
            }
        )
    if (
        luciq_usage["network_logging_found"]
        and not luciq_usage["screenshot_masking_found"]
    ):
        findings.append(
            {
                "label": "missing_screenshot_masking",
                "value": "not_detected",
                "rationale": "NetworkLogger usage detected without Luciq.setAutoMaskScreenshots.",
            }
        )
    if (
        luciq_usage["network_logging_found"]
        and not luciq_usage["network_masking_found"]
    ):
        findings.append(
            {
                "label": "missing_network_obfuscation",
                "value": "not_detected",
                "rationale": "NetworkLogger usage detected without NetworkLogger.setRequestObfuscationHandler.",
            }
        )
    if luciq_usage["init_found"] and not luciq_usage["invocation_events_detected"]:
        findings.append(
            {
                "label": "manual_invocation_only",
                "value": "no_invocation_events",
                "rationale": "Luciq.start detected but invocation events could not be inferred (likely manual trigger).",
            }
        )
    if token_info["placeholder_token_detected"]:
        findings.append(
            {
                "label": "placeholder_token_detected",
                "value": "placeholder",
                "rationale": "Luciq.start appears to use a placeholder token; replace it with a real App Token.",
            }
        )
    if token_info["multiple_tokens_detected"]:
        findings.append(
            {
                "label": "multiple_tokens_detected",
                "value": "multiple",
                "rationale": "Multiple Luciq tokens detected in source; ensure build variants set the correct value.",
            }
        )
    if (
        symbol_pipeline["ios"]["scripts_detected"] == []
        and symbol_pipeline["ios"]["issues"] == []
        and symbol_pipeline["ios"]["endpoints"] == []
    ):
        findings.append(
            {
                "label": "ios_symbol_upload_script_missing",
                "value": "not_detected",
                "rationale": "No Luciq/Instabug dSYM upload script was detected in the Xcode project.",
            }
        )
    missing_headers = privacy_settings.get("missing_header_terms", [])
    if missing_headers and luciq_usage["network_masking_found"]:
        findings.append(
            {
                "label": "network_masking_incomplete",
                "value": ", ".join(missing_headers),
                "rationale": "Network obfuscation handler detected but some sensitive headers are not masked.",
            }
        )
    missing_attachment_perms = attachment_summary.get("required_permissions_missing", [])
    if missing_attachment_perms:
        findings.append(
            {
                "label": "attachment_permissions_missing",
                "value": ", ".join(missing_attachment_perms),
                "rationale": "Attachment types are enabled but required Info.plist usage descriptions are missing.",
            }
        )
    for key, label in [
        ("bug_reporting_enabled", "bug_reporting_disabled"),
        ("crash_reporting_enabled", "crash_reporting_disabled"),
        ("session_replay_enabled", "session_replay_disabled"),
        ("surveys_enabled", "surveys_disabled"),
        ("feature_requests_enabled", "feature_requests_disabled"),
        ("in_app_replies_enabled", "in_app_replies_disabled"),
        ("in_app_chat_enabled", "in_app_chat_disabled"),
        ("oom_monitor_enabled", "oom_monitor_disabled"),
    ]:
        if module_states.get(key) is False:
            findings.append(
                {
                    "label": label,
                    "value": "disabled",
                    "rationale": f"{key.replace('_', ' ').title()} is explicitly disabled in code.",
                }
            )
    return findings


def _read_plist(ctx: AnalysisContext, path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("rb") as fp:
            ctx.record_read(path)
            return plistlib.load(fp)
    except Exception:
        return None


def _safe_read_text(ctx: AnalysisContext, path: Path) -> Optional[str]:
    try:
        data = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            data = path.read_text(encoding="latin-1", errors="ignore")
        except Exception:
            return None
    except Exception:
        return None
    ctx.record_read(path)
    return data


def _parse_package_resolved(ctx: AnalysisContext) -> Set[str]:
    versions: Set[str] = set()
    for path in ctx.plan.files_by_role.get("package_resolved", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        pins = data.get("pins") or data.get("object", {}).get("pins", [])
        for pin in pins:
            identity = pin.get("identity") or pin.get("package")
            location = (
                pin.get("location")
                or pin.get("repositoryURL")
                or ""
            )
            candidate = (identity or "") + " " + location
            if "luciq" not in candidate.lower():
                continue
            state = pin.get("state") or {}
            version = state.get("version") or state.get("revision")
            if version:
                versions.add(str(version))
    return versions


def _parse_podfile_lock(ctx: AnalysisContext) -> Set[str]:
    versions: Set[str] = set()
    pattern = re.compile(r"Luciq(?:/[A-Za-z0-9_]+)? \(([^)]+)\)")
    for path in ctx.plan.files_by_role.get("podfiles", []):
        if not path.name.endswith("Podfile.lock"):
            continue
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        for match in pattern.findall(text):
            versions.add(match.strip())
    return versions


def _parse_carthage_resolved(ctx: AnalysisContext) -> Set[str]:
    versions: Set[str] = set()
    for path in ctx.plan.files_by_role.get("cartfiles", []):
        if path.name != "Cartfile.resolved":
            continue
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        for line in text.splitlines():
            if "luciq" not in line.lower():
                continue
            parts = line.strip().split()
            if parts and parts[-1].strip('"'):
                versions.add(parts[-1].strip('"'))
    return versions


def _detect_manual_embed(
    ctx: AnalysisContext, skip_project_scan: bool = False
) -> bool:
    if not skip_project_scan:
        for path in ctx.plan.files_by_role.get("xcodeproj", []):
            text = _safe_read_text(ctx, path)
            if not text:
                continue
            if "LuciqSDK.xcframework" in text or "LuciqSDK.framework" in text:
                return True
    for candidate in ctx.root.rglob("LuciqSDK.xcframework"):
        if "DerivedData" in candidate.parts or ".git" in candidate.parts:
            continue
        return True
    return False


def _detect_manual_sdk_version(ctx: AnalysisContext) -> Optional[str]:
    search_roots = list(ctx.root.rglob("LuciqSDK.xcframework"))
    for framework_root in search_roots:
        if "DerivedData" in framework_root.parts or ".git" in framework_root.parts:
            continue
        for platform in [
            "ios-arm64",
            "ios-arm64_x86_64-simulator",
            "tvos-arm64",
            "tvos-arm64_x86_64-simulator",
        ]:
            info_path = (
                framework_root
                / platform
                / "LuciqSDK.framework"
                / "Info.plist"
            )
            if info_path.exists():
                data = _read_plist(ctx, info_path)
                if not data:
                    continue
                version = data.get("CFBundleShortVersionString") or data.get(
                    "CFBundleVersion"
                )
                if version:
                    return version
    return None


TOKEN_LITERAL_PATTERN = re.compile(r'withToken:\s*"([^"]+)"')
TOKEN_IDENTIFIER_PATTERN = re.compile(
    r"withToken:\s*([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)
TOKEN_DECL_PATTERN = re.compile(
    r"(?:static\s+)?(?:private\s+|fileprivate\s+|public\s+|internal\s+)?(?:let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String)?\s*=\s*\"([^\"]+)\""
)


def _extract_token_candidates(text: str) -> Dict[str, str]:
    tokens: Dict[str, str] = {}
    for match in TOKEN_DECL_PATTERN.finditer(text):
        name, value = match.groups()
        tokens[name] = value
    return tokens


def _resolve_token_value(window: str, token_map: Dict[str, str]) -> Optional[str]:
    literal = _extract_token_literal(window)
    if literal:
        return literal
    condensed = window.replace("\n", " ")
    identifier_match = TOKEN_IDENTIFIER_PATTERN.search(condensed)
    if identifier_match:
        identifier = identifier_match.group(1)
        return token_map.get(identifier)
    return None


def _extract_token_literal(window: str) -> Optional[str]:
    match = TOKEN_LITERAL_PATTERN.search(window)
    if match:
        return match.group(1).strip()
    return None


def _extract_masking_arguments(window: str) -> str:
    normalized = window.replace("\n", " ")
    match = re.search(
        r"setAutoMask(?:Screenshots|ingLevel)\s*\((.*?)\)", normalized
    )
    if match:
        return match.group(1).strip()
    return ""


def _format_snippet(window: str) -> str:
    snippet = window.strip("\n")
    return snippet if len(snippet) <= 500 else snippet[:497] + "..."


def _is_probable_code_use(line: str, symbol: str) -> bool:
    pos = line.find(symbol)
    if pos == -1:
        return False
    stripped = line.strip()
    if stripped.startswith("//"):
        return False
    preceding = line[:pos]
    if preceding.count('"') % 2 == 1 or preceding.count("'") % 2 == 1:
        return False
    return True


def _mask_token(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


def _looks_like_placeholder_token(token: str) -> bool:
    token_upper = token.upper()
    return any(keyword in token_upper for keyword in ["YOUR", "TOKEN", "PLACEHOLDER"])


def _bool_from_line(line: str) -> Optional[bool]:
    lower = line.lower()
    if "disabled" in lower or "false" in lower:
        return False
    if "enabled" in lower or "true" in lower:
        return True
    return None


def _load_package_json_cache(ctx: AnalysisContext) -> None:
    if ctx.package_json_cache:
        return
    for path in ctx.plan.files_by_role.get("package_json", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        ctx.package_json_cache[path] = data


def _load_gradle_texts(ctx: AnalysisContext) -> None:
    if ctx.gradle_text_cache:
        return
    for path in ctx.plan.files_by_role.get("gradle_files", []):
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        ctx.gradle_text_cache[path] = text


def _detect_react_native_dependency(ctx: AnalysisContext) -> bool:
    _load_package_json_cache(ctx)
    for data in ctx.package_json_cache.values():
        deps = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key, {}))
        for name in deps:
            lname = name.lower()
            if "react" in lname and ("instabug" in lname or "luciq" in lname):
                return True
    return False


def _detect_flutter_dependency(ctx: AnalysisContext) -> bool:
    for path in ctx.plan.files_by_role.get("pubspec", []):
        text = _safe_read_text(ctx, path)
        if text and "luciq_flutter" in text:
            return True
    return False


def _gradle_has_ndk_dependency(ctx: AnalysisContext) -> bool:
    _load_gradle_texts(ctx)
    for text in ctx.gradle_text_cache.values():
        if "luciq-ndk-crash" in text:
            return True
    return False


def _extract_ios_symbol_pipeline(ctx: AnalysisContext) -> Dict[str, List[str]]:
    scripts: Set[str] = set()
    endpoints: Set[str] = set()
    tokens: Set[str] = set()
    issues: List[str] = []
    for path in ctx.plan.files_by_role.get("xcodeproj", []):
        text = ctx.pbx_text_cache.get(path)
        if not text:
            continue
        if any(keyword in text for keyword in ["upload_symbols", "instabug", "luciq"]):
            scripts.add(relative_path(path, ctx.root))
        endpoints.update(ENDPOINT_PATTERN.findall(text))
        tokens.update(_extract_app_tokens_from_text(text))
    for path in ctx.plan.files_by_role.get("shell_scripts", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        if any(keyword in text for keyword in ["upload", "instabug", "luciq"]):
            scripts.add(relative_path(path, ctx.root))
        endpoints.update(ENDPOINT_PATTERN.findall(text))
        tokens.update(_extract_app_tokens_from_text(text))
    for path in ctx.plan.files_by_role.get("env_files", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        endpoints.update(ENDPOINT_PATTERN.findall(text))
        tokens.update(_extract_env_tokens_from_text(text))
    if ctx.pbx_text_cache and not scripts:
        issues.append("No Luciq/Instabug dSYM upload script detected in Xcode project.")
    return {
        "scripts_detected": sorted(dict.fromkeys(scripts)),
        "endpoints": sorted(dict.fromkeys(endpoints)),
        "app_tokens": sorted(dict.fromkeys(tokens)),
        "issues": issues,
    }


def _extract_android_symbol_pipeline(ctx: AnalysisContext) -> Dict[str, List[str]]:
    _load_gradle_texts(ctx)
    mapping_tasks: Set[str] = set()
    endpoints: Set[str] = set()
    tokens: Set[str] = set()
    issues: List[str] = []
    for path, text in ctx.gradle_text_cache.items():
        rel = relative_path(path, ctx.root)
        if "mappingUpload" in text or "luciq" in text and "mapping" in text:
            mapping_tasks.add(rel)
        endpoints.update(ENDPOINT_PATTERN.findall(text))
        tokens.update(_extract_app_tokens_from_text(text))
    if ctx.gradle_text_cache and not mapping_tasks:
        issues.append("No Luciq mapping upload configuration detected in Gradle files.")
    return {
        "mapping_tasks": sorted(dict.fromkeys(mapping_tasks)),
        "endpoints": sorted(dict.fromkeys(endpoints)),
        "app_tokens": sorted(dict.fromkeys(tokens)),
        "issues": issues,
    }


def _extract_react_native_symbol_pipeline(
    ctx: AnalysisContext,
) -> Dict[str, List[str]]:
    dependencies: List[str] = []
    _load_package_json_cache(ctx)
    for data in ctx.package_json_cache.values():
        for key in ("dependencies", "devDependencies"):
            for name, version in data.get(key, {}).items():
                lname = name.lower()
                if "instabug" in lname or "luciq" in lname:
                    dependencies.append(f"{name}@{version}")
    env_flags = _collect_env_flags(ctx)
    sourcemap_paths = _collect_sourcemap_paths(ctx)
    issues: List[str] = []
    if dependencies and not env_flags:
        issues.append("React Native Luciq dependency detected but no INSTABUG/LUCIQ env flags were found.")
    return {
        "dependencies": sorted(dict.fromkeys(dependencies)),
        "env_flags": env_flags,
        "sourcemap_paths": sourcemap_paths,
        "issues": issues,
    }


def _extract_app_tokens_from_text(text: str) -> Set[str]:
    tokens: Set[str] = set()
    for match in APP_TOKEN_PATTERN.findall(text):
        tokens.add(_mask_token(match.strip()))
    for match in TOKEN_ENV_PATTERN.findall(text):
        tokens.add(_mask_token(match[1].strip()))
    return tokens


def _extract_env_tokens_from_text(text: str) -> Set[str]:
    tokens: Set[str] = set()
    for match in TOKEN_ENV_PATTERN.findall(text):
        tokens.add(_mask_token(match[1].strip()))
    return tokens


def _collect_env_flags(ctx: AnalysisContext) -> List[str]:
    flags: Set[str] = set()
    for path in ctx.plan.files_by_role.get("env_files", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "INSTABUG" in stripped or "LUCIQ" in stripped:
                flags.add(stripped)
    return sorted(dict.fromkeys(flags))


def _collect_sourcemap_paths(ctx: AnalysisContext) -> List[str]:
    paths: Set[str] = set()
    for path in ctx.plan.files_by_role.get("shell_scripts", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        if ".map" in text or ".jsbundle" in text:
            paths.add(relative_path(path, ctx.root))
    return sorted(dict.fromkeys(paths))


def _summarize_feature_flags(
    events: List[Dict[str, Any]], clear_on_logout: bool
) -> Dict[str, Any]:
    flags = sorted(
        {
            event["flag_name"]
            for event in events
            if event.get("flag_name")
        }
    )
    breakdown = Counter(event["operation"] for event in events)
    return {
        "events_detected": len(events),
        "flags_tracked": flags,
        "operation_breakdown": dict(breakdown),
        "clear_on_logout_detected": clear_on_logout,
    }


def _summarize_invocations(
    gesture_events: List[str], programmatic_invocations: List[Dict[str, Any]]
) -> Dict[str, Any]:
    issues: List[str] = []
    if not gesture_events and not programmatic_invocations:
        issues.append("No gesture or programmatic Luciq invocation detected.")
    return {
        "gesture_events": gesture_events,
        "programmatic_invocations": programmatic_invocations,
        "issues": issues,
    }


def _summarize_custom_logging(
    log_calls: List[Dict[str, Any]], data_calls: List[Dict[str, Any]]
) -> Dict[str, Any]:
    return {
        "log_calls": log_calls,
        "custom_data_calls": data_calls,
    }


def _summarize_attachments(
    attachment_options: Optional[Dict[str, Optional[bool]]]
) -> Dict[str, Any]:
    return {
        "attachment_api_detected": bool(attachment_options),
        "options": attachment_options or {},
        "required_permissions_missing": [],
    }


def _collect_permissions(ctx: AnalysisContext) -> Dict[str, Any]:
    ios_keys_found: Set[str] = set()
    for info_plist in ctx.plan.files_by_role.get("info_plists", []):
        data = _read_plist(ctx, info_plist)
        if not data:
            continue
        for key in IOS_USAGE_DESCRIPTION_KEYS:
            if key in data:
                ios_keys_found.add(key)
    android_permissions: Set[str] = set()
    for manifest in ctx.plan.files_by_role.get("android_manifests", []):
        text = _safe_read_text(ctx, manifest)
        if not text:
            continue
        for permission in ANDROID_PERMISSION_KEYS:
            if permission in text:
                android_permissions.add(permission)
    ios_summary = {
        friendly: (key in ios_keys_found)
        for key, friendly in IOS_USAGE_DESCRIPTION_KEYS.items()
    }
    android_summary = {
        friendly: (permission in android_permissions)
        for permission, friendly in ANDROID_PERMISSION_KEYS.items()
    }
    return {
        "ios_usage_descriptions": ios_summary,
        "android_permissions": android_summary,
    }


def _annotate_attachment_permissions(
    attachment_summary: Dict[str, Any], permissions_summary: Dict[str, Any]
) -> None:
    missing: List[str] = []
    ios_perms = permissions_summary.get("ios_usage_descriptions", {})
    for option_key, permission_key in ATTACHMENT_PERMISSION_MAP.items():
        option_value = attachment_summary["options"].get(option_key)
        if option_value and not ios_perms.get(permission_key, False):
            missing.append(permission_key)
    attachment_summary["required_permissions_missing"] = sorted(dict.fromkeys(missing))


def _collect_release_artifacts(ctx: AnalysisContext) -> Dict[str, Any]:
    ignored_dirs = {"DerivedData", ".git", "build", "Pods", "node_modules"}
    app_store_keys: List[str] = []
    play_service_accounts: List[str] = []
    team_configs: List[str] = []

    for path in ctx.root.rglob("*.p8"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if path.is_file():
            app_store_keys.append(relative_path(path, ctx.root))

    for pattern in ("*service*.json", "*play*.json", "*google*.json"):
        for path in ctx.root.rglob(pattern):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.is_file():
                play_service_accounts.append(relative_path(path, ctx.root))

    for pattern in ("*team*.yml", "*team*.yaml", "*team*.json"):
        for path in ctx.root.rglob(pattern):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.is_file() and "luciq" in path.name.lower():
                team_configs.append(relative_path(path, ctx.root))

    return {
        "app_store_keys_detected": sorted(dict.fromkeys(app_store_keys)),
        "play_service_accounts_detected": sorted(dict.fromkeys(play_service_accounts)),
        "team_config_files": sorted(dict.fromkeys(team_configs)),
    }


def _extract_masking_terms(context_block: str) -> Tuple[Set[str], Set[str]]:
    headers_found: Set[str] = set()
    body_found: Set[str] = set()
    lower_block = context_block.lower()
    for header in NETWORK_SENSITIVE_HEADERS:
        if header.lower() in lower_block:
            headers_found.add(header)
    for field in NETWORK_SENSITIVE_BODY_FIELDS:
        if field.lower() in lower_block:
            body_found.add(field)
    return headers_found, body_found


def _extract_attachment_options(context_block: str) -> Dict[str, Optional[bool]]:
    options: Dict[str, Optional[bool]] = {
        "screenshot": None,
        "extra_screenshot": None,
        "gallery_image": None,
        "voice_note": None,
        "screen_recording": None,
    }
    for logical_name, labels in ATTACHMENT_LABELS.items():
        for label in labels:
            match = re.search(
                rf"{label}\s*:\s*(true|false)", context_block, flags=re.IGNORECASE
            )
            if match:
                options[logical_name] = match.group(1).lower() == "true"
                break
    call_match = re.search(
        r"setAttachmentTypesEnabled\s*\(\s*(true|false)", context_block, re.IGNORECASE
    )
    if call_match and options["screenshot"] is None:
        options["screenshot"] = call_match.group(1).lower() == "true"
    return options


def _extract_feature_flag_details(
    operation: str, context_block: str
) -> Tuple[Optional[str], Optional[str]]:
    name = None
    variant = None
    if operation in ("add_feature_flag", "add_feature_flags"):
        name_match = re.search(
            r"addFeatureFlags?\s*\(\s*\"([^\"]+)\"", context_block
        )
        if name_match:
            name = name_match.group(1)
        variant_match = re.search(r"variant\s*:\s*\"([^\"]+)\"", context_block)
        if variant_match:
            variant = variant_match.group(1)
    elif operation in ("remove_feature_flag", "remove_feature_flags"):
        name_match = re.search(
            r"removeFeatureFlags?\s*\(\s*\"([^\"]+)\"", context_block
        )
        if name_match:
            name = name_match.group(1)
    return name, variant


def _gather_context(
    lines: List[str], idx: int, before: int = 3, after: int = 20
) -> str:
    zero_based = idx - 1
    start = max(0, zero_based - before)
    end = min(len(lines), zero_based + after)
    return "\n".join(lines[start:end])


def _generate_uuid() -> str:
    # Local import to avoid uuid dependency at module import time.
    import uuid

    return str(uuid.uuid4())

