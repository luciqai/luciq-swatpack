"""
Luciq SWAT Pack - Project Analysis Module

This module orchestrates the extraction of Luciq SDK integration data
from iOS (and eventually Android) projects.
"""
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

# Import all constants from the dedicated module
from .constants import (
    INVOCATION_EVENT_PATTERN,
    FEATURE_API_PATTERNS,
    MODULE_DEFAULT_TRUE,
    MODULE_DEFAULT_FALSE,
    NETWORK_SENSITIVE_HEADERS,
    NETWORK_SENSITIVE_BODY_FIELDS,
    IOS_USAGE_DESCRIPTION_KEYS,
    ANDROID_PERMISSION_KEYS,
    ATTACHMENT_PERMISSION_MAP,
    ATTACHMENT_LABELS,
    PROGRAMMATIC_INVOCATION_PATTERNS,
    CUSTOM_LOG_PATTERNS,
    CUSTOM_DATA_PATTERNS,
    MODULE_TOGGLE_PATTERNS,
    PRIVATE_VIEW_PATTERNS,
    DSYM_SCRIPT_KEYWORDS,
    SHELL_SCRIPT_KEYWORDS,
    ENDPOINT_PATTERN,
    TOKEN_ENV_PATTERN,
    APP_TOKEN_PATTERN,
    TOKEN_LITERAL_PATTERN,
    TOKEN_IDENTIFIER_PATTERN,
    TOKEN_DECL_PATTERN,
    # Android-specific patterns
    ANDROID_INIT_PATTERNS,
    ANDROID_MODULE_TOGGLE_PATTERNS,
    ANDROID_INVOCATION_EVENTS,
    ANDROID_NETWORK_PATTERNS,
    ANDROID_APM_EXTENDED_PATTERNS,
    ANDROID_BUG_REPORTING_PATTERNS,
    ANDROID_SESSION_REPLAY_PATTERNS,
    ANDROID_CRASH_REPORTING_PATTERNS,
    ANDROID_MASKING_PATTERNS,
    # APM patterns
    APM_FLOW_PATTERNS,
    APM_TRACE_PATTERNS,
    APM_LIFECYCLE_PATTERNS,
    # Non-fatal crash reporting
    NON_FATAL_PATTERNS,
    # Network obfuscation
    NETWORK_OBFUSCATION_PATTERNS,
    # User consent
    USER_CONSENT_PATTERNS,
    # SDK state control
    SDK_STATE_PATTERNS,
    # Welcome message
    WELCOME_MESSAGE_PATTERNS,
    # Screenshot capture
    SCREENSHOT_PATTERNS,
    # WebView tracking
    WEBVIEW_PATTERNS,
    WEBVIEW_MASKING_PATTERNS,
    # React Native-specific patterns
    REACT_NATIVE_INIT_PATTERNS,
    REACT_NATIVE_APM_PATTERNS,
    REACT_NATIVE_BUG_REPORTING_PATTERNS,
    REACT_NATIVE_CRASH_REPORTING_PATTERNS,
    REACT_NATIVE_SESSION_REPLAY_PATTERNS,
    REACT_NATIVE_NETWORK_PATTERNS,
    REACT_NATIVE_SURVEYS_PATTERNS,
    REACT_NATIVE_REPLIES_PATTERNS,
    REACT_NATIVE_FEATURE_REQUESTS_PATTERNS,
    REACT_NATIVE_MODULE_TOGGLE_PATTERNS,
    # Flutter-specific patterns
    FLUTTER_INIT_PATTERNS,
    FLUTTER_APM_PATTERNS,
    FLUTTER_BUG_REPORTING_PATTERNS,
    FLUTTER_CRASH_REPORTING_PATTERNS,
    FLUTTER_SESSION_REPLAY_PATTERNS,
    FLUTTER_SURVEYS_PATTERNS,
    FLUTTER_REPLIES_PATTERNS,
    FLUTTER_FEATURE_REQUESTS_PATTERNS,
    FLUTTER_FEATURE_FLAG_PATTERNS,
    FLUTTER_MODULE_TOGGLE_PATTERNS,
)


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


def _detect_platform(ctx: AnalysisContext) -> str:
    """Detect the primary platform of the project."""
    has_ios = bool(
        ctx.plan.files_by_role.get("xcodeproj")
        or ctx.plan.files_by_role.get("swift_sources")
    )
    has_android = bool(
        ctx.plan.files_by_role.get("gradle_files")
        or ctx.plan.files_by_role.get("kotlin_sources")
        or ctx.plan.files_by_role.get("java_sources")
        or ctx.plan.files_by_role.get("android_manifests")
    )
    has_rn = _detect_react_native_dependency(ctx)
    has_flutter = _detect_flutter_dependency(ctx)

    # Priority: cross-platform > native
    if has_rn:
        return "react_native"
    if has_flutter:
        return "flutter"
    if has_ios and has_android:
        return "cross_platform"
    if has_android:
        return "android"
    if has_ios:
        return "ios"
    return "unknown"


def analyze_project(ctx: AnalysisContext) -> Dict[str, Any]:
    platform = _detect_platform(ctx)
    project_identity, build_systems, manual_hint = _collect_project_identity(ctx, platform)
    luciq_sdk = _collect_luciq_sdk(ctx, build_systems, manual_hint, platform)

    # Scan based on detected platform
    if platform == "react_native":
        (
            usage_data,
            module_states,
            privacy_settings,
            token_analysis,
            scan_meta,
        ) = _scan_react_native_usage(ctx)
    elif platform == "flutter":
        (
            usage_data,
            module_states,
            privacy_settings,
            token_analysis,
            scan_meta,
        ) = _scan_flutter_usage(ctx)
    elif platform == "android":
        (
            usage_data,
            module_states,
            privacy_settings,
            token_analysis,
            scan_meta,
        ) = _scan_android_usage(ctx)
    else:
        # iOS, cross-platform, or unknown - use iOS scanner (existing)
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
        "platform_detected": platform,
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
    platform: str = "ios",
) -> Tuple[Dict[str, Any], List[str], bool]:
    app_name = "unknown"
    bundle_id = "unknown"
    manual_embed_hint = False
    build_systems = []

    # iOS project identity
    if platform in ("ios", "cross_platform", "react_native", "flutter"):
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

    # iOS build systems
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

    # Android project identity
    android_app_id = "unknown"
    android_min_sdk: Set[str] = set()
    android_target_sdk: Set[str] = set()
    gradle_paths: List[str] = []

    if platform in ("android", "cross_platform", "react_native", "flutter"):
        # Extract Android app identity from Gradle files
        _load_gradle_texts(ctx)
        app_id_pattern = re.compile(r'(?:applicationId|namespace)\s*[=:]\s*["\']([^"\']+)["\']')
        min_sdk_pattern = re.compile(r'minSdk(?:Version)?\s*[=:]\s*(\d+)')
        target_sdk_pattern = re.compile(r'targetSdk(?:Version)?\s*[=:]\s*(\d+)')

        for path, text in ctx.gradle_text_cache.items():
            gradle_paths.append(relative_path(path, ctx.root))
            for match in app_id_pattern.findall(text):
                if android_app_id == "unknown":
                    android_app_id = match
            android_min_sdk.update(min_sdk_pattern.findall(text))
            android_target_sdk.update(target_sdk_pattern.findall(text))

        # Use Android app_id as bundle_id if iOS not found
        if bundle_id == "unknown" and android_app_id != "unknown":
            bundle_id = android_app_id

        # Gradle is the build system for Android
        if ctx.plan.files_by_role.get("gradle_files"):
            build_systems.append("gradle")

    identity = {
        "app_name": app_name,
        "bundle_id": bundle_id,
        "xcodeproj_paths": xcodeproj_paths,
        "workspace_paths": workspace_paths,
        "build_systems_detected": sorted(dict.fromkeys(build_systems)),
        "deployment_targets_detected": sorted(deployment_targets),
        "swift_versions_detected": sorted(swift_versions),
        # Android-specific fields
        "android_app_id": android_app_id if platform in ("android", "cross_platform") else None,
        "android_min_sdk_detected": sorted(android_min_sdk) if android_min_sdk else [],
        "android_target_sdk_detected": sorted(android_target_sdk) if android_target_sdk else [],
        "gradle_paths": sorted(dict.fromkeys(gradle_paths)) if gradle_paths else [],
    }
    return identity, identity["build_systems_detected"], manual_embed_hint


def _collect_luciq_sdk(
    ctx: AnalysisContext, build_systems: List[str], manual_hint: bool, platform: str = "ios"
) -> Dict[str, Any]:
    versions: Set[str] = set()
    sources: Set[str] = set()
    luciq_installed = False

    # iOS: Manual embed detection
    if platform in ("ios", "cross_platform", "react_native", "flutter"):
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

        # iOS: SPM
        spm_versions = _parse_package_resolved(ctx)
        if spm_versions:
            versions.update(spm_versions)
            sources.add("Package.resolved")
            luciq_installed = True

        # iOS: CocoaPods
        pod_versions = _parse_podfile_lock(ctx)
        if pod_versions:
            versions.update(pod_versions)
            sources.add("Podfile.lock")
            luciq_installed = True

        # iOS: Carthage
        carthage_versions = _parse_carthage_resolved(ctx)
        if carthage_versions:
            versions.update(carthage_versions)
            sources.add("Cartfile.resolved")
            luciq_installed = True
    else:
        manual_detected = False

    # Android: Gradle dependencies
    if platform in ("android", "cross_platform", "react_native", "flutter"):
        gradle_versions = _parse_gradle_dependencies(ctx)
        if gradle_versions:
            versions.update(gradle_versions)
            sources.add("build.gradle")
            luciq_installed = True

    integration_method = "unknown"
    if luciq_installed:
        if manual_detected and len(build_systems) == 0:
            integration_method = "manual"
        elif len(build_systems) == 1:
            integration_method = build_systems[0]
        elif "gradle" in build_systems and platform == "android":
            integration_method = "gradle"

    return {
        "luciq_installed": luciq_installed,
        "integration_method": integration_method,
        "sdk_versions_detected": sorted(v for v in versions if v),
        "sdk_sources": sorted(sources),
    }


def _parse_gradle_dependencies(ctx: AnalysisContext) -> Set[str]:
    """Parse Gradle files for Luciq SDK versions."""
    versions: Set[str] = set()
    _load_gradle_texts(ctx)

    # Match patterns like: implementation("com.luciq.library:luciq:14.2.0")
    # Or: implementation 'com.luciq.library:luciq:14.2.0'
    # Or legacy: com.instabug.library:instabug:14.2.0
    version_pattern = re.compile(
        r'(?:com\.luciq|com\.instabug)[^:]*:[^:]+:([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
    )

    for text in ctx.gradle_text_cache.values():
        for match in version_pattern.findall(text):
            versions.add(match)

    return versions


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
        "force_restart_enabled": None,           # CrashReporting.forceRestartEnabled
        "network_auto_masking_enabled": None,    # NetworkLogger.autoMaskingEnabled (SDK 14.2+)
        "ndk_crashes_enabled": None,             # Android-specific: CrashReporting.setNDKCrashesState
        "luciq_logs_enabled": None,              # Android-specific: SessionReplay.setLuciqLogsEnabled
    }

    privacy_settings = {
        "auto_masking_calls": [],
        "private_view_calls_found": False,
        "compose_private_modifiers_found": False,
        "network_masking_rules_found": False,
    }

    # New iOS feature tracking
    apm_usage: List[Dict[str, Any]] = []
    non_fatal_calls: List[Dict[str, Any]] = []
    user_consent_calls: List[Dict[str, Any]] = []
    welcome_message_calls: List[Dict[str, Any]] = []
    webview_tracking_calls: List[Dict[str, Any]] = []
    webview_masking_found = False

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
            # Private view detection - patterns imported from constants.py
            if any(pattern in line for pattern in PRIVATE_VIEW_PATTERNS):
                privacy_settings["private_view_calls_found"] = True
            if ".luciqPrivate" in line:
                privacy_settings["compose_private_modifiers_found"] = True

            # APM Flow/Trace/Lifecycle patterns
            for apm_pattern in APM_FLOW_PATTERNS + APM_TRACE_PATTERNS + APM_LIFECYCLE_PATTERNS:
                if apm_pattern in line:
                    apm_usage.append({
                        "file": rel,
                        "line": idx,
                        "call": apm_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "APM",
                        "code_snippet": snippet,
                    })
                    break

            # Non-fatal crash reporting patterns
            for nf_pattern in NON_FATAL_PATTERNS:
                if nf_pattern in line:
                    non_fatal_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": nf_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "NonFatalCrash",
                        "code_snippet": snippet,
                    })
                    break

            # Network obfuscation patterns (enhanced detection)
            for obf_pattern in NETWORK_OBFUSCATION_PATTERNS:
                if obf_pattern in line:
                    network_masking_found = True
                    privacy_settings["network_masking_rules_found"] = True
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": obf_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    # Extract masking terms from context
                    if "ObfuscationHandler" in obf_pattern:
                        context_block = _gather_context(lines, idx, after=25)
                        headers_found, body_found = _extract_masking_terms(context_block)
                        network_mask_headers.update(headers_found)
                        network_mask_body.update(body_found)
                    break

            # User consent patterns
            for consent_pattern in USER_CONSENT_PATTERNS:
                if consent_pattern in line:
                    user_consent_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": consent_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "UserConsent",
                        "code_snippet": snippet,
                    })
                    break

            # Welcome message patterns
            for welcome_pattern in WELCOME_MESSAGE_PATTERNS:
                if welcome_pattern in line:
                    welcome_message_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": welcome_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "WelcomeMessage",
                        "code_snippet": snippet,
                    })
                    break

            # WebView tracking patterns
            for webview_pattern in WEBVIEW_PATTERNS:
                if webview_pattern in line:
                    webview_tracking_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": webview_pattern,
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "WebViewTracking",
                        "code_snippet": snippet,
                    })
                    break

            # WebView masking in auto-mask options
            for webview_mask_pattern in WEBVIEW_MASKING_PATTERNS:
                if webview_mask_pattern in line:
                    webview_masking_found = True
                    break

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
        # New iOS feature data
        "apm_usage": apm_usage,
        "non_fatal_calls": non_fatal_calls,
        "user_consent_calls": user_consent_calls,
        "welcome_message_calls": welcome_message_calls,
        "webview_tracking_calls": webview_tracking_calls,
        "webview_masking_found": webview_masking_found,
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


def _scan_android_usage(
    ctx: AnalysisContext,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Optional[bool]],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    """Scan Kotlin and Java files for Luciq SDK usage (Android)."""
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
        "force_restart_enabled": None,
        "network_auto_masking_enabled": None,
        "ndk_crashes_enabled": None,  # Android-specific
        "luciq_logs_enabled": None,   # Android-specific
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

    # New Android feature tracking (matching iOS)
    apm_usage: List[Dict[str, Any]] = []
    non_fatal_calls: List[Dict[str, Any]] = []
    user_consent_calls: List[Dict[str, Any]] = []
    welcome_message_calls: List[Dict[str, Any]] = []
    webview_tracking_calls: List[Dict[str, Any]] = []
    webview_masking_found = False

    # Android token extraction pattern
    android_token_pattern = re.compile(
        r'Luciq\.Builder\s*\([^,]+,\s*["\']([^"\']+)["\']'
    )
    # Gradle token pattern
    gradle_token_pattern = re.compile(
        r'appToken\s*=\s*["\']([^"\']+)["\']'
    )

    # Scan Kotlin and Java source files
    kotlin_files = ctx.plan.files_by_role.get("kotlin_sources", [])
    java_files = ctx.plan.files_by_role.get("java_sources", [])
    source_files = kotlin_files + java_files

    for path in source_files:
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        lines = text.splitlines()
        func_pattern = re.compile(r"^\s*(?:private\s+|public\s+|internal\s+|protected\s+)?fun\s+([A-Za-z0-9_]+)")
        current_function = None

        for idx, line in enumerate(lines, start=1):
            rel = relative_path(path, ctx.root)
            window = "\n".join(lines[idx - 1 : idx + 2])
            snippet = _format_snippet(window)

            # Track current function for logout detection
            func_match = func_pattern.match(line.strip())
            if func_match:
                current_function = func_match.group(1).lower()

            # Detect SDK initialization: Luciq.Builder(context, "token")
            for init_pattern in ANDROID_INIT_PATTERNS:
                if init_pattern in line:
                    if "Luciq.Builder(" in line:
                        init_found = True
                        init_locations.append({
                            "file": rel,
                            "line": idx,
                            "snippet_type": "Luciq.Builder",
                            "code_snippet": snippet,
                        })
                        usage_locations.append({
                            "file": rel,
                            "line": idx,
                            "snippet_type": "Luciq.Builder",
                            "code_snippet": snippet,
                        })
                        # Extract token from Builder call
                        token_match = android_token_pattern.search(window)
                        if token_match:
                            token = token_match.group(1)
                            masked = _mask_token(token)
                            tokens_detected.append({
                                "file": rel,
                                "line": idx,
                                "value_masked": masked,
                            })
                            token_values.add(token)
                            if _looks_like_placeholder_token(token):
                                placeholder_token_detected = True
                    break

            # Detect invocation events
            for event in ANDROID_INVOCATION_EVENTS:
                if event in line:
                    # Extract just the event name (e.g., "SHAKE" from "LuciqInvocationEvent.SHAKE")
                    event_name = event.split(".")[-1].lower()
                    invocation_events.add(event_name)

            # Detect module toggles using Android patterns
            for module_key, patterns in ANDROID_MODULE_TOGGLE_PATTERNS.items():
                if any(pattern in line for pattern in patterns):
                    inferred = _bool_from_android_line(line)
                    if inferred is not None:
                        module_states[module_key] = inferred

            # Detect feature flag API calls (shared patterns work for Android too)
            for needle, label in FEATURE_API_PATTERNS.items():
                if needle in line:
                    context_block = _gather_context(lines, idx)
                    flag_name, variant = _extract_android_feature_flag_details(label, context_block)
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

            # Detect programmatic invocations
            for invocation_pattern in PROGRAMMATIC_INVOCATION_PATTERNS:
                if invocation_pattern in line:
                    programmatic_invocations.append({
                        "file": rel,
                        "line": idx,
                        "call": invocation_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect custom logging
            for log_pattern in CUSTOM_LOG_PATTERNS:
                if log_pattern in line:
                    custom_log_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": log_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect custom data
            for data_pattern in CUSTOM_DATA_PATTERNS:
                if data_pattern in line:
                    custom_data_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": data_pattern,
                        "code_snippet": snippet,
                    })
                    break

            # Detect user identification
            if "Luciq.identifyUser" in line or "Luciq.setUserData" in line:
                identify_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.identifyUser",
                    "code_snippet": snippet,
                })

            # Detect logout
            if "Luciq.logOut" in line:
                logout_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.logOut",
                    "code_snippet": snippet,
                })

            # Detect network logging
            for net_pattern in ANDROID_NETWORK_PATTERNS:
                if net_pattern in line:
                    network_logging_found = True
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": net_pattern,
                        "code_snippet": snippet,
                    })
                    break

            # Detect private view patterns
            if any(pattern in line for pattern in PRIVATE_VIEW_PATTERNS):
                privacy_settings["private_view_calls_found"] = True
            if ".luciqPrivate" in line:
                privacy_settings["compose_private_modifiers_found"] = True

            # APM Flow/Trace/Lifecycle patterns (Android)
            for apm_pattern in APM_FLOW_PATTERNS + APM_TRACE_PATTERNS + APM_LIFECYCLE_PATTERNS:
                if apm_pattern in line:
                    apm_usage.append({
                        "file": rel,
                        "line": idx,
                        "call": apm_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "APM",
                        "code_snippet": snippet,
                    })
                    break

            # Android APM extended patterns
            for apm_ext_pattern in ANDROID_APM_EXTENDED_PATTERNS:
                if apm_ext_pattern in line:
                    apm_usage.append({
                        "file": rel,
                        "line": idx,
                        "call": apm_ext_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "APM",
                        "code_snippet": snippet,
                    })
                    break

            # Non-fatal crash reporting patterns (Android)
            for nf_pattern in NON_FATAL_PATTERNS + ANDROID_CRASH_REPORTING_PATTERNS:
                if nf_pattern in line:
                    # Avoid duplicate callback detection
                    if "Callback" in nf_pattern:
                        continue
                    non_fatal_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": nf_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "NonFatalCrash",
                        "code_snippet": snippet,
                    })
                    break

            # User consent patterns (Android)
            for consent_pattern in USER_CONSENT_PATTERNS:
                if consent_pattern in line:
                    user_consent_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": consent_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "UserConsent",
                        "code_snippet": snippet,
                    })
                    break

            # Welcome message patterns (Android)
            for welcome_pattern in WELCOME_MESSAGE_PATTERNS:
                if welcome_pattern in line:
                    welcome_message_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": welcome_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "WelcomeMessage",
                        "code_snippet": snippet,
                    })
                    break

            # WebView tracking patterns (Android)
            if "APM.setWebViewsTrackingEnabled(" in line:
                webview_tracking_calls.append({
                    "file": rel,
                    "line": idx,
                    "call": "APM.setWebViewsTrackingEnabled",
                    "code_snippet": snippet,
                })
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "WebViewTracking",
                    "code_snippet": snippet,
                })

            # Screenshot/masking patterns (Android)
            for mask_pattern in ANDROID_MASKING_PATTERNS:
                if mask_pattern in line:
                    screenshot_masking_found = True
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": mask_pattern,
                        "code_snippet": snippet,
                    })
                    break

            # Network auto-masking (Android)
            if "Luciq.setNetworkAutoMaskingState(" in line:
                network_masking_found = True
                privacy_settings["network_masking_rules_found"] = True

            # Session Replay patterns (Android)
            for sr_pattern in ANDROID_SESSION_REPLAY_PATTERNS:
                if sr_pattern in line:
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": sr_pattern.rstrip(":("),
                        "code_snippet": snippet,
                    })
                    # Detect network logs in session replay
                    if "setNetworkLogsEnabled" in sr_pattern:
                        network_logging_found = True
                    break

    # Also extract tokens from Gradle files
    for path, text in ctx.gradle_text_cache.items():
        for match in gradle_token_pattern.finditer(text):
            token = match.group(1)
            masked = _mask_token(token)
            rel = relative_path(path, ctx.root)
            tokens_detected.append({
                "file": rel,
                "line": 0,  # Line unknown from gradle
                "value_masked": masked,
            })
            token_values.add(token)
            if _looks_like_placeholder_token(token):
                placeholder_token_detected = True

    # Check for NDK dependency in Gradle
    if _gradle_has_ndk_dependency(ctx):
        module_states["ndk_module_present"] = True

    # Apply defaults if init was found
    if init_found:
        for key in MODULE_DEFAULT_TRUE:
            if module_states.get(key) is None:
                module_states[key] = True
        for key in MODULE_DEFAULT_FALSE:
            if module_states.get(key) is None:
                module_states[key] = False

    # Build privacy settings
    privacy_settings["masked_header_terms"] = sorted(dict.fromkeys(network_mask_headers))
    privacy_settings["masked_body_terms"] = sorted(dict.fromkeys(network_mask_body))
    privacy_settings["missing_header_terms"] = [
        header for header in NETWORK_SENSITIVE_HEADERS
        if header not in network_mask_headers
    ]
    privacy_settings["missing_body_terms"] = [
        field for field in NETWORK_SENSITIVE_BODY_FIELDS
        if field not in network_mask_body
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
        # Android feature data (matching iOS for schema consistency)
        "apm_usage": apm_usage,
        "non_fatal_calls": non_fatal_calls,
        "user_consent_calls": user_consent_calls,
        "welcome_message_calls": welcome_message_calls,
        "webview_tracking_calls": webview_tracking_calls,
        "webview_masking_found": webview_masking_found,
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


def _bool_from_android_line(line: str) -> Optional[bool]:
    """Extract boolean value from Android SDK patterns.

    Android SDK uses Feature.State.ENABLED/DISABLED or true/false.
    """
    lower = line.lower()
    if "disabled" in lower or "false" in lower:
        return False
    if "enabled" in lower or "true" in lower:
        return True
    return None


def _extract_android_feature_flag_details(
    operation: str, context_block: str
) -> Tuple[Optional[str], Optional[str]]:
    """Extract feature flag name and variant from Android code."""
    name = None
    variant = None
    if operation in ("add_feature_flag", "add_feature_flags"):
        # Kotlin/Java: Luciq.addFeatureFlag("FlagName", "variant")
        name_match = re.search(
            r'addFeatureFlag[s]?\s*\(\s*["\']([^"\']+)["\']', context_block
        )
        if name_match:
            name = name_match.group(1)
        variant_match = re.search(
            r'addFeatureFlag[s]?\s*\([^,]+,\s*["\']([^"\']+)["\']', context_block
        )
        if variant_match:
            variant = variant_match.group(1)
    elif operation in ("remove_feature_flag", "remove_feature_flags"):
        name_match = re.search(
            r'removeFeatureFlag[s]?\s*\(\s*["\']([^"\']+)["\']', context_block
        )
        if name_match:
            name = name_match.group(1)
    return name, variant


def _scan_react_native_usage(
    ctx: AnalysisContext,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Optional[bool]],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    """Scan JavaScript/TypeScript files for Luciq SDK usage (React Native)."""
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
        "react_native_integration_detected": True,  # Obviously true for RN
        "flutter_integration_detected": None,
        "surveys_enabled": None,
        "feature_requests_enabled": None,
        "in_app_replies_enabled": None,
        "in_app_chat_enabled": None,
        "oom_monitor_enabled": None,
        "force_restart_enabled": None,
        "network_auto_masking_enabled": None,
        "ndk_crashes_enabled": None,
        "luciq_logs_enabled": None,
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
    attachment_options: Optional[Dict[str, Optional[bool]]] = None
    clear_feature_flags_on_logout = False

    # Feature tracking
    apm_usage: List[Dict[str, Any]] = []
    non_fatal_calls: List[Dict[str, Any]] = []
    user_consent_calls: List[Dict[str, Any]] = []
    welcome_message_calls: List[Dict[str, Any]] = []
    webview_tracking_calls: List[Dict[str, Any]] = []
    webview_masking_found = False

    # Token extraction patterns for JS/TS
    rn_token_pattern = re.compile(
        r'(?:token|appToken)\s*:\s*["\']([^"\']+)["\']'
    )

    js_files = ctx.plan.files_by_role.get("js_sources", [])

    for path in js_files:
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        lines = text.splitlines()
        func_pattern = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z0-9_]+)")
        arrow_func_pattern = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=")
        current_function = None

        for idx, line in enumerate(lines, start=1):
            rel = relative_path(path, ctx.root)
            window = "\n".join(lines[idx - 1 : idx + 2])
            snippet = _format_snippet(window)

            # Track current function
            func_match = func_pattern.match(line.strip())
            if func_match:
                current_function = func_match.group(1).lower()
            arrow_match = arrow_func_pattern.match(line.strip())
            if arrow_match:
                current_function = arrow_match.group(1).lower()

            # Detect SDK initialization: Luciq.init({ token: 'APP_TOKEN', ... })
            if "Luciq.init(" in line or "Instabug.init(" in line:
                init_found = True
                init_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.init",
                    "code_snippet": snippet,
                })
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.init",
                    "code_snippet": snippet,
                })
                # Extract token
                token_match = rn_token_pattern.search(window)
                if token_match:
                    token = token_match.group(1)
                    masked = _mask_token(token)
                    tokens_detected.append({
                        "file": rel,
                        "line": idx,
                        "value_masked": masked,
                    })
                    token_values.add(token)
                    if _looks_like_placeholder_token(token):
                        placeholder_token_detected = True

            # Detect invocation events
            for event_pattern in REACT_NATIVE_INIT_PATTERNS:
                if "InvocationEvent." in event_pattern and event_pattern in line:
                    event_name = event_pattern.split(".")[-1].lower()
                    invocation_events.add(event_name)

            # Detect module toggles
            for module_key, patterns in REACT_NATIVE_MODULE_TOGGLE_PATTERNS.items():
                if any(pattern in line for pattern in patterns):
                    inferred = _bool_from_js_line(line)
                    if inferred is not None:
                        module_states[module_key] = inferred

            # Detect APM usage
            for apm_pattern in REACT_NATIVE_APM_PATTERNS:
                if apm_pattern in line:
                    apm_usage.append({
                        "file": rel,
                        "line": idx,
                        "call": apm_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "APM",
                        "code_snippet": snippet,
                    })
                    break

            # Detect Bug Reporting patterns
            for br_pattern in REACT_NATIVE_BUG_REPORTING_PATTERNS:
                if br_pattern in line:
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": br_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    if "setEnabledAttachmentTypes" in br_pattern:
                        context_block = _gather_context(lines, idx, after=10)
                        attachment_options = _extract_js_attachment_options(context_block)
                    if "show(" in br_pattern:
                        programmatic_invocations.append({
                            "file": rel,
                            "line": idx,
                            "call": br_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    if "addUserConsent" in br_pattern:
                        user_consent_calls.append({
                            "file": rel,
                            "line": idx,
                            "call": br_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    break

            # Detect Crash Reporting patterns
            for cr_pattern in REACT_NATIVE_CRASH_REPORTING_PATTERNS:
                if cr_pattern in line:
                    if "report" in cr_pattern.lower():
                        non_fatal_calls.append({
                            "file": rel,
                            "line": idx,
                            "call": cr_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": cr_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect Session Replay patterns
            for sr_pattern in REACT_NATIVE_SESSION_REPLAY_PATTERNS:
                if sr_pattern in line:
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": sr_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    if "maskViewComponentsWithTag" in sr_pattern:
                        screenshot_masking_found = True
                    break

            # Detect Network Logger patterns
            for nl_pattern in REACT_NATIVE_NETWORK_PATTERNS:
                if nl_pattern in line:
                    network_logging_found = True
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": nl_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    if "ObfuscationHandler" in nl_pattern:
                        network_masking_found = True
                        privacy_settings["network_masking_rules_found"] = True
                    break

            # Detect user identification
            if "Luciq.identifyUser(" in line or "Luciq.setUserData(" in line:
                identify_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.identifyUser",
                    "code_snippet": snippet,
                })

            # Detect logout
            if "Luciq.logOut(" in line:
                logout_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.logOut",
                    "code_snippet": snippet,
                })

            # Detect feature flag calls
            for needle, label in FEATURE_API_PATTERNS.items():
                if needle in line:
                    context_block = _gather_context(lines, idx)
                    flag_name, variant = _extract_js_feature_flag_details(label, context_block)
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
                        if current_function and any(
                            token in current_function for token in ("logout", "signout")
                        ):
                            clear_feature_flags_on_logout = True
                    break

            # Detect custom logging
            for log_pattern in CUSTOM_LOG_PATTERNS:
                if log_pattern in line:
                    custom_log_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": log_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect custom data
            for data_pattern in CUSTOM_DATA_PATTERNS:
                if data_pattern in line:
                    custom_data_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": data_pattern,
                        "code_snippet": snippet,
                    })
                    break

    # Apply defaults if init was found
    if init_found:
        for key in MODULE_DEFAULT_TRUE:
            if module_states.get(key) is None:
                module_states[key] = True
        for key in MODULE_DEFAULT_FALSE:
            if module_states.get(key) is None:
                module_states[key] = False

    # Build privacy settings
    privacy_settings["masked_header_terms"] = []
    privacy_settings["masked_body_terms"] = []
    privacy_settings["missing_header_terms"] = list(NETWORK_SENSITIVE_HEADERS) if network_logging_found and not network_masking_found else []
    privacy_settings["missing_body_terms"] = list(NETWORK_SENSITIVE_BODY_FIELDS) if network_logging_found and not network_masking_found else []

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
        "apm_usage": apm_usage,
        "non_fatal_calls": non_fatal_calls,
        "user_consent_calls": user_consent_calls,
        "welcome_message_calls": welcome_message_calls,
        "webview_tracking_calls": webview_tracking_calls,
        "webview_masking_found": webview_masking_found,
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


def _scan_flutter_usage(
    ctx: AnalysisContext,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Optional[bool]],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    """Scan Dart files for Luciq SDK usage (Flutter)."""
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
        "flutter_integration_detected": True,  # Obviously true for Flutter
        "surveys_enabled": None,
        "feature_requests_enabled": None,
        "in_app_replies_enabled": None,
        "in_app_chat_enabled": None,
        "oom_monitor_enabled": None,
        "force_restart_enabled": None,
        "network_auto_masking_enabled": None,
        "ndk_crashes_enabled": None,
        "luciq_logs_enabled": None,
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
    attachment_options: Optional[Dict[str, Optional[bool]]] = None
    clear_feature_flags_on_logout = False

    # Feature tracking
    apm_usage: List[Dict[str, Any]] = []
    non_fatal_calls: List[Dict[str, Any]] = []
    user_consent_calls: List[Dict[str, Any]] = []
    welcome_message_calls: List[Dict[str, Any]] = []
    webview_tracking_calls: List[Dict[str, Any]] = []
    webview_masking_found = False

    # Token extraction patterns for Dart
    dart_token_pattern = re.compile(
        r"(?:token|appToken)\s*:\s*['\"]([^'\"]+)['\"]"
    )

    dart_files = ctx.plan.files_by_role.get("dart_sources", [])

    for path in dart_files:
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        lines = text.splitlines()
        func_pattern = re.compile(r"^\s*(?:Future|void|[A-Z]\w*)\s+([A-Za-z0-9_]+)\s*\(")
        current_function = None

        for idx, line in enumerate(lines, start=1):
            rel = relative_path(path, ctx.root)
            window = "\n".join(lines[idx - 1 : idx + 2])
            snippet = _format_snippet(window)

            # Track current function
            func_match = func_pattern.match(line.strip())
            if func_match:
                current_function = func_match.group(1).lower()

            # Detect SDK initialization: Luciq.init(token: 'APP_TOKEN', ...)
            if "Luciq.init(" in line or "Instabug.init(" in line:
                init_found = True
                init_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.init",
                    "code_snippet": snippet,
                })
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.init",
                    "code_snippet": snippet,
                })
                # Extract token
                token_match = dart_token_pattern.search(window)
                if token_match:
                    token = token_match.group(1)
                    masked = _mask_token(token)
                    tokens_detected.append({
                        "file": rel,
                        "line": idx,
                        "value_masked": masked,
                    })
                    token_values.add(token)
                    if _looks_like_placeholder_token(token):
                        placeholder_token_detected = True

            # Detect invocation events
            for event_pattern in FLUTTER_INIT_PATTERNS:
                if "InvocationEvent." in event_pattern and event_pattern in line:
                    event_name = event_pattern.split(".")[-1].lower()
                    invocation_events.add(event_name)

            # Detect module toggles
            for module_key, patterns in FLUTTER_MODULE_TOGGLE_PATTERNS.items():
                if any(pattern in line for pattern in patterns):
                    inferred = _bool_from_dart_line(line)
                    if inferred is not None:
                        module_states[module_key] = inferred

            # Detect APM usage
            for apm_pattern in FLUTTER_APM_PATTERNS:
                if apm_pattern in line:
                    apm_usage.append({
                        "file": rel,
                        "line": idx,
                        "call": apm_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": "APM",
                        "code_snippet": snippet,
                    })
                    break

            # Detect Bug Reporting patterns
            for br_pattern in FLUTTER_BUG_REPORTING_PATTERNS:
                if br_pattern in line:
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": br_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    if "setEnabledAttachmentTypes" in br_pattern:
                        context_block = _gather_context(lines, idx, after=10)
                        attachment_options = _extract_dart_attachment_options(context_block)
                    if "show(" in br_pattern:
                        programmatic_invocations.append({
                            "file": rel,
                            "line": idx,
                            "call": br_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    if "addUserConsents" in br_pattern:
                        user_consent_calls.append({
                            "file": rel,
                            "line": idx,
                            "call": br_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    break

            # Detect Crash Reporting patterns
            for cr_pattern in FLUTTER_CRASH_REPORTING_PATTERNS:
                if cr_pattern in line:
                    if "report" in cr_pattern.lower():
                        non_fatal_calls.append({
                            "file": rel,
                            "line": idx,
                            "call": cr_pattern.rstrip("("),
                            "code_snippet": snippet,
                        })
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": cr_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect Session Replay patterns
            for sr_pattern in FLUTTER_SESSION_REPLAY_PATTERNS:
                if sr_pattern in line:
                    usage_locations.append({
                        "file": rel,
                        "line": idx,
                        "snippet_type": sr_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    if "setNetworkLogsEnabled" in sr_pattern:
                        network_logging_found = True
                    break

            # Detect user identification
            if "Luciq.identifyUser(" in line or "Luciq.setUserData(" in line:
                identify_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.identifyUser",
                    "code_snippet": snippet,
                })

            # Detect logout
            if "Luciq.logOut(" in line:
                logout_hooks_found = True
                usage_locations.append({
                    "file": rel,
                    "line": idx,
                    "snippet_type": "Luciq.logOut",
                    "code_snippet": snippet,
                })

            # Detect feature flag calls (Flutter-specific patterns)
            for ff_pattern in FLUTTER_FEATURE_FLAG_PATTERNS:
                if ff_pattern in line:
                    context_block = _gather_context(lines, idx)
                    flag_name, variant = _extract_dart_feature_flag_details(ff_pattern, context_block)
                    label = "add_feature_flags" if "add" in ff_pattern.lower() else (
                        "remove_all_feature_flags" if "clear" in ff_pattern.lower() else "remove_feature_flags"
                    )
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
                        if current_function and any(
                            token in current_function for token in ("logout", "signout")
                        ):
                            clear_feature_flags_on_logout = True
                    break

            # Detect custom logging
            for log_pattern in CUSTOM_LOG_PATTERNS:
                if log_pattern in line:
                    custom_log_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": log_pattern.rstrip("("),
                        "code_snippet": snippet,
                    })
                    break

            # Detect custom data
            for data_pattern in CUSTOM_DATA_PATTERNS:
                if data_pattern in line:
                    custom_data_calls.append({
                        "file": rel,
                        "line": idx,
                        "call": data_pattern,
                        "code_snippet": snippet,
                    })
                    break

    # Check for NDK dependency in pubspec
    if _pubspec_has_ndk_dependency(ctx):
        module_states["ndk_module_present"] = True

    # Apply defaults if init was found
    if init_found:
        for key in MODULE_DEFAULT_TRUE:
            if module_states.get(key) is None:
                module_states[key] = True
        for key in MODULE_DEFAULT_FALSE:
            if module_states.get(key) is None:
                module_states[key] = False

    # Build privacy settings
    privacy_settings["masked_header_terms"] = []
    privacy_settings["masked_body_terms"] = []
    privacy_settings["missing_header_terms"] = list(NETWORK_SENSITIVE_HEADERS) if network_logging_found and not network_masking_found else []
    privacy_settings["missing_body_terms"] = list(NETWORK_SENSITIVE_BODY_FIELDS) if network_logging_found and not network_masking_found else []

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
        "apm_usage": apm_usage,
        "non_fatal_calls": non_fatal_calls,
        "user_consent_calls": user_consent_calls,
        "welcome_message_calls": welcome_message_calls,
        "webview_tracking_calls": webview_tracking_calls,
        "webview_masking_found": webview_masking_found,
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


def _bool_from_js_line(line: str) -> Optional[bool]:
    """Extract boolean value from JavaScript/TypeScript SDK patterns."""
    lower = line.lower()
    if "false" in lower:
        return False
    if "true" in lower:
        return True
    return None


def _bool_from_dart_line(line: str) -> Optional[bool]:
    """Extract boolean value from Dart SDK patterns."""
    lower = line.lower()
    if "false" in lower:
        return False
    if "true" in lower:
        return True
    return None


def _extract_js_feature_flag_details(
    operation: str, context_block: str
) -> Tuple[Optional[str], Optional[str]]:
    """Extract feature flag name and variant from JavaScript/TypeScript code."""
    name = None
    variant = None
    if operation in ("add_feature_flag", "add_feature_flags"):
        # JS: Luciq.addFeatureFlag('FlagName', 'variant')
        name_match = re.search(
            r"addFeatureFlags?\s*\(\s*['\"]([^'\"]+)['\"]", context_block
        )
        if name_match:
            name = name_match.group(1)
        variant_match = re.search(
            r"addFeatureFlags?\s*\([^,]+,\s*['\"]([^'\"]+)['\"]", context_block
        )
        if variant_match:
            variant = variant_match.group(1)
    elif operation in ("remove_feature_flag", "remove_feature_flags"):
        name_match = re.search(
            r"removeFeatureFlags?\s*\(\s*['\"]([^'\"]+)['\"]", context_block
        )
        if name_match:
            name = name_match.group(1)
    return name, variant


def _extract_dart_feature_flag_details(
    pattern: str, context_block: str
) -> Tuple[Optional[str], Optional[str]]:
    """Extract feature flag name and variant from Dart code."""
    name = None
    variant = None
    if "addFeatureFlags" in pattern:
        # Dart uses FeatureFlag objects: FeatureFlag('name', 'variant')
        name_match = re.search(
            r"FeatureFlag\s*\(\s*['\"]([^'\"]+)['\"]", context_block
        )
        if name_match:
            name = name_match.group(1)
        variant_match = re.search(
            r"FeatureFlag\s*\([^,]+,\s*['\"]([^'\"]+)['\"]", context_block
        )
        if variant_match:
            variant = variant_match.group(1)
    return name, variant


def _extract_js_attachment_options(context_block: str) -> Dict[str, Optional[bool]]:
    """Extract attachment options from JavaScript/TypeScript code."""
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
    return options


def _extract_dart_attachment_options(context_block: str) -> Dict[str, Optional[bool]]:
    """Extract attachment options from Dart code."""
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
    return options


def _pubspec_has_ndk_dependency(ctx: AnalysisContext) -> bool:
    """Check if pubspec.yaml has NDK dependency."""
    for path in ctx.plan.files_by_role.get("pubspec", []):
        text = _safe_read_text(ctx, path)
        if text and "luciq_flutter_ndk" in text:
            return True
    return False


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


# Note: ENDPOINT_PATTERN, TOKEN_ENV_PATTERN, APP_TOKEN_PATTERN are imported from constants.py


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


# Note: TOKEN_LITERAL_PATTERN, TOKEN_IDENTIFIER_PATTERN, TOKEN_DECL_PATTERN
# are imported from constants.py


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
        if "luciq-ndk" in text:
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
        # Look for dSYM upload script references in Xcode project
        if any(keyword in text for keyword in DSYM_SCRIPT_KEYWORDS):
            scripts.add(relative_path(path, ctx.root))
        endpoints.update(ENDPOINT_PATTERN.findall(text))
        tokens.update(_extract_app_tokens_from_text(text))
    for path in ctx.plan.files_by_role.get("shell_scripts", []):
        text = _safe_read_text(ctx, path)
        if not text:
            continue
        # Shell scripts for dSYM upload
        if any(keyword in text for keyword in SHELL_SCRIPT_KEYWORDS):
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

