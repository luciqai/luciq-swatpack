from __future__ import annotations

import json
import plistlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .plan import CapturePlan
from .utils import redact_home, relative_path, run_command

INVOCATION_EVENT_PATTERN = re.compile(
    r"\.(shake|screenshot|floatingButton)"
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


def analyze_project(ctx: AnalysisContext) -> Dict[str, Any]:
    project_identity, build_systems, manual_hint = _collect_project_identity(ctx)
    luciq_sdk = _collect_luciq_sdk(ctx, build_systems, manual_hint)
    usage_data, module_states, privacy_settings, token_analysis = _scan_luciq_usage(
        ctx
    )
    symbolication = _detect_symbolication(ctx.root)
    symbol_pipeline = _collect_symbol_pipeline(ctx)
    ci_hints = (
        _detect_ci_hints(ctx) if ctx.include_ci_hints else None
    )
    environment = _collect_environment()
    privacy = _build_privacy_disclosure(ctx)
    extra_findings = _derive_extra_findings(
        luciq_sdk, usage_data, token_analysis, symbol_pipeline
    )

    run_metadata = {
        "tool_version": "0.1.0",
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
) -> Tuple[Dict[str, Any], Dict[str, Optional[bool]], Dict[str, Any], Dict[str, Any]]:
    init_locations: List[Dict[str, Any]] = []
    usage_locations: Dict[Tuple[str, str], Dict[str, Any]] = {}
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
    }

    privacy_settings = {
        "auto_masking_calls": [],
        "private_view_calls_found": False,
        "compose_private_modifiers_found": False,
        "network_masking_rules_found": False,
    }

    swift_files = ctx.plan.files_by_role.get("swift_sources", [])
    for path in swift_files:
        text = _safe_read_text(ctx, path)
        if text is None:
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            rel = relative_path(path, ctx.root)
            window = "\n".join(lines[idx - 1 : idx + 2])
            if "Luciq.start" in line:
                init_found = True
                init_locations.append(
                    {"file": rel, "line": idx, "snippet_type": "Luciq.start"}
                )
                usage_locations.setdefault(
                    (rel, "Luciq.start"),
                    {"file": rel, "line": idx, "snippet_type": "Luciq.start"},
                )
                invocation_events.update(
                    INVOCATION_EVENT_PATTERN.findall(window)
                )
                token = _extract_token_from_window(window)
                if token:
                    masked = _mask_token(token)
                    tokens_detected.append(
                        {"file": rel, "line": idx, "value_masked": masked}
                    )
                    token_values.add(token)
                    if _looks_like_placeholder_token(token):
                        placeholder_token_detected = True
            if "Luciq.setAutoMaskScreenshots" in line:
                screenshot_masking_found = True
                usage_locations.setdefault(
                    (rel, "Luciq.setAutoMaskScreenshots"),
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.setAutoMaskScreenshots",
                    },
                )
            if "Luciq.setReproStepsFor" in line:
                repro_steps_found = True
                usage_locations.setdefault(
                    (rel, "Luciq.setReproStepsFor"),
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.setReproStepsFor",
                    },
                )
            if "Luciq.identifyUser" in line:
                identify_hooks_found = True
                usage_locations.setdefault(
                    (rel, "Luciq.identifyUser"),
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.identifyUser",
                    },
                )
            if "Luciq.logOut" in line:
                logout_hooks_found = True
                usage_locations.setdefault(
                    (rel, "Luciq.logOut"),
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "Luciq.logOut",
                    },
                )
            if "NetworkLogger" in line:
                network_logging_found = True
                usage_locations.setdefault(
                    (rel, "NetworkLogger"),
                    {
                        "file": rel,
                        "line": idx,
                        "snippet_type": "NetworkLogger",
                    },
                )
            if "NetworkLogger.setRequestObfuscationHandler" in line:
                network_masking_found = True
                privacy_settings["network_masking_rules_found"] = True
            if "BugReporting.setState" in line:
                module_states["bug_reporting_enabled"] = _bool_from_line(line)
            if "CrashReporting.setState" in line:
                module_states["crash_reporting_enabled"] = _bool_from_line(line)
            if "CrashReporting.setAnrState" in line:
                module_states["anr_monitor_enabled"] = _bool_from_line(line)
            if "SessionReplay.setEnabled" in line:
                module_states["session_replay_enabled"] = _bool_from_line(line)
            if "SessionReplay.setNetworkLogsEnabled" in line:
                module_states["network_logs_enabled"] = _bool_from_line(line)
            if "SessionReplay.setUserStepsEnabled" in line:
                module_states["user_steps_enabled"] = _bool_from_line(line)
            if "Luciq.disable" in line:
                module_states["sdk_globally_disabled"] = True
            if "Luciq.enable" in line and module_states["sdk_globally_disabled"] is None:
                module_states["sdk_globally_disabled"] = False
            if "Luciq.setDebugEnabled" in line:
                module_states["debug_logs_enabled"] = _bool_from_line(line)
            if "Luciq.setAPMEnabled" in line:
                module_states["apm_enabled"] = _bool_from_line(line)
            if "Luciq.setAutoMaskingLevel" in line:
                privacy_settings["auto_masking_calls"].append("setAutoMaskingLevel")
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

    usage_locations_list = sorted(
        usage_locations.values(),
        key=lambda entry: (entry["file"], entry["line"]),
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
    }
    token_info = {
        "tokens_detected": tokens_detected,
        "multiple_tokens_detected": len(token_values) > 1,
        "placeholder_token_detected": placeholder_token_detected,
    }
    return usage, module_states, privacy_settings, token_info


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


TOKEN_REGEX = re.compile(r'withToken:\s*"([^"]+)"')


def _extract_token_from_window(window: str) -> Optional[str]:
    match = TOKEN_REGEX.search(window)
    if match:
        return match.group(1).strip()
    return None


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


def _generate_uuid() -> str:
    # Local import to avoid uuid dependency at module import time.
    import uuid

    return str(uuid.uuid4())

