from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List

from .utils import iter_files, iter_matching_files, relative_path

FIELDS_TO_CAPTURE = [
    "Run metadata (versions, timestamps, UUID run id)",
    "Project identity (app/bundle names, project/workspace paths)",
    "Build systems & dependency metadata (lockfiles + xcframework references)",
    "Luciq SDK presence, versions, and usage file+line numbers",
    "Symbolication + CI hints (paths only)",
    "Environment toolchain versions (macOS/Xcode/Swift/CocoaPods/Carthage)",
    "Privacy disclosure metadata (files read, fields captured/excluded)",
]

FIELDS_NOT_CAPTURED = [
    "Source code contents",
    "UI strings, screenshots, or assets",
    "Secrets/tokens/API keys",
    "Email addresses, user IDs, or other PII",
    "Network traffic or uploads of any kind",
]

POTENTIAL_EXTRA_FINDINGS = [
    "Luciq SDK referenced but Luciq.start not detected",
    "Network logging detected without screenshot masking",
    "Network logging detected without obfuscation handler",
    "Luciq.start detected but invocation events not inferred",
]


@dataclass
class CapturePlan:
    scan_root: Path
    files_by_role: Dict[str, List[Path]] = field(default_factory=dict)
    include_ci_hints: bool = False
    files_allowlist: List[str] = field(default_factory=list)

    def files_to_read(self) -> List[str]:
        files: List[str] = []
        for paths in self.files_by_role.values():
            for path in paths:
                files.append(relative_path(path, self.scan_root))
        return sorted(dict.fromkeys(files))

    def fields_to_capture(self) -> List[str]:
        return FIELDS_TO_CAPTURE.copy()

    def fields_not_captured(self) -> List[str]:
        return FIELDS_NOT_CAPTURED.copy()

    def potential_extra_findings(self) -> List[str]:
        return POTENTIAL_EXTRA_FINDINGS.copy()


def build_capture_plan(
    root: Path, include_ci_hints: bool, allowlist_patterns: List[str]
) -> CapturePlan:
    root = root.resolve()
    files_by_role: Dict[str, List[Path]] = {}

    files_by_role["xcodeproj"] = _filter_with_allowlist(
        _collect_sorted([path for path in iter_files(root, "project.pbxproj")]),
        root,
        allowlist_patterns,
    )
    files_by_role["info_plists"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, ["Info.plist"]))),
        root,
        allowlist_patterns,
    )
    files_by_role["package_resolved"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, ["Package.resolved"]))),
        root,
        allowlist_patterns,
    )
    files_by_role["podfiles"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, ["Podfile", "Podfile.lock"]))),
        root,
        allowlist_patterns,
    )
    files_by_role["cartfiles"] = _filter_with_allowlist(
        _collect_sorted(
            list(iter_matching_files(root, ["Cartfile", "Cartfile.resolved"]))
        ),
        root,
        allowlist_patterns,
    )
    files_by_role["swift_sources"] = _filter_with_allowlist(
        _collect_sorted([path for path in iter_files(root, ".swift")]),
        root,
        allowlist_patterns,
    )
    gradle_targets = [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "app/build.gradle",
        "app/build.gradle.kts",
        "GradleScripts/build.gradle",
    ]
    files_by_role["gradle_files"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, gradle_targets))),
        root,
        allowlist_patterns,
    )
    files_by_role["package_json"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, ["package.json"]))),
        root,
        allowlist_patterns,
    )
    env_targets = [".xcode.env", ".env", ".env.production", ".env.staging"]
    files_by_role["env_files"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, env_targets))),
        root,
        allowlist_patterns,
    )
    shell_targets = ["upload_symbols.sh", "upload_dsym.sh", "instabug.sh"]
    files_by_role["shell_scripts"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, shell_targets))),
        root,
        allowlist_patterns,
    )
    files_by_role["pubspec"] = _filter_with_allowlist(
        _collect_sorted(list(iter_matching_files(root, ["pubspec.yaml"]))),
        root,
        allowlist_patterns,
    )
    if include_ci_hints:
        ci_targets = [
            "Fastfile",
            "bitrise.yml",
            "bitrise.yaml",
            "Jenkinsfile",
            "circle.yml",
            "config.yml",
        ]
        files_by_role["ci_configs"] = _filter_with_allowlist(
            _collect_sorted(list(iter_matching_files(root, ci_targets))),
            root,
            allowlist_patterns,
        )
        # also capture GitHub workflows yaml files
        github_workflows = []
        workflows_root = root / ".github" / "workflows"
        if workflows_root.exists():
            github_workflows = sorted(
                workflows_root.glob("*.yml")
            ) + sorted(workflows_root.glob("*.yaml"))
        files_by_role["ci_configs"].extend(github_workflows)
        files_by_role["ci_configs"] = _filter_with_allowlist(
            _collect_sorted(files_by_role["ci_configs"]),
            root,
            allowlist_patterns,
        )

    return CapturePlan(
        scan_root=root,
        files_by_role=files_by_role,
        include_ci_hints=include_ci_hints,
        files_allowlist=allowlist_patterns,
    )


def render_manifest(plan: CapturePlan) -> str:
    sections = []
    sections.append("Capture Manifest")
    sections.append("")
    sections.append("Files that will be read:")
    files = plan.files_to_read()
    if files:
        for path in files:
            sections.append(f"  - {path}")
    else:
        sections.append("  (none)")
    sections.append("")
    sections.append("Fields that will be captured:")
    for field_label in plan.fields_to_capture():
        sections.append(f"  - {field_label}")
    sections.append("")
    sections.append("Fields explicitly NOT captured:")
    for field_label in plan.fields_not_captured():
        sections.append(f"  - {field_label}")
    sections.append("")
    if plan.files_allowlist:
        sections.append("Custom file allowlist patterns in effect:")
        for pattern in plan.files_allowlist:
            sections.append(f"  - {pattern}")
        sections.append("")
    if plan.potential_extra_findings():
        sections.append("Potential extra findings (if encountered):")
        for item in plan.potential_extra_findings():
            sections.append(f"  - {item}")
    sections.append("")
    sections.append("Privacy FAQ:")
    sections.append(
        "- Why is this safe? Only approved metadata (paths, versions, line numbers) is stored."
    )
    sections.append(
        "- Does it upload anything? No. All files remain local; you choose when to send outputs."
    )
    sections.append(
        "- Can I restrict files further? Yes, use --files-allowlist with glob patterns."
    )
    return "\n".join(sections)


def explain_extractors() -> str:
    return (
        "Extractor guide:\n"
        "- Project metadata: parses Info.plist and project.pbxproj for bundle/app names.\n"
        "- Build systems: inspects Package.resolved, Podfile(.lock), Cartfile(.resolved), and xcframework references.\n"
        "- Luciq usage: scans Swift source for Luciq.* APIs, recording only file paths, line numbers, and API labels.\n"
        "- SDK versions: parsed from lockfiles; manual embeds are reported as version 'unknown'.\n"
        "- Symbolication & CI hints: file presence only (e.g., upload-symbols scripts, Fastfile, GitHub workflows).\n"
        "- Environment: shell commands sw_vers, xcodebuild -version, swift --version, pod --version, carthage version.\n"
        "- File allowlist: when provided, only files matching the glob patterns are read.\n"
    )


def _collect_sorted(paths: List[Path]) -> List[Path]:
    unique = []
    seen = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    unique.sort()
    return unique


def _filter_with_allowlist(
    paths: List[Path], root: Path, allowlist_patterns: List[str]
) -> List[Path]:
    if not allowlist_patterns:
        return paths
    filtered: List[Path] = []
    for path in paths:
        rel = relative_path(path, root)
        rel_posix = rel.replace("\\", "/")
        for pattern in allowlist_patterns:
            if fnmatch(rel_posix, pattern):
                filtered.append(path)
                break
    return filtered

