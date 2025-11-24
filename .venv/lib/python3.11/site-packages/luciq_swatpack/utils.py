from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "DerivedData",
    "build",
    "Build",
    "Pods",
    "vendor",
    "Vendor",
    "Carthage",
    ".idea",
    ".vscode",
    "Carthage/Build",
}


def iter_files(root: Path, suffix: str) -> Iterator[Path]:
    """Yield files under root with the given suffix, skipping ignored directories."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        filtered = [
            d for d in dirnames if not _is_ignored_directory(Path(dirpath) / d)
        ]
        dirnames[:] = filtered
        for name in filenames:
            if not name.endswith(suffix):
                continue
            path = Path(dirpath) / name
            if _is_ignored_directory(path.parent):
                continue
            yield path


def iter_matching_files(root: Path, names: Iterable[str]) -> Iterator[Path]:
    """Yield files whose names match one of the provided names."""
    name_set = set(names)
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        filtered = [
            d for d in dirnames if not _is_ignored_directory(Path(dirpath) / d)
        ]
        dirnames[:] = filtered
        for name in filenames:
            if name in name_set:
                path = Path(dirpath) / name
                yield path


def _is_ignored_directory(path: Path) -> bool:
    parts = set(path.parts)
    for ignored in IGNORED_DIRECTORIES:
        if ignored in parts:
            return True
    return False


def run_command(command: List[str]) -> Optional[str]:
    """Run a shell command safely and return stdout or None on failure."""
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except FileNotFoundError:
        return None
    output = result.stdout.strip()
    return output or None


def redact_home(path: Path) -> str:
    """Replace the user's home directory with /Users/<redacted> to preserve privacy."""
    path = path.resolve()
    home = Path.home().resolve()
    try:
        relative = path.relative_to(home)
    except ValueError:
        return str(path)
    return str(Path("/Users/<redacted>") / relative)


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

