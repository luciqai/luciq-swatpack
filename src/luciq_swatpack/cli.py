from __future__ import annotations

from pathlib import Path
from typing import List

import typer

from .main import run_scan
from . import __version__

app = typer.Typer(help="Luciq SWAT Pack customer-side collector")

_SCAN_BANNER = (
    r" _               _        ",
    r"| |   _   _  ___(_) __ _  ",
    r"| |__| |_| |/ __| |/ _` | ",
    r"|____|\___/|\___|_|\__, | ",
    r"                      |_| ",
    "",
    r"   _____ _      ______  ______   ___  ___  _____ __ __",
    r"  / ___/| | /| / / __ |/_  __/  / _ \/ _ \/ ___// //_/",
    r" _\ \   | |/ |/ / /_| | / /    / ___/ __ / /__ / ,<   ",
    r"/___/   |__/|__/_/  |_|/_/    /_/  /_/ |_\___//_/|_|  ",
)


def _print_scan_banner() -> None:
    """Minimal banner for full scan command."""
    for line in _SCAN_BANNER:
        typer.echo(line)
    typer.echo("")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"luciq-swatpack version: {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the installed luciq-swatpack version and exit.",
        callback=_version_callback,
        is_eager=True,
        expose_value=False,
    )
) -> None:
    """Top-level command placeholder."""
    # Typer callback enforces explicit subcommands.
    return None


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the iOS project root (defaults to current directory)",
    ),
    platform: str = typer.Option(
        "ios",
        "--platform",
        "-p",
        help="Platform to scan (ios only for now, but flag kept for future use)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the capture manifest and exit without producing files",
    ),
    manifest_only: bool = typer.Option(
        False,
        "--manifest-only",
        help="Alias for --dry-run (prints manifest + privacy FAQ only)",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Describe how each extractor works in plain English",
    ),
    include_ci_hints: bool = typer.Option(
        False,
        "--include-ci-hints",
        help="Include CI configuration metadata (still privacy-safe)",
    ),
    output_dir: Path = typer.Option(
        Path("./luciq_swatpack_out/"),
        "--output-dir",
        "-o",
        help="Directory for luciq_swatpack.json/report/log outputs",
    ),
    files_allowlist: List[str] = typer.Option(
        None,
        "--files-allowlist",
        help=(
            "Optional glob(s) relative to scan root to further restrict which files "
            "may be read (repeat flag to add multiple patterns)."
        ),
    ),
) -> None:
    """Generate a SWAT Pack snapshot."""
    _print_scan_banner()
    effective_dry_run = dry_run or manifest_only
    cli_arguments = {
        "path": str(path),
        "platform": platform,
        "dry_run": effective_dry_run,
        "explain": explain,
        "include_ci_hints": include_ci_hints,
        "output_dir": str(output_dir),
        "files_allowlist": files_allowlist or [],
    }
    run_scan(
        root=path,
        platform=platform,
        dry_run=effective_dry_run,
        explain=explain,
        include_ci_hints=include_ci_hints,
        output_dir=output_dir,
        files_allowlist=files_allowlist or [],
        cli_arguments=cli_arguments,
        typer_version=typer.__version__,
    )


if __name__ == "__main__":
    app()

