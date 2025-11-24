from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import typer

from .analysis import AnalysisContext, analyze_project
from .plan import (
    CapturePlan,
    build_capture_plan,
    explain_extractors,
    render_manifest,
)
from .reporting import write_json_snapshot, write_markdown_report
from .utils import relative_path


def run_scan(
    root: Path,
    platform: str,
    dry_run: bool,
    explain: bool,
    include_ci_hints: bool,
    output_dir: Path,
    files_allowlist: List[str],
    cli_arguments: Dict[str, object],
    typer_version: str,
) -> None:
    if platform.lower() != "ios":
        typer.echo(
            "Android scanning is not supported yet. Please rerun with --platform ios."
        )
        raise typer.Exit(code=2)
    root = root.expanduser().resolve()
    if not root.exists():
        typer.echo(f"Error: path '{root}' does not exist.")
        raise typer.Exit(code=1)

    typer.echo("Step 1/6 Resolving capture plan…")
    plan = build_capture_plan(root, include_ci_hints, files_allowlist)
    _validate_plan_or_exit(plan)
    manifest_text = render_manifest(plan)
    typer.echo(manifest_text)
    if explain:
        typer.echo("")
        typer.echo(explain_extractors())

    if dry_run:
        typer.echo("Dry run requested; exiting after manifest.")
        return

    typer.echo("Step 2/6 Preparing output directory…")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "luciq_swatpack.log"
    _configure_logging(log_path)
    logging.info("Scan root: %s", root)
    logging.info("Output directory: %s", output_dir)

    typer.echo("Step 3/6 Collecting metadata…")
    ctx = AnalysisContext(
        root=root,
        plan=plan,
        include_ci_hints=include_ci_hints,
        cli_arguments=cli_arguments,
        typer_version=typer_version,
    )
    snapshot = analyze_project(ctx)

    typer.echo("Step 4/6 Writing JSON snapshot…")
    json_path = write_json_snapshot(output_dir, snapshot)
    logging.info("Wrote %s", json_path)

    typer.echo("Step 5/6 Writing human report…")
    report_path = write_markdown_report(output_dir, snapshot)
    logging.info("Wrote %s", report_path)

    typer.echo("Step 6/6 Finalizing…")
    logging.info("Files read (%d): %s", len(ctx.files_read), ctx.files_read)
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Report: {report_path}")
    typer.echo(f"Log: {log_path}")


def _configure_logging(log_path: Path) -> None:
    logging.basicConfig(
        filename=log_path,
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.INFO,
    )


def _validate_plan_or_exit(plan: CapturePlan) -> None:
    blockers: List[str] = []
    if not plan.files_by_role.get("info_plists"):
        blockers.append(
            "No Info.plist files were found (needed for app/bundle metadata)."
        )
    if not plan.files_by_role.get("swift_sources"):
        blockers.append(
            "No Swift source files were found (needed to detect Luciq usage)."
        )
    if blockers:
        typer.echo("Unable to continue because:")
        for item in blockers:
            typer.echo(f"- {item}")
        typer.echo("")
        typer.echo("What you can do next:")
        typer.echo("* Ensure you pointed the tool at the Xcode project root.")
        if plan.files_allowlist:
            typer.echo("* Review your --files-allowlist patterns; they might be too restrictive.")
        typer.echo("* Re-run with --explain for details or contact Luciq Support.")
        raise typer.Exit(code=2)

