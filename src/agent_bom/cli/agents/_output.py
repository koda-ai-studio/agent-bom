"""Step 5: output rendering and format helpers."""

from __future__ import annotations

import contextlib
import errno
import json
import sys
from pathlib import Path
from typing import Any, Iterator

import click

from agent_bom.cli._param_source import is_explicit
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._output_terminal import _emit_console_report as _emit_console_report
from agent_bom.cli.agents._output_terminal import _emit_skill_analysis as _emit_skill_analysis
from agent_bom.cli.agents._output_terminal import _emit_stdout_report as _emit_stdout_report
from agent_bom.cli.agents._output_terminal import _emit_stdout_standard as _emit_stdout_standard
from agent_bom.cli.agents._report_written import announce_report_written
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_badge,
    export_csv,
    export_cyclonedx,
    export_html,
    export_json,
    export_junit,
    export_markdown,
    export_parquet,
    export_pdf,
    export_prometheus,
    export_sarif,
    export_spdx,
    export_spdx2,
    push_otlp,
    push_to_gateway,
    to_csv,
    to_cyclonedx,
    to_junit,
    to_markdown,
    to_prometheus,
    to_redacted_json,
    to_sarif,
    to_spdx,
    to_spdx2,
)
from agent_bom.output.json_fmt import write_redacted_json

_FORMAT_OUTPUT_RULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "json": ("agent-bom-report.json", (".json", ".json.gz")),
    "cyclonedx": ("agent-bom.cdx.json", (".cdx.json", ".json", ".cdx.json.gz", ".json.gz")),
    "sarif": ("agent-bom.sarif", (".sarif", ".sarif.json", ".sarif.gz", ".sarif.json.gz")),
    "spdx": ("agent-bom.spdx.json", (".spdx.json", ".json", ".spdx.json.gz", ".json.gz")),
    "spdx2": ("agent-bom.spdx2.json", (".spdx2.json", ".spdx.json", ".json", ".spdx2.json.gz", ".spdx.json.gz", ".json.gz")),
    "junit": ("agent-bom-results.xml", (".xml",)),
    "csv": ("agent-bom-results.csv", (".csv",)),
    "parquet": ("agent-bom-findings.parquet", (".parquet",)),
    "markdown": ("agent-bom-report.md", (".md", ".markdown")),
    "html": ("agent-bom-report.html", (".html", ".htm")),
    "pdf": ("agent-bom-report.pdf", (".pdf",)),
    "prometheus": ("agent-bom-metrics.prom", (".prom", ".txt")),
    "graph": ("agent-bom-graph.json", (".json",)),
    "mermaid": ("agent-bom-diagram.mmd", (".mmd", ".mermaid", ".md")),
    "svg": ("agent-bom-supply-chain.svg", (".svg",)),
    "graph-html": ("agent-bom-graph.html", (".graph-html", ".html", ".htm")),
    "badge": ("agent-bom-badge.json", (".json",)),
    "plain": ("agent-bom-report.txt", (".txt", ".text", ".log")),
    "text": ("agent-bom-report.txt", (".txt", ".text", ".log")),
}


def _is_null_device(output: Any) -> bool:
    """Return True when ``output`` points at the platform null device."""
    import os

    if not output or output == "-":
        return False
    candidates = {os.devnull, "/dev/null"}
    try:
        return os.path.realpath(str(output)) in {os.path.realpath(c) for c in candidates}
    except OSError:
        return str(output) in candidates


def _resolve_output_path(output: Any, output_format: str) -> str:
    """Return an output path whose suffix matches the selected format."""
    default_name, allowed_suffixes = _FORMAT_OUTPUT_RULES[output_format]
    if not output:
        return default_name

    raw_path = str(output)
    # Null device is a discard sink: keep the path verbatim so the write lands on
    # /dev/null (which succeeds silently) rather than a suffixed sibling like
    # `/dev/null.json` that lives in an unwritable dir and would fail (#3643).
    if _is_null_device(raw_path):
        return raw_path
    lower_path = raw_path.lower()
    if any(lower_path.endswith(suffix) for suffix in allowed_suffixes):
        return raw_path

    path = Path(raw_path)
    if not path.suffix:
        default_suffix = "".join(Path(default_name).suffixes)
        return f"{raw_path}{default_suffix}"

    # Friendly short-form handling: a truncated final suffix like `.cdx` /
    # `.spdx` / `.spdx2` that becomes a valid multi-part suffix for this format
    # once `.json` is appended is accepted rather than hard-erroring. We match
    # the exact allowed multi-part suffix (e.g. `.cdx.json`), so unrelated
    # extensions like `.png` still error instead of silently gaining `.json`.
    short_form = f"{path.suffix.lower()}.json"
    if short_form in allowed_suffixes:
        aliased = f"{raw_path}.json"
        click.echo(
            f"--format {output_format}: '{raw_path}' looks like a short form for this format; writing to '{aliased}'.",
            err=True,
        )
        return aliased

    suffix_list = ", ".join(allowed_suffixes)
    click.echo(
        f"--format {output_format} cannot write to '{raw_path}' because the file extension does not match. Use one of: {suffix_list}.",
        err=True,
    )
    raise SystemExit(2)


def _stdout_serialization(
    report: AIBOMReport,
    blast_radii: list,
    output_format: str,
    *,
    exclude_unfixable: bool,
    offline_html: bool,
    report_json: dict[str, Any] | None = None,
) -> str | None:
    """Best-effort serialize the report for stdout fallback when -o write fails.

    Returns ``None`` for formats that have no usable stdout representation
    (e.g. binary PDF), in which case the caller prints a skip message instead.
    """
    if output_format in ("json", "graph", "badge"):
        if output_format == "graph":
            from agent_bom.output.graph import build_graph_elements

            return json.dumps({"elements": build_graph_elements(report, blast_radii), "format": "cytoscape"}, indent=2)
        if output_format == "badge":
            from agent_bom.output.badge import to_badge

            return json.dumps(to_badge(report), indent=2)
        return json.dumps(to_redacted_json(report, report_json=report_json), indent=2)
    if output_format == "cyclonedx":
        return json.dumps(to_cyclonedx(report), indent=2)
    if output_format == "sarif":
        return json.dumps(to_sarif(report, exclude_unfixable=exclude_unfixable), indent=2)
    if output_format == "spdx":
        return json.dumps(to_spdx(report), indent=2)
    if output_format == "spdx2":
        return json.dumps(to_spdx2(report), indent=2)
    if output_format == "junit":
        return to_junit(report, blast_radii)
    if output_format == "csv":
        return to_csv(report, blast_radii)
    if output_format == "parquet":
        return None
    if output_format == "markdown":
        return to_markdown(report, blast_radii)
    if output_format == "prometheus":
        return to_prometheus(report, blast_radii)
    if output_format in ("html", "graph-html"):
        from agent_bom.output import to_html

        return to_html(report, blast_radii, offline_assets=offline_html)
    if output_format in ("text", "plain"):
        return _format_text(report, blast_radii)
    if output_format == "mermaid":
        from agent_bom.output.mermaid import to_mermaid_supply_chain

        return to_mermaid_supply_chain(report)
    if output_format == "svg":
        from agent_bom.output.svg import to_svg

        return to_svg(report, blast_radii)
    # pdf and any unknown/binary format have no stdout representation
    return None


@contextlib.contextmanager
def _enospc_report_fallback(
    con: Any,
    report: AIBOMReport,
    blast_radii: list,
    output_format: str,
    *,
    exclude_unfixable: bool,
    offline_html: bool,
    report_json: dict[str, Any] | None = None,
) -> Iterator[None]:
    """Catch a full-disk (or any) failure writing the ``-o`` report.

    The scan has already done all the work and computed its findings; a failed
    report write must NOT crash with a traceback. On ``OSError`` we emit the
    report to stdout when the format allows (so results are never lost), or
    print a clear actionable skip message, then let the normal exit-code path
    run with the scan's real exit code.
    """
    try:
        yield
    except OSError as exc:
        is_full = exc.errno in (errno.ENOSPC, errno.EDQUOT)
        reason = "disk full" if is_full else (exc.strerror or str(exc))
        target = getattr(exc, "filename", None) or "the report file"
        serialized = _stdout_serialization(
            report,
            blast_radii,
            output_format,
            exclude_unfixable=exclude_unfixable,
            offline_html=offline_html,
            report_json=report_json,
        )
        if serialized is not None:
            con.print(f"\n  [yellow]⚠[/yellow] Could not write report to {target} ({reason}) — emitting results to stdout instead.")
            click.echo(serialized, nl=not serialized.endswith("\n"))
        else:
            con.print(
                f"\n  [yellow]⚠[/yellow] Could not write report to {target} ({reason}) — "
                f"results shown above. Free space, pass -o to a roomier path, or set "
                f"AGENT_BOM_STATE_DIR=/tmp/agent-bom."
            )


def _register_iceberg_if_configured(report, blast_radii, con, quiet: bool) -> None:
    """Publish to a configured Iceberg REST catalog alongside the Parquet file.

    No-op unless an Iceberg catalog URL is configured (env / --iceberg-catalog-url).
    Once configured, publication is a requested artifact and therefore fails
    closed. The error points to the already-written Parquet recovery artifact.
    """
    from agent_bom.output.iceberg_catalog import maybe_register_iceberg
    from agent_bom.security import sanitize_error

    try:
        result = maybe_register_iceberg(report, blast_radii)
    except Exception as exc:  # noqa: BLE001 - degrade cleanly, file already written
        detail = sanitize_error(exc, generic=True)
        raise click.ClickException(
            f"Iceberg snapshot publication failed: {detail}. "
            "The Parquet file was written; retry with the same file after checking catalog URL, credentials, and warehouse access."
        ) from exc
    if result and not quiet:
        con.print(f"  [green]✓[/green] Iceberg snapshot: {result['identifier']} ({result['rows']} rows) → {result['catalog_url']}")


def render_output(
    ctx: ScanContext,
    *,
    output: Any,
    output_format: str,
    no_tree: bool,
    quiet: bool,
    no_color: bool,
    open_report: bool,
    compliance_export: Any,
    mermaid_mode: str,
    push_gateway: Any,
    otel_endpoint: Any,
    baseline: Any,
    delta_mode: bool,
    verbose: bool = False,
    exclude_unfixable: bool = False,
    fixable_only: bool = False,
    agent_mode: bool = False,
    agent_token_budget: int = 0,
    agent_mode_full: bool = False,
    offline_html: bool = False,
    **kwargs: Any,
) -> None:
    """Step 5: render report to console/file. Also Steps 5b, 5c, 5d."""
    con = ctx.con
    report = ctx.report
    blast_radii = ctx.blast_radii
    is_stdout = output == "-"
    compact_page = int(kwargs.get("page") or 1)

    # ``--output *.zip`` names the compliance bundle when a compliance export
    # is requested.  ZIP is not a normal report format, so do not send that
    # path through report-format inference before the bundle exporter runs.
    click_ctx = click.get_current_context(silent=True)
    compliance_bundle_output = bool(compliance_export and output and output.lower().endswith(".zip") and is_explicit(click_ctx, "output"))
    if not compliance_bundle_output:
        with _enospc_report_fallback(
            con,
            report,
            blast_radii,
            output_format,
            exclude_unfixable=exclude_unfixable,
            offline_html=offline_html,
            report_json=ctx.report_json,
        ):
            _emit_report(
                agent_mode,
                agent_mode_full,
                agent_token_budget,
                blast_radii,
                compact_page,
                con,
                ctx,
                exclude_unfixable,
                fixable_only,
                is_stdout,
                kwargs,
                mermaid_mode,
                no_tree,
                offline_html,
                open_report,
                output,
                output_format,
                quiet,
                report,
                verbose,
            )

    # Step 5b: Push to Prometheus Pushgateway (if requested)
    if push_gateway:
        from agent_bom.output.prometheus import PushgatewayError

        try:
            push_to_gateway(push_gateway, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics pushed to Pushgateway: {push_gateway}")
        except PushgatewayError as e:
            con.print(f"\n  [yellow]⚠[/yellow] Pushgateway push failed: {e}")

    # Step 5c: OpenTelemetry OTLP export (if requested)
    if otel_endpoint:
        try:
            push_otlp(otel_endpoint, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics exported via OTLP: {otel_endpoint}")
        except ImportError as e:
            con.print(f"\n  [yellow]⚠[/yellow] OTel export skipped: {e}")
        except Exception as e:  # noqa: BLE001
            con.print(f"\n  [yellow]⚠[/yellow] OTLP export failed: {e}")

    # Step 5d: Compliance evidence export (if requested)
    if compliance_export:
        from agent_bom.output import export_compliance_bundle

        ce_path = output if compliance_bundle_output else f"compliance-{compliance_export}.zip"
        if not ce_path.endswith(".zip"):
            ce_path += ".zip"
        export_compliance_bundle(report, compliance_export, ce_path)
        con.print(f"\n  [green]✓[/green] Compliance bundle: {ce_path}")


def _format_text(report: AIBOMReport, blast_radii: list) -> str:
    """Plain text output for piping to grep/awk.

    Delegates to the shared renderer so the CLI, the API scan result, and any
    other surface emit byte-identical plain text.
    """
    from agent_bom.output.scan_document import to_text

    return to_text(report, blast_radii)


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    sys.stdout.write(_format_text(report, blast_radii))


def _emit_document_report(
    blast_radii: Any,
    con: Any,
    ctx: ScanContext,
    exclude_unfixable: Any,
    offline_html: Any,
    open_report: Any,
    output: Any,
    output_format: Any,
    quiet: Any,
    report: Any,
) -> bool:
    if output_format in ("text", "plain") and not output:
        _print_text(report, blast_radii)
        return True
    elif output_format == "json":
        if output in (None, "", "-"):
            write_redacted_json(report, sys.stdout, report_json=ctx.report_json)
            sys.stdout.flush()
        else:
            out_path = _resolve_output_path(output, output_format)
            export_json(report, out_path, report_json=ctx.report_json)
            announce_report_written(con, "JSON report", out_path, quiet=quiet)
        return True
    elif output_format == "cyclonedx":
        out_path = _resolve_output_path(output, output_format)
        export_cyclonedx(report, out_path)
        announce_report_written(con, "CycloneDX BOM", out_path, quiet=quiet)
        return True
    elif output_format == "sarif":
        out_path = _resolve_output_path(output, output_format)
        export_sarif(report, out_path, exclude_unfixable=exclude_unfixable)
        announce_report_written(con, "SARIF report", out_path, quiet=quiet)
        if not quiet:
            con.print("  [dim]SARIF includes enrichment context when available: CVSS/CWE, EPSS, and CISA KEV.[/dim]")
        return True
    elif output_format == "spdx":
        out_path = _resolve_output_path(output, output_format)
        export_spdx(report, out_path)
        announce_report_written(con, "SPDX 3.0 BOM", out_path, quiet=quiet)
        return True
    elif output_format == "spdx2":
        out_path = _resolve_output_path(output, output_format)
        export_spdx2(report, out_path)
        announce_report_written(con, "SPDX 2.3 BOM", out_path, quiet=quiet)
        return True
    elif output_format == "junit":
        out_path = _resolve_output_path(output, output_format)
        export_junit(report, out_path, blast_radii)
        announce_report_written(con, "JUnit XML", out_path, quiet=quiet)
        return True
    elif output_format == "csv":
        out_path = _resolve_output_path(output, output_format)
        export_csv(report, out_path, blast_radii)
        announce_report_written(con, "CSV report", out_path, quiet=quiet)
        return True
    elif output_format == "parquet":
        out_path = _resolve_output_path(output, output_format)
        export_parquet(report, out_path, blast_radii)
        announce_report_written(con, "Parquet findings", out_path, quiet=quiet)
        _register_iceberg_if_configured(report, blast_radii, con, quiet)
        return True
    elif output_format == "markdown":
        out_path = _resolve_output_path(output, output_format)
        export_markdown(report, out_path, blast_radii)
        announce_report_written(con, "Markdown report", out_path, quiet=quiet)
        return True
    return False


def _emit_visual_report(
    blast_radii: Any,
    con: Any,
    mermaid_mode: Any,
    offline_html: Any,
    open_report: Any,
    output: Any,
    output_format: Any,
    quiet: Any,
    report: Any,
) -> bool:
    if output_format == "graph":
        from agent_bom.output.graph import build_graph_elements

        out_path = _resolve_output_path(output, output_format)
        elements = build_graph_elements(report, blast_radii)
        Path(out_path).write_text(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
        announce_report_written(con, "Graph JSON", out_path, quiet=quiet)
        con.print("  [dim]Cytoscape.js-compatible element list — open with Cytoscape desktop or any JS graph library[/dim]")
        return True
    elif output_format == "mermaid":
        out_path = _resolve_output_path(output, output_format)
        if mermaid_mode == "attack-flow":
            from agent_bom.output.mermaid import to_mermaid

            Path(out_path).write_text(to_mermaid(report, blast_radii))
        elif mermaid_mode == "lifecycle":
            from agent_bom.output.mermaid import to_mermaid_lifecycle

            Path(out_path).write_text(to_mermaid_lifecycle(report, blast_radii))
        else:
            from agent_bom.output.mermaid import to_mermaid_supply_chain

            Path(out_path).write_text(to_mermaid_supply_chain(report))
        announce_report_written(con, f"Mermaid diagram ({mermaid_mode})", out_path, quiet=quiet)
        con.print("  [dim]Render with: mermaid-cli, GitHub markdown, or mermaid.live[/dim]")
        return True
    elif output_format == "svg":
        from agent_bom.output.svg import export_svg

        out_path = _resolve_output_path(output, output_format)
        export_svg(report, blast_radii, out_path)
        announce_report_written(con, "SVG diagram", out_path, quiet=quiet)
        con.print("  [dim]Open in any browser or image viewer[/dim]")
        return True
    elif output_format == "graph-html":
        from agent_bom.output.graph import export_graph_html

        out_path = _resolve_output_path(output, output_format)
        export_graph_html(report, blast_radii, out_path, offline_assets=offline_html)
        announce_report_written(con, "Interactive graph", out_path, quiet=quiet)
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}", soft_wrap=True)
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}", soft_wrap=True)
        return True
    elif output_format == "badge":
        out_path = _resolve_output_path(output, output_format)
        export_badge(report, out_path)
        announce_report_written(con, "Badge JSON", out_path, quiet=quiet)
        con.print("  [dim]Use with: https://img.shields.io/endpoint?url=<public-url-to-badge-json>[/dim]")
        return True
    return False


def _emit_inferred_report(
    blast_radii: Any,
    con: Any,
    ctx: ScanContext,
    exclude_unfixable: Any,
    offline_html: Any,
    output: Any,
    output_format: Any,
    quiet: Any,
    report: Any,
) -> bool:
    if output_format in ("text", "plain") and output:
        out_path = _resolve_output_path(output, output_format)
        Path(out_path).write_text(_format_text(report, blast_radii))
        announce_report_written(con, "Plain text report", out_path, quiet=quiet)
        return True
    elif output:
        if output.endswith(".cdx.json"):
            export_cyclonedx(report, output)
        elif output.endswith(".json"):
            export_json(report, output, report_json=ctx.report_json)
        elif output.endswith(".sarif"):
            export_sarif(report, output, exclude_unfixable=exclude_unfixable)
        elif output.endswith(".spdx.json"):
            export_spdx(report, output)
        elif output.endswith(".graph-html"):
            from agent_bom.output.graph import export_graph_html

            export_graph_html(report, blast_radii, output, offline_assets=offline_html)
        elif output.endswith(".html"):
            export_html(report, output, blast_radii, offline_assets=offline_html)
        elif output.endswith(".pdf"):
            export_pdf(report, output, blast_radii)
        elif output.endswith(".xml"):
            export_junit(report, output, blast_radii)
        elif output.endswith(".csv"):
            export_csv(report, output, blast_radii)
        elif output.endswith(".parquet"):
            export_parquet(report, output, blast_radii)
            _register_iceberg_if_configured(report, blast_radii, con, quiet)
        elif output.endswith(".md"):
            export_markdown(report, output, blast_radii)
        else:
            click.echo(
                f"Cannot infer output format from '{output}'. Use --format explicitly or choose a supported extension.",
                err=True,
            )
            raise SystemExit(2)
        announce_report_written(con, "Report", output, quiet=quiet)
        return True
    return False


def _emit_report(
    agent_mode: Any,
    agent_mode_full: Any,
    agent_token_budget: Any,
    blast_radii: Any,
    compact_page: Any,
    con: Any,
    ctx: ScanContext,
    exclude_unfixable: Any,
    fixable_only: Any,
    is_stdout: Any,
    kwargs: Any,
    mermaid_mode: Any,
    no_tree: Any,
    offline_html: Any,
    open_report: Any,
    output: Any,
    output_format: Any,
    quiet: Any,
    report: Any,
    verbose: Any,
) -> None:
    if is_stdout:
        _emit_stdout_report(
            agent_mode,
            agent_mode_full,
            agent_token_budget,
            blast_radii,
            ctx,
            exclude_unfixable,
            mermaid_mode,
            offline_html,
            output,
            output_format,
            report,
        )
    elif _is_null_device(output) and output_format in ("console", "text", "plain"):
        pass
    elif output_format == "console" and not output:
        _emit_console_report(compact_page, con, ctx, fixable_only, kwargs, no_tree, quiet, report, verbose)
    else:
        _emit_document_report(
            blast_radii, con, ctx, exclude_unfixable, offline_html, open_report, output, output_format, quiet, report
        ) or _emit_web_report(blast_radii, con, offline_html, open_report, output, output_format, quiet, report) or _emit_visual_report(
            blast_radii, con, mermaid_mode, offline_html, open_report, output, output_format, quiet, report
        ) or _emit_inferred_report(blast_radii, con, ctx, exclude_unfixable, offline_html, output, output_format, quiet, report)


def _emit_web_report(
    blast_radii: Any, con: Any, offline_html: Any, open_report: Any, output: Any, output_format: Any, quiet: Any, report: Any
) -> bool:
    if output_format == "html":
        out_path = _resolve_output_path(output, output_format)
        export_html(report, out_path, blast_radii, offline_assets=offline_html)
        announce_report_written(con, "HTML report", out_path, quiet=quiet)
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}", soft_wrap=True)
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}", soft_wrap=True)
        return True
    elif output_format == "pdf":
        out_path = _resolve_output_path(output, output_format)
        export_pdf(report, out_path, blast_radii)
        announce_report_written(con, "PDF report", out_path, quiet=quiet)
        return True
    elif output_format == "prometheus":
        out_path = _resolve_output_path(output, output_format)
        export_prometheus(report, out_path, blast_radii)
        announce_report_written(con, "Prometheus metrics", out_path, quiet=quiet)
        con.print("  [dim]Scrape with node_exporter textfile or push via --push-gateway[/dim]")
        return True
    return False
