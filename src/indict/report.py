"""Rendering: the same Report as a terminal view, JSON, or Markdown.

The terminal view is for reading at a glance. `--json` is for piping into other
tools. `--markdown` is the paste-into-a-ticket format. All three read from one
`Report`, so they never drift apart.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Report, SourceResult, Verdict

_VERDICT_STYLE = {
    Verdict.MALICIOUS: "bold white on red",
    Verdict.SUSPICIOUS: "bold black on yellow",
    Verdict.CLEAN: "bold white on green",
    Verdict.UNKNOWN: "bold white on grey37",
}
_VERDICT_COLOR = {
    Verdict.MALICIOUS: "red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CLEAN: "green",
    Verdict.UNKNOWN: "grey62",
}


# --- Terminal -------------------------------------------------------------

def render_terminal(report: Report, console: Console | None = None) -> None:
    console = console or Console()

    banner = Text(f" {report.verdict.value.upper()} ", style=_VERDICT_STYLE[report.verdict])
    header = Text.assemble(
        (report.indicator, "bold"),
        ("  (", "dim"),
        (report.indicator_type.value, "cyan"),
        (")  ", "dim"),
        banner,
    )
    if report.redacted:
        header.append("  [redacted]", style="dim")
    console.print(Panel(header, expand=False, border_style=_VERDICT_COLOR[report.verdict]))

    _render_sources(report, console)
    _render_evidence(report, console)
    _render_correlation(report, console)
    _render_unavailable(report, console)


def _render_sources(report: Report, console: Console) -> None:
    table = Table(title="Sources", title_justify="left", header_style="bold", expand=True)
    table.add_column("source", style="cyan", no_wrap=True)
    table.add_column("verdict", no_wrap=True)
    table.add_column("summary")
    table.add_column("", justify="right", style="dim", no_wrap=True)

    for result in report.ran:
        if not result.ok:
            verdict_cell = Text("error", style="red")
        else:
            verdict_cell = Text(result.verdict.value, style=_VERDICT_COLOR[result.verdict])
        marker = "cached" if result.from_cache else ""
        if result.latency_ms is not None and not result.from_cache:
            marker = f"{result.latency_ms} ms"
        table.add_row(result.source, verdict_cell, result.summary, marker)

    if report.ran:
        console.print(table)


def _render_evidence(report: Report, console: Console) -> None:
    if not report.evidence:
        return
    lines = Text()
    for item in report.evidence:
        lines.append(f"  • {item}\n")
    console.print(Panel(lines, title="Verdict evidence", title_align="left",
                        border_style=_VERDICT_COLOR[report.verdict], expand=False))


def _render_correlation(report: Report, console: Console) -> None:
    if not report.clusters:
        return
    table = Table(title="Correlated infrastructure", title_justify="left",
                  header_style="bold", expand=True)
    table.add_column(report.clusters[0].label, style="magenta", no_wrap=True)
    table.add_column("related indicators")
    for cluster in report.clusters:
        members = ", ".join(cluster.members[:12])
        if len(cluster.members) > 12:
            members += f", (+{len(cluster.members) - 12} more)"
        table.add_row(f"{cluster.key}  ({len(cluster.members)})", members)
    console.print(table)


def _render_unavailable(report: Report, console: Console) -> None:
    skipped = [r for r in report.results if not r.available]
    if not skipped:
        return
    text = Text()
    for result in skipped:
        text.append(f"  • {result.source}: {result.summary}\n", style="dim")
    console.print(Panel(text, title="Not run", title_align="left",
                        border_style="grey37", expand=False))


# --- JSON -----------------------------------------------------------------

def to_dict(report: Report) -> dict[str, Any]:
    return {
        "indicator": report.indicator,
        "indicator_type": report.indicator_type.value,
        "verdict": report.verdict.value,
        "generated_at": datetime.fromtimestamp(
            report.generated_at, tz=UTC
        ).isoformat(),
        "redacted": report.redacted,
        "evidence": report.evidence,
        "sources": [_result_dict(r) for r in report.results],
        "pivots": [
            {
                "indicator": p.indicator,
                "type": p.indicator_type.value,
                "relation": p.relation.value,
                "source": p.source,
            }
            for p in report.pivots
        ],
        "clusters": [
            {"key": c.key, "label": c.label, "members": c.members}
            for c in report.clusters
        ],
    }


def _result_dict(result: SourceResult) -> dict[str, Any]:
    return {
        "source": result.source,
        "available": result.available,
        "ok": result.ok,
        "error": result.error,
        "verdict": result.verdict.value,
        "score": result.score,
        "summary": result.summary,
        "data": result.data,
        "links": result.links,
        "from_cache": result.from_cache,
        "latency_ms": result.latency_ms,
    }


def to_json(report: Report, indent: int = 2) -> str:
    return json.dumps(to_dict(report), indent=indent, sort_keys=False)


# --- Markdown -------------------------------------------------------------

def to_markdown(report: Report) -> str:
    generated = datetime.fromtimestamp(report.generated_at, tz=UTC)
    lines: list[str] = [
        f"# indict report: `{report.indicator}`",
        "",
        f"- **Type:** {report.indicator_type.value}",
        f"- **Verdict:** **{report.verdict.value.upper()}**",
        f"- **Generated:** {generated.strftime('%Y-%m-%d %H:%M UTC')}"
        + ("  (redacted)" if report.redacted else ""),
        "",
    ]

    if report.evidence:
        lines += ["## Verdict evidence", ""]
        lines += [f"- {item}" for item in report.evidence]
        lines.append("")

    lines += ["## Sources", "", "| Source | Verdict | Summary | Reference |",
              "| --- | --- | --- | --- |"]
    for result in report.ran:
        verdict = "error" if not result.ok else result.verdict.value
        link = result.links[0] if result.links else ""
        ref = f"[link]({link})" if link else ""
        summary = result.summary.replace("|", "\\|")
        lines.append(f"| {result.source} | {verdict} | {summary} | {ref} |")
    lines.append("")

    if report.clusters:
        lines += ["## Correlated infrastructure", ""]
        for cluster in report.clusters:
            lines.append(f"- **{cluster.key}** ({cluster.label}, {len(cluster.members)}):")
            lines += [f"  - {member}" for member in cluster.members[:25]]
            if len(cluster.members) > 25:
                lines.append(f"  - (+{len(cluster.members) - 25} more)")
        lines.append("")

    skipped = [r for r in report.results if not r.available]
    if skipped:
        lines += ["## Not run", ""]
        lines += [f"- {r.source}: {r.summary}" for r in skipped]
        lines.append("")

    lines += [
        "---",
        "",
        "_Generated by [indict](https://github.com/rgerjeki/indict). "
        "Source data is cited, not rehosted._",
        "",
    ]
    return "\n".join(lines)
