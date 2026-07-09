"""Command-line entry point and orchestration.

`triage()` is the reusable core: detect the type, run every applicable and
available source (in parallel, because triage speed is the point), correlate the
pivots, and aggregate a verdict into a Report. `main()` wraps it with argument
parsing and output selection. Keeping `triage()` separate keeps it testable
without touching argv or stdout.
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.resolver
import httpx
from rich.console import Console

from . import __version__
from .cache import Cache
from .config import Config, load_config
from .correlate import correlate
from .feeds import FeedCache
from .http import Http, RateLimited
from .indicators import DetectionError, detect
from .models import IndicatorType, Report, SourceResult
from .redact import redact_report
from .report import render_terminal, to_json, to_markdown
from .sources import Source, all_sources
from .sources.base import Context
from .verdict import aggregate


def triage(
    value: str,
    config: Config,
    *,
    only: set[str] | None = None,
    do_correlate: bool = True,
    max_workers: int = 8,
) -> Report:
    """Enrich, correlate, and score a single indicator. The reusable core."""
    indicator_type, indicator = detect(value)

    http = Http(timeout=config.http_timeout)
    ctx = Context(
        config=config,
        http=http,
        cache=Cache(config.cache_dir, config.cache_ttl, enabled=config.use_cache),
        feeds=FeedCache(config.cache_dir / "feeds", http),
    )

    report = Report(indicator=indicator, indicator_type=indicator_type)
    try:
        _run_sources(report, indicator, indicator_type, ctx, only, max_workers)
    finally:
        ctx.http.close()

    if do_correlate:
        correlate(report, resolve=_make_resolver(config.http_timeout))
    else:
        correlate(report, resolve=None)
    aggregate(report)
    return report


def _run_sources(
    report: Report,
    indicator: str,
    indicator_type: IndicatorType,
    ctx: Context,
    only: set[str] | None,
    max_workers: int,
) -> None:
    to_run: list[Source] = []
    for source in all_sources():
        if only and source.name not in only:
            continue
        if not source.supports(indicator_type):
            continue
        if not source.available(ctx.config):
            report.results.append(
                SourceResult.unavailable(
                    source.name, indicator, indicator_type, source.unavailable_reason()
                )
            )
            continue
        to_run.append(source)

    if not to_run:
        return

    with ThreadPoolExecutor(max_workers=min(max_workers, len(to_run))) as pool:
        futures = {
            pool.submit(_run_one, source, indicator, indicator_type, ctx): source
            for source in to_run
        }
        for future in futures:
            report.results.append(future.result())

    # Stable, readable ordering: by the registry order of the sources.
    order = {s.name: i for i, s in enumerate(all_sources())}
    report.results.sort(key=lambda r: order.get(r.source, 99))


def _run_one(
    source: Source, indicator: str, indicator_type: IndicatorType, ctx: Context
) -> SourceResult:
    import time

    start = time.perf_counter()
    try:
        result = source.query(indicator, indicator_type, ctx)
    except RateLimited:
        result = SourceResult.failed(source.name, indicator, indicator_type, "rate limited")
    except httpx.HTTPStatusError as exc:
        result = SourceResult.failed(
            source.name, indicator, indicator_type, f"HTTP {exc.response.status_code}"
        )
    except httpx.HTTPError as exc:
        result = SourceResult.failed(
            source.name, indicator, indicator_type, type(exc).__name__
        )
    except Exception as exc:  # noqa: BLE001 - one bad source must not sink the run
        result = SourceResult.failed(
            source.name, indicator, indicator_type, f"{type(exc).__name__}: {exc}"
        )
    if result.latency_ms is None:
        result.latency_ms = int((time.perf_counter() - start) * 1000)
    return result


def _make_resolver(timeout: float):
    """A live DNS A-record resolver for correlation, tolerant of failures."""

    def resolve(host: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(host, "A", lifetime=timeout)
            return [str(a) for a in answers]
        except Exception:  # noqa: BLE001 - a name that will not resolve just yields nothing
            return []

    return resolve


# --- argument parsing / output -------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="indict",
        description="Enrich, correlate, and triage an OSINT indicator "
        "(IP, domain, hash, or URL).",
    )
    parser.add_argument("indicator", nargs="?", help="the indicator to look up")
    parser.add_argument("--json", metavar="PATH",
                        help="write JSON to PATH (use '-' for stdout)")
    parser.add_argument("--markdown", metavar="PATH",
                        help="write a Markdown report to PATH (use '-' for stdout)")
    parser.add_argument("--redact", action="store_true",
                        help="strip PII (WHOIS names/emails) for shareable output")
    parser.add_argument("--no-cache", action="store_true",
                        help="ignore and do not write the local response cache")
    parser.add_argument("--no-correlate", action="store_true",
                        help="skip live subdomain resolution during correlation")
    parser.add_argument("--only", metavar="SOURCES",
                        help="comma-separated source names to run (e.g. dns,crt.sh)")
    parser.add_argument("--env-file", default=".env",
                        help="path to the .env file (default: .env)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the terminal report (useful with --json)")
    parser.add_argument("--version", action="version", version=f"indict {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    err = Console(stderr=True)

    if not args.indicator:
        parser.print_help()
        return 2

    config = load_config(args.env_file)
    if args.no_cache:
        config.use_cache = False
    only = {s.strip() for s in args.only.split(",")} if args.only else None

    try:
        report = triage(
            args.indicator,
            config,
            only=only,
            do_correlate=not args.no_correlate,
        )
    except DetectionError as exc:
        err.print(f"[red]error:[/red] {exc}")
        return 2

    if args.redact:
        redact_report(report)

    if not args.quiet:
        render_terminal(report, console)

    if args.json:
        _emit(to_json(report), args.json, console)
    if args.markdown:
        _emit(to_markdown(report), args.markdown, console)

    return 0


def _emit(content: str, target: str, console: Console) -> None:
    if target == "-":
        # Print raw (no rich markup interpretation) so JSON/Markdown stays intact.
        print(content)
    else:
        Path(target).write_text(content)
        console.print(f"[dim]wrote {target}[/dim]")


if __name__ == "__main__":
    sys.exit(main())
