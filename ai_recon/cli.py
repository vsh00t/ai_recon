"""ai-recon CLI entry point (Typer)."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
import yaml
from platformdirs import user_cache_dir
from rich.console import Console
from rich.table import Table

from ai_recon.core.errors import AIReconError
from ai_recon.core.models import Report, ScopeDocument
from ai_recon.core.registry import Registry
from ai_recon.core.report import ReportEmitter
from ai_recon.core.runner import Profile, Runner

app = typer.Typer(
    name="ai-recon",
    help="Universal AI reconnaissance and red-teaming framework.",
    no_args_is_help=True,
    add_completion=False,
)
scope_app = typer.Typer(name="scope", help="Scope management.", no_args_is_help=True)
tech_app = typer.Typer(name="technique", help="Technique inspection.", no_args_is_help=True)
catalog_app = typer.Typer(name="catalog", help="Catalog inspection.", no_args_is_help=True)
adapter_app = typer.Typer(name="adapter", help="Adapter inspection.", no_args_is_help=True)
report_app = typer.Typer(name="report", help="Report management.", no_args_is_help=True)
app.add_typer(scope_app)
app.add_typer(tech_app)
app.add_typer(catalog_app)
app.add_typer(adapter_app)
app.add_typer(report_app)

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_cache_dir() -> Path:
    return Path(user_cache_dir("ai-recon"))


def _setup_logging(level: str) -> logging.Logger:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
        stream=sys.stderr,
    )
    return logging.getLogger("ai_recon")


def _load_scope(path: Path) -> ScopeDocument:
    with path.open() as fh:
        data = yaml.safe_load(fh)
    return ScopeDocument.model_validate(data)


def _runs_dir(cache_dir: Path) -> Path:
    return cache_dir / "runs"


# ---------------------------------------------------------------------------
# scope ...
# ---------------------------------------------------------------------------

@scope_app.command("validate")
def scope_validate(scope_path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Validate a scope.yaml against the schema."""
    try:
        sc = _load_scope(scope_path)
    except Exception as exc:
        console.print(f"[red]Invalid scope:[/red] {exc}")
        raise typer.Exit(2)
    console.print(f"[green]✓[/green] scope OK — engagement: {sc.engagement.name}, "
                  f"{len(sc.scope.allow)} allow entries.")


@scope_app.command("discover")
def scope_discover(
    scope_path: Path = typer.Option(..., "--scope", exists=True),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    """Run only the discovery phase from a scope."""
    sc = _load_scope(scope_path)
    cache = cache_dir or _default_cache_dir()
    profile = Profile(
        name="discovery_only",
        intrusiveness_max="passive",
        enable=[
            "passive.header_fingerprint", "passive.health_probe",
            "passive.openai_compat_probe", "passive.dns_recon",
        ],
        disable=[],
        options={},
    )
    runner = Runner(scope=sc, profile=profile, cache_dir=cache, dry_run=False)
    report = asyncio.run(runner.run())
    _persist(report, cache)
    console.print(f"[green]Discovery complete:[/green] {len(report.findings)} findings "
                  f"(run_id={report.run_id})")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@app.command("run")
def run_cmd(
    scope_path: Path = typer.Option(..., "--scope", exists=True),
    profile_name: str = typer.Option(..., "--profile"),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
    seed: int = typer.Option(42, "--seed"),
    allow_intrusive: Optional[str] = typer.Option(
        None, "--allow-intrusive",
        help="Override intrusiveness ceiling: passive|low|medium|high",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    log_level: str = typer.Option("INFO", "--log-level"),
    max_concurrency: int = typer.Option(4, "--max-concurrency"),
) -> None:
    """Execute a profile against a scope and emit a report."""
    log = _setup_logging(log_level)
    sc = _load_scope(scope_path)
    cache = cache_dir or _default_cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    profile = Profile.find(profile_name)

    runner = Runner(
        scope=sc,
        profile=profile,
        cache_dir=cache,
        seed=seed,
        allow_intrusive=allow_intrusive,  # type: ignore[arg-type]
        dry_run=dry_run,
        max_concurrency=max_concurrency,
        logger=log,
    )

    try:
        report = asyncio.run(runner.run())
    except AIReconError as exc:
        console.print(f"[red]{exc.__class__.__name__}:[/red] {exc}")
        raise typer.Exit(2)

    if dry_run:
        return

    out = _persist(report, cache)
    _print_summary(report, out)


# ---------------------------------------------------------------------------
# recon — generic one-shot AI reconnaissance against any URL
# ---------------------------------------------------------------------------

@app.command("recon")
def recon_cmd(
    target: str = typer.Argument(
        ..., help="Target base URL (e.g. https://api.example.com) or host:port."
    ),
    profile_name: str = typer.Option(
        "full_recon", "--profile",
        help="Recon profile to execute.",
    ),
    authorization_ref: str = typer.Option(
        "", "--authorization",
        help="Engagement authorization reference (required for medium/high).",
    ),
    intrusiveness: str = typer.Option(
        "low", "--intrusiveness",
        help="Cap intrusiveness for this run: passive|low|medium|high.",
    ),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
    seed: int = typer.Option(42, "--seed"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    log_level: str = typer.Option("INFO", "--log-level"),
    max_concurrency: int = typer.Option(4, "--max-concurrency"),
) -> None:
    """Run AI reconnaissance against a single target URL.

    Builds an in-memory scope.yaml that allows ONLY the resolved host/port
    of ``target`` (deny-all otherwise) and executes the chosen profile.
    Equivalent to writing a one-host scope file and calling ``run``.
    """
    log = _setup_logging(log_level)

    from urllib.parse import urlparse
    raw = target if "://" in target else f"https://{target}"
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        console.print(f"[red]Invalid target:[/red] {target}")
        raise typer.Exit(2)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    scope_doc = ScopeDocument.model_validate({
        "schema_version": 1,
        "engagement": {
            "name": f"recon:{host}",
            "authorization_ref": authorization_ref,
        },
        "scope": {
            "allow": [{"host": host, "ports": [port]}],
            "deny": [],
        },
        "intrusiveness_max": intrusiveness,
    })

    cache = cache_dir or _default_cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    profile = Profile.find(profile_name)

    runner = Runner(
        scope=scope_doc,
        profile=profile,
        cache_dir=cache,
        seed=seed,
        allow_intrusive=intrusiveness,  # type: ignore[arg-type]
        dry_run=dry_run,
        max_concurrency=max_concurrency,
        logger=log,
    )

    console.print(
        f"[cyan]ai-recon recon[/cyan] target={host}:{port} profile={profile_name} "
        f"intrusiveness={intrusiveness}"
    )

    try:
        report = asyncio.run(runner.run())
    except AIReconError as exc:
        console.print(f"[red]{exc.__class__.__name__}:[/red] {exc}")
        raise typer.Exit(2)

    if dry_run:
        return

    out = _persist(report, cache)
    _print_summary(report, out)


def _persist(report: Report, cache: Path) -> Path:
    out = _runs_dir(cache) / report.run_id
    out.mkdir(parents=True, exist_ok=True)
    em = ReportEmitter(report)
    em.write_json(out / "report.json")
    em.write_markdown(out / "report.md")
    em.write_html(out / "report.html")
    em.write_sarif(out / "report.sarif")
    return out


def _print_summary(report: Report, out: Path) -> None:
    table = Table(title=f"ai-recon run {report.run_id}", show_lines=True)
    table.add_column("severity")
    table.add_column("count", justify="right")
    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            table.add_row(sev, str(counts[sev]))
    console.print(table)
    console.print(f"[green]Report:[/green] {out}")


# ---------------------------------------------------------------------------
# technique ...
# ---------------------------------------------------------------------------

@tech_app.command("list")
def technique_list() -> None:
    """List all registered techniques."""
    Registry.load()
    table = Table(title="Techniques", show_lines=False)
    table.add_column("id")
    table.add_column("intrusiveness")
    table.add_column("produces")
    for tid in Registry.list_techniques():
        cls = Registry.get_technique(tid)
        table.add_row(
            tid,
            getattr(cls, "intrusiveness", "?"),
            ", ".join(sorted(getattr(cls, "produces", set()))) or "-",
        )
    console.print(table)


@tech_app.command("run")
def technique_run(
    technique_id: str = typer.Argument(...),
    target_spec: str = typer.Option(..., "--target", help="host:port"),
    scope_path: Path = typer.Option(..., "--scope", exists=True),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    """Run a single technique against a single target (host:port)."""
    sc = _load_scope(scope_path)
    cache = cache_dir or _default_cache_dir()
    profile = Profile(
        name="single",
        intrusiveness_max=sc.intrusiveness_max,
        enable=[technique_id],
        disable=[],
        options={},
    )
    runner = Runner(scope=sc, profile=profile, cache_dir=cache)
    report = asyncio.run(runner.run())
    out = _persist(report, cache)
    _print_summary(report, out)


# ---------------------------------------------------------------------------
# catalog ...
# ---------------------------------------------------------------------------

CATALOGS = Path(__file__).parent / "catalogs"


@catalog_app.command("list")
def catalog_list() -> None:
    table = Table(title="Catalogs")
    table.add_column("name")
    table.add_column("path")
    for p in sorted(CATALOGS.glob("*.yaml")):
        table.add_row(p.stem, str(p))
    console.print(table)


@catalog_app.command("show")
def catalog_show(name: str) -> None:
    p = CATALOGS / f"{name}.yaml"
    if not p.exists():
        console.print(f"[red]Catalog not found:[/red] {name}")
        raise typer.Exit(2)
    console.print(p.read_text())


# ---------------------------------------------------------------------------
# adapter ...
# ---------------------------------------------------------------------------

@adapter_app.command("list")
def adapter_list() -> None:
    Registry.load()
    table = Table(title="Adapters")
    table.add_column("group")
    table.add_column("kind")
    for group in ("ai_recon.adapters.siem",
                  "ai_recon.adapters.repo",
                  "ai_recon.adapters.secrets"):
        for kind in Registry.list_adapters(group):
            table.add_row(group.split(".")[-1], kind)
    console.print(table)


# ---------------------------------------------------------------------------
# report ...
# ---------------------------------------------------------------------------

@report_app.command("list")
def report_list(
    cache_dir: Path = typer.Option(None, "--cache-dir"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """List recent runs (most recent first)."""
    cache = cache_dir or _default_cache_dir()
    runs = _runs_dir(cache)
    if not runs.exists():
        console.print(f"[yellow]No runs at[/yellow] {runs}")
        return
    items = []
    for d in runs.iterdir():
        if not d.is_dir():
            continue
        rj = d / "report.json"
        if not rj.exists():
            continue
        try:
            r = Report.model_validate_json(rj.read_text())
            items.append((d.stat().st_mtime, d.name, r))
        except Exception:
            continue
    items.sort(reverse=True)
    table = Table(title=f"Runs in {runs}")
    table.add_column("run_id", style="cyan", no_wrap=True)
    table.add_column("profile")
    table.add_column("findings", justify="right")
    table.add_column("crit/high/med/low/info", justify="right")
    table.add_column("started", overflow="ellipsis")
    for _, rid, r in items[:limit]:
        c = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for f in r.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        table.add_row(
            rid,
            r.profile,
            str(len(r.findings)),
            f"{c['critical']}/{c['high']}/{c['medium']}/{c['low']}/{c['info']}",
            r.started_at.isoformat(timespec="seconds"),
        )
    console.print(table)


@report_app.command("show")
def report_show(
    run_id: str = typer.Argument(..., help="Run ID, or 'latest' for the most recent run."),
    fmt: str = typer.Option("html", "--format", "-f", help="html|md|json"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not auto-open in browser (html)."),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    """Render the visual HTML dashboard (default) and open it in the browser."""
    cache = cache_dir or _default_cache_dir()
    runs = _runs_dir(cache)
    if run_id == "latest":
        candidates = [d for d in runs.iterdir() if (d / "report.json").exists()] if runs.exists() else []
        if not candidates:
            console.print(f"[red]No runs found in[/red] {runs}")
            raise typer.Exit(2)
        run_id = max(candidates, key=lambda d: d.stat().st_mtime).name
        console.print(f"[dim]Resolved 'latest' → {run_id}[/dim]")

    run_dir = runs / run_id
    rj = run_dir / "report.json"
    if not rj.exists():
        console.print(f"[red]Report not found:[/red] {rj}")
        raise typer.Exit(2)

    if fmt == "json":
        console.print_json(rj.read_text())
        return
    if fmt == "md":
        md = run_dir / "report.md"
        if not md.exists():
            ReportEmitter(Report.model_validate_json(rj.read_text())).write_markdown(md)
        console.print(md.read_text())
        return
    if fmt != "html":
        console.print(f"[red]Unknown format:[/red] {fmt}")
        raise typer.Exit(2)

    # Always (re)render HTML so it reflects the latest renderer.
    rep = Report.model_validate_json(rj.read_text())
    html_path = run_dir / "report.html"
    ReportEmitter(rep).write_html(html_path)
    console.print(f"[green]Wrote:[/green] {html_path}")
    if not no_open:
        import webbrowser
        webbrowser.open(html_path.as_uri())


@report_app.command("open")
def report_open(
    run_id: str = typer.Argument("latest"),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    """Open the HTML report for a run (alias for `show --format html`)."""
    report_show(run_id=run_id, fmt="html", no_open=False, cache_dir=cache_dir)


@report_app.command("diff")
def report_diff(
    base_run_id: str,
    head_run_id: str,
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    cache = cache_dir or _default_cache_dir()
    base_p = _runs_dir(cache) / base_run_id / "report.json"
    head_p = _runs_dir(cache) / head_run_id / "report.json"
    if not base_p.exists() or not head_p.exists():
        console.print("[red]One of the reports does not exist[/red]")
        raise typer.Exit(2)
    base = Report.model_validate_json(base_p.read_text())
    head = Report.model_validate_json(head_p.read_text())
    diff = ReportEmitter.diff(base, head)
    console.print(json.dumps(diff, indent=2, default=str))


@report_app.command("export")
def report_export(
    run_id: str,
    fmt: str = typer.Option("sarif", "--format", help="sarif|md|json|html"),
    out: Path = typer.Option(..., "--out"),
    cache_dir: Path = typer.Option(None, "--cache-dir"),
) -> None:
    cache = cache_dir or _default_cache_dir()
    src = _runs_dir(cache) / run_id / "report.json"
    if not src.exists():
        console.print(f"[red]Run not found:[/red] {run_id}")
        raise typer.Exit(2)
    rep = Report.model_validate_json(src.read_text())
    em = ReportEmitter(rep)
    if fmt == "sarif":
        em.write_sarif(out)
    elif fmt == "md":
        em.write_markdown(out)
    elif fmt == "html":
        em.write_html(out)
    elif fmt == "json":
        em.write_json(out)
    else:
        console.print(f"[red]Unknown format:[/red] {fmt}")
        raise typer.Exit(2)
    console.print(f"[green]Wrote:[/green] {out}")


if __name__ == "__main__":  # pragma: no cover
    app()
