from __future__ import annotations
import sys
from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from echov.scope import ScopeGuard
from echov.models import Verdict
from echov import runner

console = Console()
COLOR = {Verdict.ALLOW: "green", Verdict.DENY: "red", Verdict.LEAD: "yellow"}
SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


@click.group()
def cli():
    """EchoV — authorized recon & triage."""


def _print_decisions(decisions, title):
    table = Table(title=title)
    for c in ("Verdict", "Host", "Stage", "Reason"):
        table.add_column(c)
    for d in decisions:
        table.add_row(f"[{COLOR[d.verdict]}]{d.verdict.value}[/]",
                      d.host, d.stage, d.rule)
    console.print(table)


@cli.command("scope-check")
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--target", "targets", multiple=True)
@click.option("--file", "file_path", default=None)
def scope_check(scope_path, targets, file_path):
    """Check hosts against the guard. Scans nothing."""
    guard = ScopeGuard.from_yaml(scope_path)
    hosts = list(targets)
    if file_path:
        hosts += [l.strip() for l in Path(file_path).read_text().splitlines() if l.strip()]
    if not hosts and not sys.stdin.isatty():
        hosts += [l.strip() for l in sys.stdin if l.strip()]
    if not hosts:
        raise click.UsageError("Give --target, --file, or pipe hosts via stdin.")
    _, decisions = guard.filter(hosts)
    _print_decisions(decisions, "EchoV scope check")
    c = Counter(d.verdict for d in decisions)
    console.print(f"{len(decisions)} checked — [green]{c[Verdict.ALLOW]} allowed[/], "
                  f"[red]{c[Verdict.DENY]} denied[/], [yellow]{c[Verdict.LEAD]} leads[/].")


@cli.command("scan")
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--domain", default=None, help="Root domain for subfinder discovery.")
@click.option("--target", "seeds", multiple=True, help="Seed a host directly (repeatable).")
@click.option("--no-nuclei", is_flag=True, help="Discovery only; skip the vuln scan.")
@click.option("--tags", default=None, help="Limit nuclei to these template tags.")
@click.option("--rate-limit", default=150, show_default=True)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option("--nmap", "nmap_profile", flag_value="100", default=None,
              help="OPT-IN port scan (top-100 ports). Off unless passed.")
@click.option("--nmap-ports", "nmap_profile", flag_value="1000",
              help="Opt-in port scan, top-1000 ports.")
@click.option("--nmap-all", "nmap_profile", flag_value="all",
              help="Opt-in port scan, ALL 65535 ports (loud — needs permission).")
def scan(scope_path, domain, seeds, no_nuclei, tags, rate_limit, yes, nmap_profile):
    """Run the recon pipeline against in-scope targets only."""
    guard = ScopeGuard.from_yaml(scope_path)
    allowed, decisions = runner.gather_candidates(guard, domain, list(seeds))
    _print_decisions(decisions, "Scope decisions (pre-scan)")

    if not allowed:
        console.print("[red]Nothing in scope to scan.[/] Check scope.yaml and targets.")
        return

    console.print(f"\n[bold]About to actively scan {len(allowed)} in-scope target(s):[/]")
    for a in allowed:
        console.print(f"  • {a}")
    if not yes and not click.confirm("Proceed?", default=False):
        console.print("Aborted. Nothing was scanned.")
        return

    if nmap_profile:
        console.print(f"[yellow]Port scanning ENABLED (--nmap, {nmap_profile} ports). "
                      "Confirm this target permits port scanning.[/]")
    console.print("\n[cyan]Probing live hosts (httpx)…[/]")
    r = runner.run_active(scope_path, allowed, decisions,
                          run_nuclei=not no_nuclei, rate_limit=rate_limit, tags=tags,
                          nmap_profile=nmap_profile)
    console.print(f"[green]{len(r['assets'])}[/] live host(s); "
                  f"scanning [green]{len(r['live_urls'])}[/] in-scope URL(s).")

    findings = r["findings"]
    if findings:
        sev = Counter(f.severity for f in findings)
        summary = ", ".join(f"{sev[s]} {s}" for s in SEV_ORDER if sev[s])
        console.print(f"\n[bold]{len(findings)} finding(s):[/] {summary}")
        table = Table(title="Findings (raw — not yet triaged)")
        for col in ("Severity", "Name", "Matched at"):
            table.add_column(col)
        for f in sorted(findings, key=lambda x: SEV_ORDER.index(x.severity)
                        if x.severity in SEV_ORDER else 99):
            table.add_row(f.severity, f.name, f.matched_at)
        console.print(table)
    else:
        console.print("No findings (or scan skipped).")

    console.print(f"\nSaved to [bold]{r['run_dir']}[/] "
                  "(scope_decisions.json, assets.json, findings.json)")


@cli.command("triage")
@click.option("--run", "run_dir", default=None, help="Run dir under data/runs/. Defaults to newest.")
@click.option("--context", default="Known-vulnerable practice lab (OWASP Juice Shop).",
              show_default=True)
@click.option("--model", default=None, help="Override the triage model.")
@click.option("--mock", is_flag=True, help="Use offline rule-based triage (no API key, no cost).")
def triage(run_dir, context, model, mock):
    """Triage a run's findings: real / false-positive / needs-review."""
    import json as _json
    from echov.triage.client import TriageClient, DEFAULT_MODEL
    from echov.triage.mock_client import MockTriageClient

    runs = sorted(Path("data/runs").glob("*"))
    if run_dir is None:
        if not runs:
            raise click.UsageError("No runs found. Run `echov scan` first.")
        run_path = runs[-1]
    else:
        run_path = Path(run_dir)

    findings = _json.loads((run_path / "findings.json").read_text())
    if not findings:
        console.print("No findings to triage in that run.")
        return

    engine = "offline mock (free)" if mock else (model or DEFAULT_MODEL)
    console.print(f"Triaging [bold]{len(findings)}[/] finding(s) from {run_path} "
                  f"with [cyan]{engine}[/]…")
    client = MockTriageClient() if mock else TriageClient(model=model)
    verdicts = client.triage(findings, context)

    triaged = []
    for i, f in enumerate(findings):
        v = verdicts.get(i)
        f["triage"] = v.model_dump() if v is not None else {
            "finding_index": i, "is_likely_false_positive": False,
            "confidence": 0.0, "adjusted_severity": f.get("severity", "info"),
            "reasoning": "Triage failed to parse — flagged for manual review.",
            "needs_human_review": True, "draft_writeup": None,
        }
        triaged.append(f)

    (run_path / "triaged.json").write_text(_json.dumps(triaged, indent=2))

    real = sum(1 for f in triaged if not f["triage"]["is_likely_false_positive"]
               and not f["triage"]["needs_human_review"])
    fp = sum(1 for f in triaged if f["triage"]["is_likely_false_positive"])
    review = sum(1 for f in triaged if f["triage"]["needs_human_review"])
    console.print(f"\n[bold]Triage complete:[/] [green]{real} likely real[/], "
                  f"[dim]{fp} false positive[/], [yellow]{review} need review[/].")

    table = Table(title="Triaged findings")
    for col in ("Adj Sev", "Name", "FP?", "Conf", "Review?", "Why"):
        table.add_column(col)
    for f in sorted(triaged, key=lambda x: SEV_ORDER.index(x["triage"]["adjusted_severity"])
                    if x["triage"]["adjusted_severity"] in SEV_ORDER else 99):
        t = f["triage"]
        table.add_row(t["adjusted_severity"], f["name"],
                      "yes" if t["is_likely_false_positive"] else "no",
                      f"{t['confidence']:.2f}",
                      "[yellow]yes[/]" if t["needs_human_review"] else "no",
                      (t["reasoning"][:70] + "…") if len(t["reasoning"]) > 70 else t["reasoning"])
    console.print(table)
    console.print(f"\nFull results: [bold]{run_path}/triaged.json[/]")


if __name__ == "__main__":
    cli()


@cli.command("report")
@click.option("--run", "run_dir", default=None, help="Run dir under data/runs/. Defaults to newest.")
def report(run_dir):
    """Generate a human-readable Markdown report from a triaged run."""
    from echov.report.render import write_report
    runs = sorted(Path("data/runs").glob("*"))
    if run_dir is None:
        if not runs:
            raise click.UsageError("No runs found.")
        run_path = runs[-1]
    else:
        run_path = Path(run_dir)
    if not (run_path / "triaged.json").exists():
        raise click.UsageError(f"No triaged.json in {run_path}. Run `echov triage` first.")
    out = write_report(run_path)
    console.print(f"[green]Report written:[/] [bold]{out}[/]")
    console.print(f"Read it:  [cyan]cat {out}[/]")


@cli.group("oracle")
def oracle():
    """Oracle — the reasoning engine (analyzes finished runs)."""


@oracle.command("analyze")
@click.option("--run", "run_dir", default=None, help="Run dir under data/runs/. Defaults to newest.")
@click.option("--context", default="Known-vulnerable practice lab (OWASP Juice Shop).", show_default=True)
@click.option("--model", default=None, help="Override Oracle's model (e.g. claude-opus-5-5).")
@click.option("--mock", is_flag=True, help="Offline reasoning — no API key, no cost.")
def oracle_analyze(run_dir, context, model, mock):
    """Reason over a finished run and surface prioritized leads."""
    from echov.oracle.analyze import run_analyze
    from echov.oracle.analyze import latest_run_with_findings
    if run_dir:
        run_path = Path(run_dir)
    else:
        run_path = latest_run_with_findings()
        if run_path is None:
            raise click.UsageError("No runs with findings found. Scan + triage first.")
    run_analyze(run_path, context, model=model, mock=mock)


@oracle.command("hunt")
@click.option("--run", "run_dir", default=None)
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--context", default="Known-vulnerable practice lab (OWASP Juice Shop).", show_default=True)
@click.option("--program", "program_path", default=None, help="Optional program.md of scope rules.")
@click.option("--model", default=None)
@click.option("--rounds", default=6, show_default=True, help="Max reasoning rounds.")
def oracle_hunt(run_dir, scope_path, context, program_path, model, rounds):
    """Bounded read-only investigate loop: Oracle proposes fetches, you approve, it re-reasons."""
    from echov.oracle.loop import run_hunt
    runs = sorted(Path("data/runs").glob("*"))
    if run_dir is None:
        if not runs:
            raise click.UsageError("No runs found.")
        run_path = runs[-1]
    else:
        run_path = Path(run_dir)
    run_hunt(run_path, scope_path, context, program_path=program_path, model=model, max_rounds=rounds)


@oracle.command("fetch")
@click.option("--run", "run_dir", default=None)
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
def oracle_fetch(run_dir, scope_path):
    """Run the read-only fetches Oracle proposed in its last analysis (scope-gated)."""
    import json as _json
    from echov.oracle.fetcher import fetch
    from echov.scope import ScopeGuard
    from echov.models import Verdict

    runs = sorted(Path("data/runs").glob("*"))
    run_path = Path(run_dir) if run_dir else (runs[-1] if runs else None)
    if run_path is None:
        raise click.UsageError("No runs found.")
    ap = run_path / "oracle_analysis.json"
    if not ap.exists():
        raise click.UsageError("No analysis yet. Run `echov oracle analyze` first.")
    proposed = _json.loads(ap.read_text()).get("proposed_fetches", [])
    if not proposed:
        console.print("Oracle proposed no fetches. Nothing to do.")
        return

    guard = ScopeGuard.from_yaml(scope_path)
    approved = []
    console.print("[bold]Oracle wants to fetch (read-only):[/]")
    for pf in proposed:
        host = pf["url"].split("://", 1)[-1].split("/", 1)[0]
        dec = guard.check(host, "oracle")
        if dec.verdict == Verdict.ALLOW:
            approved.append(pf)
            console.print(f"  [green]ALLOW[/] {pf['url']}  [dim]— {pf['reason']}[/]")
        else:
            console.print(f"  [yellow]BLOCKED ({dec.verdict.value})[/] {pf['url']}  "
                          "[dim]— not in scope; skipped[/]")
    if not approved:
        console.print("[yellow]Nothing cleared the scope guard.[/]")
        return
    if not click.confirm(f"\nFetch these {len(approved)} URL(s)?", default=True):
        console.print("Cancelled.")
        return

    existing = []
    fp = run_path / "oracle_fetched.json"
    if fp.exists():
        existing = _json.loads(fp.read_text())
    for pf in approved:
        res = fetch(pf["url"])
        existing.append(res)
        console.print(f"  fetched {pf['url']} → {res.get('status', res.get('error','?'))} "
                      f"{res.get('content_type','')}")
    fp.write_text(_json.dumps(existing, indent=2))
    console.print(f"\nSaved. Now run [cyan]echov oracle analyze[/] again — "
                  "Oracle will reason over what it just read.")


@oracle.command("report")
@click.option("--run", "run_dir", default=None)
def oracle_report(run_dir):
    """Render the latest Oracle analysis as a styled HTML page."""
    from echov.oracle.render_html import write
    runs = sorted(Path("data/runs").glob("*"))
    run_path = Path(run_dir) if run_dir else (runs[-1] if runs else None)
    if run_path is None or not (run_path / "oracle_analysis.json").exists():
        raise click.UsageError("No analysis found. Run `echov oracle analyze` first.")
    out = write(run_path)
    console.print(f"[green]Oracle report written:[/] [bold]{out}[/]")
    console.print(f"View it:  [cyan]grip {out} 0.0.0.0:6420[/]  → open http://localhost:6420")


@cli.command("detect")
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--target", "targets", multiple=True, help="Host/URL to fingerprint (repeatable).")
@click.option("--tools", "tool_names", default=None, help="Comma list; default = all installed.")
def detect(scope_path, targets, tool_names):
    """Run read-only detection tools (tech, WAF, TLS, headers) on in-scope targets."""
    import json as _json
    from datetime import datetime, timezone
    from echov.tools import registry

    if not targets:
        raise click.UsageError("Give at least one --target.")
    guard = ScopeGuard.from_yaml(scope_path)

    decisions, allowed = [], []
    for t in targets:
        host = t.split("://", 1)[-1].split("/", 1)[0]
        dec = guard.check(host, "detect")
        decisions.append((t, dec))
        if dec.verdict == Verdict.ALLOW:
            allowed.append(t)

    cmap = {Verdict.ALLOW: "green", Verdict.DENY: "red", Verdict.LEAD: "yellow"}
    table = Table(title="Scope decisions")
    for col in ("Verdict", "Target", "Reason"):
        table.add_column(col)
    for t, dec in decisions:
        table.add_row(f"[{cmap[dec.verdict]}]{dec.verdict.value}[/]", t, dec.rule)
    console.print(table)
    if not allowed:
        console.print("[red]Nothing in scope to run detection on.[/]")
        return

    which = [n.strip() for n in tool_names.split(",")] if tool_names else list(registry.DEFAULT_TOOLS)
    unknown = [n for n in which if n not in registry.TOOLS]
    if unknown:
        console.print(f"[yellow]Unknown tools ignored:[/] {', '.join(unknown)}")
    which = [n for n in which if n in registry.TOOLS]

    console.print(f"\n[bold]About to run {len(which)} detection tool(s) on {len(allowed)} target(s):[/]")
    for t in allowed:
        console.print(f"  • {t}")
    if not click.confirm("Proceed?", default=False):
        console.print("Aborted.")
        return

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    run_path = Path("data/runs") / ts
    run_path.mkdir(parents=True, exist_ok=True)

    results = []
    out_table = Table(title="Detection results")
    for col in ("Tool", "Target", "Result"):
        out_table.add_column(col)
    for t in allowed:
        for name in which:
            console.print(f"[cyan]running {name} on {t}…[/]")
            res = registry.TOOLS[name].run(t, run_path)
            res.setdefault("target", t)
            results.append(res)
            if res.get("skipped"):
                out_table.add_row(name, t, f"[dim]skipped — {res.get('reason','')}[/]")
            elif res.get("ok"):
                out_table.add_row(name, t, res.get("summary", ""))
            else:
                out_table.add_row(name, t, f"[red]error — {res.get('reason','')}[/]")
    (run_path / "detections.json").write_text(_json.dumps(results, indent=2))
    console.print(out_table)
    console.print(f"\nSaved to [bold]{run_path}/detections.json[/]")


@cli.command("assess")
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--target", "seeds", multiple=True, help="Host to assess (repeatable).")
@click.option("--domain", default=None, help="Root domain for subfinder discovery.")
@click.option("--tags", default="exposure,misconfig,tech", show_default=True)
@click.option("--nmap", "use_nmap", is_flag=True, help="Opt-in port scan.")
@click.option("--detect/--no-detect", default=True, help="Run detection tools (whatweb/wafw00f/headers).")
@click.option("--model", default=None)
@click.option("--mock", is_flag=True, help="Oracle uses free offline reasoning.")
@click.option("--context", default="Authorized assessment.", show_default=True)
@click.option("--yes", is_flag=True, help="Skip confirmations (lab only).")
def assess(scope_path, seeds, domain, tags, use_nmap, detect, model, mock, context, yes):
    """One-shot pipeline: scan -> triage -> detection -> Oracle assessment -> report."""
    from echov import runner
    from echov.scope import ScopeGuard
    from echov.oracle.analyze import run_analyze
    from echov.tools import registry
    import json as _json

    if not seeds and not domain:
        raise click.UsageError("Give --target or --domain.")
    guard = ScopeGuard.from_yaml(scope_path)
    allowed, decisions = runner.gather_candidates(guard, domain, list(seeds))
    if not allowed:
        console.print("[red]Nothing in scope to assess.[/]"); return
    console.print(f"[bold]Assess pipeline on {len(allowed)} in-scope target(s):[/]")
    for a in allowed:
        console.print(f"  • {a}")
    if not yes and not click.confirm("Proceed?", default=False):
        console.print("Aborted."); return

    # 1. scan
    console.print("\n[cyan]1/4 Scanning…[/]")
    r = runner.run_active(scope_path, allowed, decisions, run_nuclei=True,
                          tags=tags, nmap_profile=("100" if use_nmap else None))
    run_path = Path(r["run_dir"])
    console.print(f"  {len(r['findings'])} finding(s) · saved to {run_path.name}")

    # 2. triage
    console.print("[cyan]2/4 Triaging…[/]")
    from echov.triage.client import TriageClient
    from echov.triage.mock_client import MockTriageClient
    findings = _json.loads((run_path / "findings.json").read_text())
    if findings:
        tc = MockTriageClient() if mock else TriageClient(model=model)
        verdicts = tc.triage(findings, context)
        for i, f in enumerate(findings):
            v = verdicts.get(i)
            f["triage"] = v.model_dump() if v else {"adjusted_severity": f.get("severity","info"),
                "is_likely_false_positive": False, "needs_human_review": True, "confidence": 0.0,
                "reasoning": "triage unavailable", "draft_writeup": None}
        (run_path / "triaged.json").write_text(_json.dumps(findings, indent=2))

    # 3. detection tools (into the SAME run folder)
    if detect:
        console.print("[cyan]3/4 Detection tools…[/]")
        dets = []
        for t in allowed:
            for name in registry.DEFAULT_TOOLS:
                res = registry.TOOLS[name].run(t, run_path)
                res.setdefault("target", t); dets.append(res)
        (run_path / "detections.json").write_text(_json.dumps(dets, indent=2))
        console.print(f"  ran {len(registry.TOOLS)} tool(s) per target")

    # 4. Oracle
    console.print("[cyan]4/4 Oracle assessment…[/]")
    run_analyze(run_path, context, model=model, mock=mock)


@cli.command("assess")
@click.option("--scope", "scope_path", default="scope.yaml", show_default=True)
@click.option("--target", "seeds", multiple=True, help="Host to assess (repeatable).")
@click.option("--domain", default=None, help="Root domain for subfinder discovery.")
@click.option("--tags", default="exposure,misconfig,tech", show_default=True)
@click.option("--nmap", "use_nmap", is_flag=True, help="Opt-in port scan.")
@click.option("--detect/--no-detect", default=True, help="Run detection tools (whatweb/wafw00f/headers).")
@click.option("--model", default=None)
@click.option("--mock", is_flag=True, help="Oracle uses free offline reasoning.")
@click.option("--context", default="Authorized assessment.", show_default=True)
@click.option("--yes", is_flag=True, help="Skip confirmations (lab only).")
def assess(scope_path, seeds, domain, tags, use_nmap, detect, model, mock, context, yes):
    """One-shot pipeline: scan -> triage -> detection -> Oracle assessment -> report."""
    from echov import runner
    from echov.scope import ScopeGuard
    from echov.oracle.analyze import run_analyze
    from echov.tools import registry
    import json as _json

    if not seeds and not domain:
        raise click.UsageError("Give --target or --domain.")
    guard = ScopeGuard.from_yaml(scope_path)
    allowed, decisions = runner.gather_candidates(guard, domain, list(seeds))
    if not allowed:
        console.print("[red]Nothing in scope to assess.[/]"); return
    console.print(f"[bold]Assess pipeline on {len(allowed)} in-scope target(s):[/]")
    for a in allowed:
        console.print(f"  • {a}")
    if not yes and not click.confirm("Proceed?", default=False):
        console.print("Aborted."); return

    # 1. scan
    console.print("\n[cyan]1/4 Scanning…[/]")
    r = runner.run_active(scope_path, allowed, decisions, run_nuclei=True,
                          tags=tags, nmap_profile=("100" if use_nmap else None))
    run_path = Path(r["run_dir"])
    console.print(f"  {len(r['findings'])} finding(s) · saved to {run_path.name}")

    # 2. triage
    console.print("[cyan]2/4 Triaging…[/]")
    from echov.triage.client import TriageClient
    from echov.triage.mock_client import MockTriageClient
    findings = _json.loads((run_path / "findings.json").read_text())
    if findings:
        tc = MockTriageClient() if mock else TriageClient(model=model)
        verdicts = tc.triage(findings, context)
        for i, f in enumerate(findings):
            v = verdicts.get(i)
            f["triage"] = v.model_dump() if v else {"adjusted_severity": f.get("severity","info"),
                "is_likely_false_positive": False, "needs_human_review": True, "confidence": 0.0,
                "reasoning": "triage unavailable", "draft_writeup": None}
        (run_path / "triaged.json").write_text(_json.dumps(findings, indent=2))

    # 3. detection tools (into the SAME run folder)
    if detect:
        console.print("[cyan]3/4 Detection tools…[/]")
        dets = []
        for t in allowed:
            for name in registry.DEFAULT_TOOLS:
                res = registry.TOOLS[name].run(t, run_path)
                res.setdefault("target", t); dets.append(res)
        (run_path / "detections.json").write_text(_json.dumps(dets, indent=2))
        console.print(f"  ran {len(registry.TOOLS)} tool(s) per target")

    # 4. Oracle
    console.print("[cyan]4/4 Oracle assessment…[/]")
    run_analyze(run_path, context, model=model, mock=mock)


@oracle.command("crosscheck")
@click.option("--run", "run_dir", default=None)
@click.option("--context", default="Authorized assessment.", show_default=True)
@click.option("--sonnet-model", default=None, help="Override the Claude model.")
@click.option("--gpt-model", default=None, help="Override the GPT model.")
@click.option("--reconcile", is_flag=True, help="Add a blind reviewer pass that merges both analyses.")
def oracle_crosscheck(run_dir, context, sonnet_model, gpt_model, reconcile):
    """Run two models on the same run and flag where they agree vs disagree."""
    from echov.oracle.crosscheck import run_crosscheck
    from echov.oracle.analyze import latest_run_with_findings
    run_path = Path(run_dir) if run_dir else latest_run_with_findings()
    if run_path is None:
        raise click.UsageError("No runs with findings found.")
    run_crosscheck(run_path, context, sonnet_model=sonnet_model, gpt_model=gpt_model, reconcile=reconcile)
