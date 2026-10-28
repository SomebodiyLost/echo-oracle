from __future__ import annotations
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from echov.oracle.client import OracleClient, OracleRefused, DEFAULT_MODEL
from echov.oracle.mock_client import MockOracleClient

console = Console()
PRIO_ORDER = {"high": 0, "medium": 1, "low": 2}
PRIO_COLOR = {"high": "red", "medium": "yellow", "low": "dim"}


def _read(run_path, name):
    p = Path(run_path) / name
    return json.loads(p.read_text()) if p.exists() else []


def latest_run_with_findings(base="data/runs"):
    """Newest run that actually has findings — skips detect-only runs."""
    for d in sorted(Path(base).glob("*"), reverse=True):
        if (d / "triaged.json").exists() or (d / "findings.json").exists():
            return d
    return None


def load_run(run_path):
    findings = _read(run_path, "triaged.json") or _read(run_path, "findings.json")
    ports = _read(run_path, "ports.json")
    tech = []
    for a in _read(run_path, "assets.json"):
        tech.extend(a.get("tech") or [])
    # NEW: pull in detection-tool outputs (whatweb/wafw00f/headers/testssl) as evidence
    detections = _read(run_path, "detections.json")
    for d in detections:
        items = d.get("items")
        if d.get("category") == "tech-fingerprint" and isinstance(items, list):
            tech.extend(t.get("name") for t in items if t.get("name"))
    return findings, ports, sorted(set(filter(None, tech))), detections


def load_fetched(run_path):
    p = Path(run_path) / "oracle_fetched.json"
    return json.loads(p.read_text()) if p.exists() else []


def render(analysis):
    console.print(Panel(analysis.summary, title="🔮 Oracle — assessment", border_style="magenta"))
    if analysis.surface_notes:
        console.print("\n[bold]Unexamined in-scope surface:[/]")
        for s in analysis.surface_notes:
            console.print(f"  • {s}")
    console.print("\n[bold]Leads — highest priority first:[/]")
    for lead in sorted(analysis.leads, key=lambda l: PRIO_ORDER.get(l.priority, 9)):
        c = PRIO_COLOR.get(lead.priority, "white")
        owasp = "" if lead.owasp == "none" else f"  [blue]{lead.owasp}[/]"
        console.print(f"\n[{c}]● {lead.priority.upper()}[/]  [bold]{lead.title}[/]  "
                      f"[dim]({lead.wstg_category})[/]{owasp}  [dim]conf {lead.confidence:.0%}[/]")
        if lead.method:
            console.print(f"  [cyan]Method:[/] {lead.method}")
        if lead.result:
            console.print(f"  [cyan]Result:[/] {lead.result}")
        if lead.inference:
            console.print(f"  [cyan]Inference:[/] {lead.inference}")
        if lead.readonly_next_step:
            console.print(f"  [green]Read-only check:[/] {lead.readonly_next_step}")
        if lead.human_test:
            console.print(f"  [yellow]You test by hand:[/] {lead.human_test}")
    if analysis.coverage:
        t = Table(title="WSTG coverage (what the evidence lets Oracle assess)")
        t.add_column("Category"); t.add_column("Assessable"); t.add_column("Note")
        for c in analysis.coverage:
            mark = "[green]yes[/]" if c.assessable else "[yellow]gap[/]"
            t.add_row(c.wstg_category, mark, c.note)
        console.print("\n"); console.print(t)


def run_analyze(run_path, context, model=None, mock=False):
    findings, ports, tech, detections = load_run(run_path)
    if not findings:
        console.print("[red]No findings in that run to analyze.[/] "
                      "Point --run at a scan+triage run, or run a scan first.")
        return None
    fetched = load_fetched(run_path)
    engine = "offline mock (free)" if mock else (model or DEFAULT_MODEL)
    bits = []
    if fetched: bits.append(f"{len(fetched)} fetched")
    if detections: bits.append(f"{len(detections)} detections")
    extra = f" (+ {', '.join(bits)})" if bits else ""
    console.print(f"[magenta]Oracle[/] assessing [bold]{len(findings)}[/] finding(s){extra} "
                  f"from {Path(run_path).name} with [cyan]{engine}[/]…")
    client = MockOracleClient() if mock else OracleClient(model=model)
    try:
        analysis = client.analyze(context, findings, ports, tech, fetched=fetched)
    except OracleRefused as e:
        console.print(f"[yellow]Oracle declined this run[/] — {e}.")
        return None
    except Exception as e:
        console.print(f"[red]Oracle analysis failed:[/] {e}")
        return None
    (Path(run_path) / "oracle_analysis.json").write_text(analysis.model_dump_json(indent=2))
    render(analysis)
    console.print(f"\nFull analysis: [bold]{run_path}/oracle_analysis.json[/]")
    return analysis
