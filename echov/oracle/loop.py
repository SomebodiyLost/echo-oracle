from __future__ import annotations
import json
from pathlib import Path
import click
from rich.console import Console
from anthropic import Anthropic
from dotenv import load_dotenv

from echov.scope import ScopeGuard
from echov.models import Verdict
from echov.oracle.fetcher import fetch
from echov.oracle.loop_schema import RoundOutput
from echov.oracle.loop_prompts import LOOP_SYSTEM, program_block
from echov.oracle.client import DEFAULT_MODEL
from echov.oracle.analyze import load_run

load_dotenv(dotenv_path=".env")
console = Console()
MAX_ROUNDS = 6


def _host_of(url):
    h = url.split("://", 1)[-1].split("/", 1)[0]
    return h


def _extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    s, e = text.find("{"), text.rfind("}")
    return text[s:e + 1] if s != -1 and e != -1 else text


def run_hunt(run_path, scope_path, context, program_path=None, model=None, max_rounds=MAX_ROUNDS):
    findings, ports, tech = load_run(run_path)
    if not findings:
        console.print("[red]No findings in that run.[/]")
        return
    guard = ScopeGuard.from_yaml(scope_path)
    program_text = Path(program_path).read_text() if program_path else ""
    client = Anthropic()
    model = model or DEFAULT_MODEL

    history = [f"Target context: {context}",
               f"Technology: {', '.join(tech) if tech else 'unknown'}",
               f"Findings: {json.dumps([f.get('name') for f in findings])}"]
    collected = []

    for rnd in range(1, max_rounds + 1):
        console.print(f"\n[magenta]── Oracle round {rnd}/{max_rounds} ──[/]")
        user = ("\n".join(history) + program_block(program_text) +
                "\n\nReason and return your JSON decision for this round.")
        resp = client.messages.create(
            model=model, max_tokens=8000, system=LOOP_SYSTEM,
            messages=[{"role": "user", "content": user}])
        raw = "".join(b.text for b in resp.content if b.type == "text")
        try:
            out = RoundOutput.model_validate_json(_extract_json(raw))
        except Exception as e:
            console.print(f"[red]Could not parse round output ({e}). Stopping.[/]")
            break

        console.print(f"[dim]{out.thinking}[/]")
        if out.done or not out.proposed_fetches:
            console.print("\n[green]Oracle is done.[/]")
            console.print(out.final_summary or "(no summary)")
            break

        # scope-gate every proposed fetch — the hard floor
        approved = []
        for pf in out.proposed_fetches:
            dec = guard.check(_host_of(pf.url), "oracle")
            if dec.verdict == Verdict.ALLOW:
                approved.append(pf)
                console.print(f"  [green]ALLOW[/] {pf.url}  [dim]— {pf.reason}[/]")
            else:
                console.print(f"  [yellow]BLOCKED ({dec.verdict.value})[/] {pf.url}  "
                              f"[dim]— not cleared by scope guard; skipped[/]")

        if not approved:
            console.print("[yellow]Nothing cleared scope this round. Stopping.[/]")
            break

        # one human confirmation for the batch of in-scope read-only fetches
        if not click.confirm(f"\nFetch these {len(approved)} read-only URL(s)?", default=True):
            console.print("Stopped by you.")
            break

        for pf in approved:
            res = fetch(pf.url, method=pf.method)
            collected.append(res)
            status = res.get("status", res.get("error", "?"))
            ctype = res.get("content_type", "")
            console.print(f"    fetched {pf.url} → {status} {ctype}")
            snippet = (res.get("body", "") or "")[:1500]
            history.append(f"\nFetched {pf.url} (status {status}, {ctype}):\n{snippet}")

    out_path = Path(run_path) / "oracle_hunt.json"
    out_path.write_text(json.dumps(collected, indent=2))
    console.print(f"\nFetched content saved: [bold]{out_path}[/]")
