from __future__ import annotations
import json
from difflib import SequenceMatcher
from pathlib import Path
from typing import List
from pydantic import BaseModel
from rich.console import Console
from anthropic import Anthropic
from echov.oracle.client import OracleClient, OracleRefused, DEFAULT_MODEL, _extract_json
from echov.oracle.gpt_client import GPTOracleClient, GPTRefused, GPT_MODEL
from echov.oracle.analyze import load_run

console = Console()
PRIO_COLOR = {"high": "red", "medium": "yellow", "low": "green"}


class ReconciledLead(BaseModel):
    title: str
    found_by: str          # "both" | "A only" | "B only"
    agreed_priority: str
    note: str = ""


class Reconciliation(BaseModel):
    summary: str
    leads: List[ReconciledLead]


def _sim(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _score(a, b):
    s = _sim(a.get("title", ""), b.get("title", ""))
    oa, ob = a.get("owasp"), b.get("owasp")
    if oa and oa == ob and oa != "none":
        s += 0.35
    if a.get("wstg_category") and a.get("wstg_category") == b.get("wstg_category"):
        s += 0.25
    return s


def _match(a_leads, b_leads, thresh=0.5):
    used, pairs, only_a = set(), [], []
    for la in a_leads:
        best, best_i = 0, -1
        for i, lb in enumerate(b_leads):
            if i in used:
                continue
            sc = _score(la, lb)
            if sc > best:
                best, best_i = sc, i
        if best >= thresh:
            used.add(best_i); pairs.append((la, b_leads[best_i]))
        else:
            only_a.append(la)
    only_b = [lb for i, lb in enumerate(b_leads) if i not in used]
    return pairs, only_a, only_b


RECONCILE_SYS = """You are a senior security reviewer reconciling two independent
ASSESSMENTS (labeled A and B) of the same AUTHORIZED target. You reason only — you never
attack, exploit, or propose payloads.

Merge leads that describe the SAME underlying issue even when worded differently. For each
distinct issue, decide: was it found by 'both', 'A only', or 'B only'? Give the priority you
judge correct. In 'note', explain briefly — and when A and B assigned different severities,
say which you side with and why. Do not simply average or defer; use your own judgment.

Output ONLY JSON, no markdown:
{"summary":"...","leads":[{"title":"...","found_by":"both|A only|B only",
"agreed_priority":"high|medium|low","note":"..."}]}"""


def _reconcile(a_leads, b_leads, findings, model=None):
    client = Anthropic()
    model = model or DEFAULT_MODEL
    payload = {"assessment_A": a_leads, "assessment_B": b_leads}
    user = ("Target findings (names):\n" + json.dumps([f.get("name") for f in findings]) +
            "\n\nTwo independent assessments to reconcile:\n" + json.dumps(payload, indent=2) +
            "\n\nReturn the reconciliation JSON now.")
    text = ""
    with client.messages.stream(model=model, max_tokens=12000, system=RECONCILE_SYS,
                                messages=[{"role": "user", "content": user}]) as stream:
        for ev in stream.text_stream:
            text += ev
        final = stream.get_final_message()
    if final.stop_reason == "refusal" or not text.strip():
        raise RuntimeError("reconciler declined this run")
    return Reconciliation.model_validate_json(_extract_json(text))


def run_crosscheck(run_path, context, sonnet_model=None, gpt_model=None, reconcile=False):
    findings, ports, tech, _ = load_run(run_path)
    if not findings:
        console.print("[red]No findings in that run.[/]"); return

    console.print(f"[magenta]Cross-check[/] — [cyan]{sonnet_model or DEFAULT_MODEL}[/] + "
                  f"[cyan]{gpt_model or GPT_MODEL}[/]…")

    def to_dicts(a):
        return [l.model_dump() for l in a.leads]

    try:
        console.print("  running Claude…")
        s_leads = to_dicts(OracleClient(model=sonnet_model).analyze(context, findings, ports, tech))
    except Exception as e:
        console.print(f"[yellow]Claude side failed:[/] {e}. Stopping."); return
    try:
        console.print("  running GPT…")
        g_leads = to_dicts(GPTOracleClient(model=gpt_model).analyze(context, findings, ports, tech))
    except Exception as e:
        console.print(f"[yellow]GPT side failed:[/] {e}. Stopping."); return

    pairs, only_s, only_g = _match(s_leads, g_leads)
    console.print(f"\n[bold]Matched: {len(pairs)} agreed · {len(only_s)} only Claude · "
                  f"{len(only_g)} only GPT[/]\n")
    if pairs:
        console.print("[bold green]AGREED (higher confidence):[/]")
        for ls, lg in pairs:
            same = ls.get("priority") == lg.get("priority")
            prio = (f"[{PRIO_COLOR.get(ls['priority'],'white')}]{ls['priority'].upper()}[/]" if same
                    else f"[red]PRIORITY SPLIT[/] (Claude={ls.get('priority')}, GPT={lg.get('priority')})")
            console.print(f"  • {ls.get('title','')}  — {prio}")
    for label, leads in (("ONLY CLAUDE", only_s), ("ONLY GPT", only_g)):
        if leads:
            console.print(f"\n[bold yellow]{label} — verify manually:[/]")
            for l in leads:
                console.print(f"  • [{PRIO_COLOR.get(l.get('priority'),'white')}]"
                              f"{l.get('priority','?').upper()}[/] {l.get('title','')}")

    result = {"agreed": [{"claude": s, "gpt": g} for s, g in pairs],
              "only_claude": only_s, "only_gpt": only_g}

    if reconcile:
        console.print("\n[magenta]Reconciling (blind review of both analyses)…[/]")
        try:
            rec = _reconcile(s_leads, g_leads, findings, model=sonnet_model)
        except Exception as e:
            console.print(f"[yellow]Reconciliation failed:[/] {e}")
            rec = None
        if rec:
            console.print(f"\n[bold]Reconciled view[/]\n[dim]{rec.summary}[/]\n")
            for l in sorted(rec.leads, key=lambda x: {"high":0,"medium":1,"low":2}.get(x.agreed_priority,9)):
                fc = {"both": "green", "A only": "yellow", "B only": "yellow"}.get(l.found_by, "white")
                console.print(f"  [{PRIO_COLOR.get(l.agreed_priority,'white')}]"
                              f"{l.agreed_priority.upper()}[/]  {l.title}  [{fc}]({l.found_by})[/]")
                if l.note:
                    console.print(f"    [dim]{l.note}[/]")
            result["reconciliation"] = rec.model_dump()

    (Path(run_path) / "crosscheck.json").write_text(json.dumps(result, indent=2))
    console.print(f"\nSaved: [bold]{run_path}/crosscheck.json[/]")
