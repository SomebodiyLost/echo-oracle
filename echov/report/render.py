from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from echov.severity import SEVERITY_RANK, normalize_severity

# Blend weights for the priority score, tuned to the thresholds in
# _priority_label. Kept local on purpose: this orders the queue and is a
# different scale from the canonical CVSS weighting in echov.severity.
SEV_WEIGHT = {"critical": 8, "high": 4, "medium": 3, "low": 2, "info": 1}


def _sev_key(sev):
    return -SEVERITY_RANK.get(normalize_severity(sev), 0)


def _priority(f):
    t = f["triage"]
    sev = SEV_WEIGHT.get(normalize_severity(t["adjusted_severity"]), 1)
    conf = t.get("confidence", 0.5)
    if t["needs_human_review"]:
        return sev * 2 + (1 - conf)
    return sev + conf


def _priority_label(score):
    if score >= 8:
        return "Investigate first"
    if score >= 5:
        return "Worth a look"
    if score >= 3:
        return "Low priority"
    return "Informational"


def _verdict_line(f):
    t = f["triage"]
    if t["needs_human_review"]:
        return "**Verify manually** - the AI could not confirm this from the evidence alone."
    if t["is_likely_false_positive"]:
        return "**Likely noise** - safe to ignore unless you have reason to doubt it."
    return "**Likely real** - review the write-up, then decide on reporting."


def _load(run_path):
    run_path = Path(run_path)
    def read(name):
        p = run_path / name
        return json.loads(p.read_text()) if p.exists() else []
    return read("triaged.json"), read("scope_decisions.json")


def _dedupe(decisions):
    seen = set()
    out = []
    for d in decisions:
        key = (d["host"], d["verdict"])
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def build_markdown(run_path, tool_name="Echo"):
    triaged, decisions = _load(run_path)
    decisions = _dedupe(decisions)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    for f in triaged:
        f["_score"] = _priority(f)

    review = [f for f in triaged if f["triage"]["needs_human_review"]]
    fp = [f for f in triaged if f["triage"]["is_likely_false_positive"] or (f["triage"]["adjusted_severity"] == "info" and not f["triage"]["needs_human_review"])]
    real = [f for f in triaged if f not in fp and not f["triage"]["needs_human_review"]]

    allowed = [d for d in decisions if d["verdict"] == "ALLOW"]
    leads = [d for d in decisions if d["verdict"] == "LEAD"]
    denied = [d for d in decisions if d["verdict"] == "DENY"]

    L = []
    L.append(f"# {tool_name} - Recon & Triage Report")
    L.append("")
    L.append(f"`{Path(run_path).name}`  ·  generated {now}")
    L.append("")
    L.append("> **Authorized testing only.** Every finding requires human review before any action. The AI triage assists judgment - it does not replace it, and nothing here has been exploited.")
    L.append("")
    L.append("---")
    L.append("")

    L.append("## At a glance")
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Need your attention** | **{len(review) + len(real)}** |")
    L.append(f"| Suppressed as noise | {len(fp)} |")
    L.append(f"| Total findings triaged | {len(triaged)} |")
    L.append(f"| Hosts scanned (in scope) | {len(allowed)} |")
    L.append(f"| Out-of-scope leads surfaced | {len(leads)} |")
    L.append(f"| Hosts blocked by scope guard | {len(denied)} |")
    L.append("")

    priority = sorted(review + real, key=lambda f: f["_score"], reverse=True)

    L.append("## Priority queue")
    L.append("")
    if not priority:
        L.append("*Nothing needs attention - all findings were informational or false positives.*")
        L.append("")
    else:
        L.append("Ordered by priority (severity blended with AI confidence).")
        L.append("")
        L.append("| Priority | Severity | Finding | Confidence |")
        L.append("|---|---|---|---|")
        for f in priority:
            t = f["triage"]
            sev = normalize_severity(t["adjusted_severity"]).upper()
            L.append(f"| {_priority_label(f['_score'])} | {sev} | {f['name']} | {t['confidence']:.0%} |")
        L.append("")

    L.append("## Details")
    L.append("")
    for f in priority:
        t = f["triage"]
        sev = normalize_severity(t["adjusted_severity"]).upper()
        L.append(f"### [{sev}] {f['name']}")
        L.append("")
        L.append(f"{_priority_label(f['_score'])}  ·  **{sev}**  ·  AI confidence **{t['confidence']:.0%}**")
        L.append("")
        L.append(_verdict_line(f))
        L.append("")
        L.append(f"**Where:** `{f.get('matched_at','')}`  ")
        L.append(f"**Why:** {t['reasoning']}")
        w = t.get("draft_writeup")
        if w:
            L.append("")
            L.append("<details><summary>Draft write-up (review before use)</summary>")
            L.append("")
            for label, key in [("Title", "title"), ("Summary", "summary"), ("Steps to reproduce", "steps_to_reproduce"), ("Impact", "impact"), ("Remediation", "remediation")]:
                if w.get(key):
                    L.append(f"**{label}:** {w[key]}")
                    L.append("")
            L.append("</details>")
        L.append("")
        L.append("---")
        L.append("")

    L.append("## Suppressed findings")
    L.append("")
    L.append(f"<details><summary>Show {len(fp)} findings classified as informational / noise</summary>")
    L.append("")
    for f in sorted(fp, key=lambda f: _sev_key(f["triage"]["adjusted_severity"])):
        t = f["triage"]
        sev = normalize_severity(t["adjusted_severity"])
        L.append(f"- **{f['name']}** ({sev}, {t['confidence']:.0%}) - {t['reasoning']}")
    L.append("")
    L.append("</details>")
    L.append("")

    L.append("## Scope decisions")
    L.append("")
    L.append("What the scope guard evaluated. Blocked and out-of-scope hosts were never scanned.")
    L.append("")
    if leads:
        L.append("### Out-of-scope leads - surfaced for your decision, NOT scanned")
        L.append("")
        L.append("*A root cause may point here. Report it to the program or request scope expansion - do not scan it yourself.*")
        L.append("")
        for d in leads:
            L.append(f"- `{d['host']}` - {d['rule']} *(found by: {d['stage']})*")
        L.append("")
    if denied:
        L.append("### Denied - explicitly excluded")
        L.append("")
        for d in denied:
            L.append(f"- `{d['host']}` - {d['rule']} *(found by: {d['stage']})*")
        L.append("")
    L.append("### Allowed and scanned")
    L.append("")
    for d in allowed:
        L.append(f"- `{d['host']}` - {d['rule']}")
    L.append("")

    return "\n".join(L)


def write_report(run_path, out_name="report.md", tool_name="Echo"):
    out = Path(run_path) / out_name
    out.write_text(build_markdown(run_path, tool_name=tool_name))
    return out
