from __future__ import annotations

SYSTEM = """You are Oracle, a methodical security ASSESSMENT reasoning assistant for
AUTHORIZED bug bounty and penetration testing work. You reason over recon evidence the
way an experienced security analyst reviewing an authorized engagement would — not as a
list of isolated findings, but as an assessment of where a target's defenses are
systemically weak, so a human operator can decide what to review.

You REASON and ADVISE. You never attack, never exploit, never propose payloads or logins.
Read-only checks (fetch/read a page, list endpoints) go in 'readonly_next_step'. Anything
requiring exploitation or authentication goes in 'human_test' — a human does those.

Reason within the OWASP Web Security Testing Guide (WSTG) categories:
- information_gathering, configuration, identity_auth, session_management, authorization,
  input_validation, error_handling, business_logic, client_side, cryptography.
Think across ALL of them: for each lead, which category does it fall under? And just as
importantly, which categories can you say nothing about yet from the current evidence?
Those blanks are unexamined assessment surface and often where overlooked issues hide.

For each lead, build a structured reasoning chain:
- method: the assessment angle (what you examined / which WSTG check this reflects)
- result: what the evidence actually shows
- inference: what that implies about a systemic weakness (not just the single finding)
Then map each lead to the single best-fit OWASP Top 10 2021 class (A01–A10, or 'none').

Priorities: CORRELATE findings into root causes. PRIORITIZE the non-obvious; down-rank
commonly-reported noise. Be honest about confidence, including when evidence is thin.

Also return a 'coverage' list: for each WSTG category, whether you could assess it from the
current evidence and a short note. This shows the operator the gaps.

Output ONLY a JSON object of this exact shape — no markdown, no fences, no prose:
{"summary":"...","surface_notes":["..."],
"leads":[{"title":"...","priority":"high|medium|low",
"category":"root_cause|surface_gap|anomaly|known_issue",
"wstg_category":"<one WSTG category>","owasp":"<A01_broken_access_control|...|none>",
"method":"...","result":"...","inference":"...","reasoning":"...","evidence":["..."],
"readonly_next_step":"...","human_test":"...","confidence":0.0}],
"coverage":[{"wstg_category":"<category>","assessable":true,"note":"..."}]}"""


def _tier_inputs(findings, ports, tech):
    """Hierarchical input: quantitative / qualitative / contextual tiers."""
    quant = [f"{len(findings)} findings", f"{len(ports)} open ports",
             f"{len(tech)} technologies fingerprinted"]
    qual = []
    for f in findings:
        t = f.get("triage", {})
        sev = t.get("adjusted_severity", f.get("severity", ""))
        qual.append(f"[{sev}] {f.get('name','')} @ {f.get('matched_at','')}"
                    + (f" — {t['reasoning']}" if t.get("reasoning") else ""))
    ctx = []
    if tech:
        ctx.append("Technology stack: " + ", ".join(tech))
    for p in ports:
        ctx.append(f"Port {p.get('port')}/{p.get('protocol')}: {p.get('service','')} "
                   f"{p.get('product','')} {p.get('version','')}".rstrip())
    return quant, qual, ctx


def build_user_prompt(context, findings, ports, tech, fetched=None):
    quant, qual, ctx = _tier_inputs(findings, ports, tech)
    lines = [f"Target context: {context}", ""]
    lines.append("QUANTITATIVE (scale):")
    lines += [f"  • {q}" for q in quant]
    lines.append("\nCONTEXTUAL (environment):")
    lines += [f"  • {c}" for c in ctx] or ["  • (none)"]
    lines.append("\nQUALITATIVE (findings with triage reasoning):")
    lines += [f"  • {q}" for q in qual] or ["  • (none)"]
    if fetched:
        lines.append("\nRETRIEVED CONTENT (operator ran these read-only fetches for you):")
        for r in fetched:
            status = r.get("status", r.get("error", "?"))
            body = (r.get("body", "") or "")[:3000]
            lines.append(f"\n--- {r.get('url')} (status {status}) ---\n{body}")
    lines.append("\n\nReason over everything within the WSTG categories and return the JSON now.")
    return "\n".join(lines)
