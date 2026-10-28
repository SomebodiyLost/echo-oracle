from __future__ import annotations

import html
import json
from pathlib import Path

PRIO = {"high": ("#f2606a", "HIGH"), "medium": ("#f2b24c", "MEDIUM"), "low": ("#56d29a", "LOW")}
ORDER = {"high": 0, "medium": 1, "low": 2}


def _esc(s): return html.escape(str(s or ""))


def build(run_path):
    a = json.loads((Path(run_path) / "oracle_analysis.json").read_text())
    leads = sorted(a.get("leads", []), key=lambda l: ORDER.get(l.get("priority"), 9))
    notes = a.get("surface_notes", [])

    cards = []
    for l in leads:
        color, label = PRIO.get(l.get("priority", "low"), ("#8493a5", "?"))
        cards.append(f"""
      <div class="lead" style="border-left-color:{color}">
        <div class="lhead"><span class="prio" style="background:{color}1f;color:{color}">{label}</span>
          <span class="title">{_esc(l.get('title'))}</span>
          <span class="meta">{_esc(l.get('category'))} · {int(l.get('confidence',0)*100)}%</span></div>
        <p class="why"><b>Why:</b> {_esc(l.get('reasoning'))}</p>
        <p class="ro"><b>Read-only check:</b> {_esc(l.get('readonly_next_step'))}</p>
        <p class="ht"><b>Test by hand:</b> {_esc(l.get('human_test'))}</p>
      </div>""")

    notes_html = "".join(f"<li>{_esc(n)}</li>" for n in notes)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Oracle analysis</title><style>
:root{{box-sizing:border-box;padding-top:env(safe-area-inset-top,0);padding-bottom:env(safe-area-inset-bottom,0)}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0d1118;color:#e8edf4;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.6}}
.wrap{{max-width:860px;margin:0 auto;padding:clamp(20px,4vw,44px) clamp(16px,4vw,26px) 70px}}
h1{{font-size:clamp(28px,5vw,40px);letter-spacing:-.02em;margin:0 0 6px}}
.sum{{background:#141a24;border:1px solid #27303d;border-left:3px solid #8b7cf0;border-radius:10px;padding:16px 18px;margin:18px 0;font-size:15.5px}}
h2{{font-size:19px;font-weight:600;margin:34px 0 10px}}
.notes{{background:#141a24;border:1px solid #27303d;border-radius:10px;padding:8px 20px}}
.notes li{{margin:9px 0;font-size:14px;color:#b7c0cf}}
.lead{{background:#141a24;border:1px solid #27303d;border-left:3px solid;border-radius:10px;padding:16px 18px;margin:13px 0}}
.lhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}}
.prio{{font-size:11.5px;font-weight:700;padding:3px 10px;border-radius:20px}}
.title{{font-weight:600;font-size:16px}}
.meta{{color:#8493a5;font-size:12.5px;margin-left:auto}}
.lead p{{margin:9px 0;font-size:14px}}
.why b{{color:#e8edf4}} .ro b{{color:#5cc8f5}} .ht b{{color:#f2b24c}}
.ro,.ht{{color:#b7c0cf}}
footer{{margin-top:40px;padding-top:18px;border-top:1px solid #27303d;color:#5e6a7d;font-size:12.5px}}
</style></head><body><div class="wrap">
<h1>🔮 Oracle analysis</h1>
<div class="sum">{_esc(a.get('summary'))}</div>
<h2>Unexamined in-scope surface</h2>
<ul class="notes">{notes_html}</ul>
<h2>Leads — highest priority first</h2>
{''.join(cards)}
<footer>Oracle reasons and advises; a human reviews, runs read-only checks, and tests by hand. Authorized targets only.</footer>
</div></body></html>"""


def write(run_path, out_name="oracle_analysis.html"):
    out = Path(run_path) / out_name
    out.write_text(build(run_path))
    return out
