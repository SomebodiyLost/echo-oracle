"""Echo Oracle security console (Streamlit).

Reads a finished Echo run from data/runs/<run>/ and presents it as a
security dashboard: a letter-grade security level, an OWASP attack-surface
radar, WSTG methodology coverage, Oracle leads, and the generated reports.

Visual system: pitch-black canvas with an ambient purple/cyan glow,
near-black cards, Echo cyan + Oracle purple as the accent pair, and solid
semantic colors for severity and priority. Charts are inline SVG built as
HTML strings so they render consistently inside the custom cards.
"""
from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from echov.severity import SEVERITY_COLOR  # noqa: E402  (needs ROOT on sys.path)

st.set_page_config(page_title="Echo Oracle — Security Console", page_icon=None,
                   layout="wide", initial_sidebar_state="expanded")

RUNS = ROOT / "data" / "runs"

# ============================================================
# Palette
# ============================================================
ECHO, ORACLE = "#22d3ee", "#a78bfa"
GREEN, AMBER, RED = "#2ee6a6", "#ffb020", "#ff4d5e"
SEV = SEVERITY_COLOR
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
PRIO = {"high": RED, "medium": AMBER, "low": GREEN}
PRIO_ORDER = {"high": 0, "medium": 1, "low": 2}
STATUS = {"2xx": GREEN, "3xx": ECHO, "4xx": AMBER, "5xx": "#ff3b4e", "?": "#6b7280"}
OWASP = [("A01", "Access ctl"), ("A02", "Crypto"), ("A03", "Injection"), ("A04", "Design"),
         ("A05", "Misconfig"), ("A06", "Components"), ("A07", "Auth"), ("A08", "Integrity"),
         ("A09", "Logging"), ("A10", "SSRF")]
OWASP_IDX = {code: i for i, (code, _) in enumerate(OWASP)}

# ============================================================
# Styles
# ============================================================
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');

/* canvas */
.stApp {
  background:
    radial-gradient(900px circle at 88% -12%, rgba(167,139,250,.16), transparent 60%),
    radial-gradient(700px circle at -8% 18%, rgba(34,211,238,.07), transparent 60%),
    #000;
  font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
}
#MainMenu, footer { visibility:hidden; }
header[data-testid="stHeader"] { background:transparent; }
[data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] { visibility:hidden; }
.block-container { padding-top:1.6rem; padding-bottom:3rem; max-width:1320px; }
body, .stApp, p, span, div, label { color:#fff; }

/* sidebar: always open; the collapse control is removed so it cannot disappear */
section[data-testid="stSidebar"] {
  background:#07070b; border-right:1px solid rgba(255,255,255,.06);
  display:block !important; visibility:visible !important; transform:none !important;
  width:300px !important; min-width:300px !important; max-width:300px !important;
}
section[data-testid="stSidebar"] > div { width:300px !important; min-width:300px !important; }
[data-testid="stSidebarCollapseButton"], [data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"], section[data-testid="stSidebar"] button[kind="header"],
section[data-testid="stSidebar"] button[kind="headerNoPadding"] { display:none !important; }
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap:8px; }

.sb-brand { font-size:22px; font-weight:800; letter-spacing:-.01em; text-align:center; margin-top:4px; }
.sb-brand .e { color:#22d3ee; } .sb-brand .o { color:#a78bfa; }
.sb-sub { color:#6b7280; font-size:12px; text-align:center; padding-bottom:10px; margin-bottom:2px; }
.sb-h { color:#c3c9d4; font-size:11px; letter-spacing:.14em; text-transform:uppercase; font-weight:700;
        margin:0; padding:16px 0 10px; line-height:1.4; border-top:1px solid rgba(255,255,255,.08); }

/* sidebar nav + export: rounded rectangles, like the site's buttons */
section[data-testid="stSidebar"] .stButton, section[data-testid="stSidebar"] .stDownloadButton,
section[data-testid="stSidebar"] [data-testid="stButton"], section[data-testid="stSidebar"] [data-testid="stDownloadButton"] {
  width:100% !important; display:block;
}
section[data-testid="stSidebar"] .stButton button,
section[data-testid="stSidebar"] .stDownloadButton button {
  width:100% !important; display:flex; justify-content:center; align-items:center; text-align:center;
  height:42px; min-height:42px; background:#0c0b12; border:1px solid rgba(255,255,255,.09); border-radius:10px;
  color:#b4bcc9; padding:0 14px; font-weight:500; font-size:13.5px;
  box-shadow:0 0 18px rgba(167,139,250,.10);
  transition:border-color .2s, background .2s, transform .2s, box-shadow .2s;
}
section[data-testid="stSidebar"] .stButton button:hover,
section[data-testid="stSidebar"] .stDownloadButton button:hover {
  border-color:#5c6672; color:#fff; transform:translateY(-1px); box-shadow:0 0 22px rgba(167,139,250,.2);
}
section[data-testid="stSidebar"] .stButton button[kind="primary"],
section[data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
  background:rgba(167,139,250,.14); border-color:rgba(167,139,250,.6); color:#fff; font-weight:600;
  box-shadow:0 0 22px rgba(167,139,250,.32);
}
section[data-testid="stSidebar"] .stButton button p,
section[data-testid="stSidebar"] .stDownloadButton button p { margin:0; }
section[data-testid="stSidebar"] [data-baseweb="select"] > div {
  background:#0c0b12; border-radius:10px; border-color:rgba(255,255,255,.09);
  box-shadow:0 0 18px rgba(167,139,250,.10);
}

/* header */
.hd-title { font-size:28px; font-weight:700; letter-spacing:-.02em; }
.hd-sub { color:#8a93a3; font-size:13px; margin-top:4px; }
.pill { display:inline-flex; align-items:center; gap:7px; padding:5px 11px; border-radius:20px; font-size:12px;
        border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.03); color:#d6dbe4; margin-left:8px; }
.pill i { width:7px; height:7px; border-radius:50%; display:inline-block; }
.mono { font-family:"JetBrains Mono", ui-monospace, monospace; }

/* cards */
.card { position:relative; overflow:hidden; background:#0c0b12; border:1px solid rgba(255,255,255,.07);
        border-radius:16px; padding:18px 20px; margin-bottom:16px;
        box-shadow:0 14px 34px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.03); }
.card.fixed { height:312px; display:flex; flex-direction:column; }
.card.tall { min-height:336px; }
.card-h { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:12px; }
.card-h b { font-size:14.5px; font-weight:600; color:#fff; }
.card-h span { color:#6b7280; font-size:11.5px; }
.card-body { flex:1; display:flex; align-items:center; justify-content:center; min-height:0; }

/* stat tiles */
.stat { position:relative; overflow:hidden; background:#0c0b12; border:1px solid rgba(255,255,255,.07);
        border-radius:16px; padding:16px 18px; display:flex; flex-direction:column; gap:10px; min-height:118px;
        box-shadow:0 14px 34px rgba(0,0,0,.5); }
.stat-top { display:flex; align-items:center; gap:10px; }
.stat-ico { width:30px; height:30px; border-radius:50%; display:grid; place-items:center; flex:none; }
.stat-ico svg { width:15px; height:15px; }
.stat-l { color:#8a93a3; font-size:12px; font-weight:500; }
.stat-v { font-size:30px; font-weight:700; line-height:1; font-variant-numeric:tabular-nums; }
.stat-s { color:#6b7280; font-size:12px; }

/* list rows */
.lrow { display:flex; align-items:center; gap:12px; padding:11px 0; border-top:1px solid rgba(255,255,255,.06); }
.lrow:first-of-type { border-top:none; padding-top:2px; }
.lico { width:36px; height:36px; border-radius:9px; display:grid; place-items:center; flex:none;
        font-family:"JetBrains Mono",monospace; font-size:9.5px; font-weight:800; letter-spacing:.04em; }
.ltxt { flex:1; min-width:0; }
.ltitle { font-size:13.5px; color:#fff; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.lsub { font-size:11.5px; color:#6b7280; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.lmeta { font-size:11px; color:#8a93a3; font-family:"JetBrains Mono",monospace; white-space:nowrap; }
.row { display:flex; align-items:center; gap:12px; padding:11px 0; border-top:1px solid rgba(255,255,255,.06); }
.row:first-of-type { border-top:none; }
.badge { font-size:10.5px; font-weight:800; padding:3px 9px; border-radius:20px; white-space:nowrap; }
.chip { font-size:10.5px; font-weight:800; padding:3px 8px; border-radius:5px; white-space:nowrap; }
.tag { color:#22d3ee; font-size:11px; font-family:"JetBrains Mono",monospace; }
.title { color:#fff; font-size:13.5px; flex:1; }
.rule { color:#8a93a3; font-size:11px; }

/* severity list beside the grade gauge */
.sevlist { display:flex; flex-direction:column; gap:9px; min-width:118px; }
.sevrow { display:flex; align-items:center; gap:9px; }
.sevrow i { width:8px; height:8px; border-radius:50%; display:inline-block; }
.sevrow .n { font-size:17px; font-weight:700; font-variant-numeric:tabular-nums; min-width:22px; }
.sevrow .l { font-size:12px; color:#9aa3b2; text-transform:capitalize; }

.legend-item { display:block; font-size:13px; color:#d6dbe4; margin:8px 0; }
.legend-dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:9px; vertical-align:middle; }
.muted-note { color:#6b7280; font-size:12.5px; }
</style>""", unsafe_allow_html=True)


# ============================================================
# Data
# ============================================================
def list_runs():
    """Run folders that contain findings, newest first."""
    return [d for d in sorted(RUNS.glob("*"), reverse=True)
            if (d / "triaged.json").exists() or (d / "findings.json").exists()]


def read(run, name):
    """Read a JSON artifact from a run folder; missing or malformed files read as empty."""
    p = run / name
    try:
        return json.loads(p.read_text()) if p.exists() else []
    except Exception:
        return []


def security_score(leads, findings):
    """0-100 score: Oracle lead priorities when present, otherwise finding severities."""
    pen = 0
    for l in leads:
        pen += {"high": 20, "medium": 8, "low": 2}.get(l.get("priority"), 0)
    if not leads:
        for f in findings:
            s = f.get("triage", {}).get("adjusted_severity", f.get("severity", "info"))
            pen += {"critical": 25, "high": 15, "medium": 6, "low": 2}.get(s, 0)
    return max(0, 100 - pen)


def grade_of(score):
    """Letter grade, risk label, and the gradient pair used for the gauge arc."""
    if score >= 90:
        return "A", "Low risk", GREEN, ECHO
    if score >= 80:
        return "B", "Moderate risk", ECHO, ORACLE
    if score >= 65:
        return "C", "Elevated risk", "#ffd54a", AMBER
    if score >= 50:
        return "D", "High risk", AMBER, "#ff6a3d"
    return "F", "Very high risk", "#ff6a3d", SEV["critical"]


# ============================================================
# Charts (inline SVG)
# ============================================================
_uid = 0


def _nid():
    """Unique id for per-chart SVG defs."""
    global _uid
    _uid += 1
    return f"g{_uid}"


def _glow(nid, sd=2.4):
    return (f'<filter id="{nid}-glow" x="-40%" y="-40%" width="180%" height="180%">'
            f'<feGaussianBlur stdDeviation="{sd}" result="b"/><feMerge><feMergeNode in="b"/>'
            f'<feMergeNode in="SourceGraphic"/></feMerge></filter>')


def _mix(a, b, t):
    """Linear blend of two hex colors."""
    ah, bh = int(a[1:], 16), int(b[1:], 16)
    ch = [round(((ah >> s) & 255) * (1 - t) + ((bh >> s) & 255) * t) for s in (16, 8, 0)]
    return "#%02x%02x%02x" % tuple(ch)


def grade_ring(score, size=168):
    """Score arc in the grade's gradient with the letter grade in the center."""
    g, label, c1, c2 = grade_of(score)
    nid = _nid()
    stroke = 9
    r = (100 - stroke) / 2 - 3
    c = 2 * math.pi * r
    frac = max(0.0, min(1.0, score / 100))
    arc = (f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="url(#{nid})" stroke-width="{stroke}" '
           f'stroke-linecap="round" transform="rotate(-90 50 50)" stroke-dasharray="{c*frac:.1f} {c:.1f}" '
           f'filter="url(#{nid}-glow)"/>') if frac > 0 else ""
    return (f'<svg viewBox="0 0 100 100" style="width:{size}px;height:{size}px;display:block;overflow:visible">'
            f'<defs><linearGradient id="{nid}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient>{_glow(nid)}</defs>'
            f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="{stroke}"/>'
            f'{arc}'
            f'<text x="50" y="47" text-anchor="middle" fill="#fff" font-family="Inter,system-ui,sans-serif" '
            f'font-size="30" font-weight="800">{g}</text>'
            f'<text x="50" y="60" text-anchor="middle" fill="#9aa3b2" font-family="Inter,system-ui,sans-serif" '
            f'font-size="7.2">{label}</text>'
            f'<text x="50" y="70" text-anchor="middle" fill="#6b7280" font-family="JetBrains Mono,monospace" '
            f'font-size="6.5">{score} / 100</text></svg>')


def sev_side(counts):
    """Severity counts stacked beside the gauge; zero rows are dimmed, never hidden."""
    rows = ""
    for k in SEV_ORDER:
        v = counts.get(k, 0)
        col = SEV.get(k, "#6b7280")
        dim = "" if v else "opacity:.42;"
        rows += (f'<div class="sevrow" style="{dim}"><i style="background:{col};box-shadow:0 0 8px {col}"></i>'
                 f'<span class="n">{v}</span><span class="l">{k}</span></div>')
    return f'<div class="sevlist">{rows}</div>'


def radar_svg(values, labels, W=300, H=236):
    """Attack-surface radar: one axis per OWASP Top 10 category."""
    n = len(values)
    cx, cy, R = W / 2, H / 2 + 4, min(W, H) * 0.36
    mx = max(max(values), 1)
    nid = _nid()

    def pt(i, rr):
        a = -math.pi / 2 + 2 * math.pi * i / n
        return cx + rr * math.cos(a), cy + rr * math.sin(a)

    out = [f'<svg viewBox="0 0 {W} {H}" style="width:100%;max-width:{W}px;height:auto;display:block;overflow:visible">',
           f'<defs>{_glow(nid, 3)}</defs>']
    for lvl in (0.33, 0.66, 1.0):
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in (pt(i, R * lvl) for i in range(n)))
        out.append(f'<polygon points="{pts}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="1"/>')
    for i, lab in enumerate(labels):
        x, y = pt(i, R)
        out.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{x:.1f}" y2="{y:.1f}" stroke="rgba(255,255,255,.06)"/>')
        lx, ly = pt(i, R + 16)
        anchor = "middle" if abs(lx - cx) < 8 else ("start" if lx > cx else "end")
        out.append(f'<text x="{lx:.1f}" y="{ly + 3:.1f}" text-anchor="{anchor}" fill="#8a93a3" '
                   f'font-family="Inter,system-ui,sans-serif" font-size="8.5">{lab}</text>')
    if any(values):
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in (pt(i, R * (v / mx)) for i, v in enumerate(values)))
        out.append(f'<polygon points="{pts}" fill="rgba(167,139,250,.22)" stroke="#a78bfa" stroke-width="1.8" '
                   f'stroke-linejoin="round" filter="url(#{nid}-glow)"/>')
        for i, v in enumerate(values):
            if v:
                x, y = pt(i, R * (v / mx))
                out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#0c0b12" stroke="#a78bfa" stroke-width="1.6"/>')
    out.append("</svg>")
    return "".join(out)


def tick_ring(frac, big, sub, size=150, ticks=40):
    """Segmented ring: filled ticks run cyan to purple with a glow."""
    nid = _nid()
    filled = round(max(0.0, min(1.0, frac)) * ticks)
    lit, dim = [], []
    for i in range(ticks):
        a = 2 * math.pi * i / ticks - math.pi / 2
        x1, y1 = 50 + 38 * math.cos(a), 50 + 38 * math.sin(a)
        x2, y2 = 50 + 46 * math.cos(a), 50 + 46 * math.sin(a)
        seg = f'x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke-width="3" stroke-linecap="round"'
        if i < filled:
            lit.append(f'<line {seg} stroke="{_mix(ECHO, ORACLE, i / max(1, ticks - 1))}"/>')
        else:
            dim.append(f'<line {seg} stroke="rgba(255,255,255,.09)"/>')
    return (f'<svg viewBox="0 0 100 100" style="width:{size}px;height:{size}px;display:block;overflow:visible">'
            f'<defs>{_glow(nid, 1.6)}</defs><g>{"".join(dim)}</g><g filter="url(#{nid}-glow)">{"".join(lit)}</g>'
            f'<text x="50" y="52" text-anchor="middle" fill="#fff" font-family="Inter,system-ui,sans-serif" '
            f'font-size="20" font-weight="700">{big}</text>'
            f'<text x="50" y="63" text-anchor="middle" fill="#9aa3b2" font-family="JetBrains Mono,monospace" '
            f'font-size="6.5" letter-spacing="0.1em">{sub}</text></svg>')


def donut_svg(counts, palette, center_label, size=150):
    """Multi-segment donut in solid semantic colors with a soft glow."""
    counts = {k: v for k, v in counts.items() if v}
    total = sum(counts.values())
    if total == 0:
        return '<div class="muted-note">No data to chart.</div>'
    nid = _nid()
    stroke = 15
    r = (100 - stroke) / 2 - 2
    c = 2 * math.pi * r
    segs, acc = [], 0.0
    for k, v in counts.items():
        frac = v / total
        col = palette.get(k, "#6b7280")
        segs.append(f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="{col}" stroke-width="{stroke}" '
                    f'stroke-dasharray="{c*frac:.2f} {c:.2f}" stroke-dashoffset="{-(acc*c):.2f}" '
                    f'transform="rotate(-90 50 50)"/>')
        acc += frac
    legend = "".join(f'<span class="legend-item"><span class="legend-dot" style="background:{palette.get(k, "#6b7280")}">'
                     f'</span>{k} · {v}</span>' for k, v in counts.items())
    svg = (f'<svg viewBox="0 0 100 100" style="width:{size}px;height:{size}px;flex:none;display:block;overflow:visible">'
           f'<defs>{_glow(nid, 1.4)}</defs>'
           f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="{stroke}"/>'
           f'<g filter="url(#{nid}-glow)">{"".join(segs)}</g>'
           f'<text x="50" y="47" text-anchor="middle" fill="#fff" font-family="Inter,system-ui,sans-serif" '
           f'font-size="19" font-weight="700">{total}</text>'
           f'<text x="50" y="59" text-anchor="middle" fill="#9aa3b2" font-size="7.5" letter-spacing="0.08em">'
           f'{center_label}</text></svg>')
    return f'<div style="display:flex;align-items:center;gap:22px;flex-wrap:wrap">{svg}<div>{legend}</div></div>'


# ============================================================
# UI helpers
# ============================================================
ICONS = {
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/></svg>',
    "list":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
    "alert":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/></svg>',
    "grid":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    "server": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
    "globe":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/></svg>',
}


def stat(col, label, value, sub="", icon="shield", color=ORACLE):
    """A stat tile: tinted icon circle, label, big number, footnote."""
    col.markdown(
        f'<div class="stat">'
        f'<div class="stat-top"><span class="stat-ico" style="background:{color}22;color:{color}">{ICONS[icon]}</span>'
        f'<span class="stat-l">{label}</span></div>'
        f'<div class="stat-v" style="color:{color}">{value}</div>'
        f'<div class="stat-s">{sub}</div></div>', unsafe_allow_html=True)


def card(title, inner, meta="", cls="", center=True):
    """A titled card; fixed-height cards center their content."""
    meta_html = f"<span>{meta}</span>" if meta else ""
    body = f'<div class="card-body">{inner}</div>' if center else f"<div>{inner}</div>"
    return f'<div class="card {cls}"><div class="card-h"><b>{title}</b>{meta_html}</div>{body}</div>'


def wide_button(container, label, key, kind):
    """Full-width button; supports both the new and the old Streamlit width parameter."""
    try:
        return container.button(label, key=key, type=kind, width="stretch")
    except TypeError:
        return container.button(label, key=key, type=kind, use_container_width=True)


def wide_download(container, label, data, file_name, key, mime=None):
    """Full-width download button with the same version fallback."""
    kw = {"file_name": file_name, "key": key}
    if mime:
        kw["mime"] = mime
    try:
        return container.download_button(label, data, width="stretch", **kw)
    except TypeError:
        return container.download_button(label, data, use_container_width=True, **kw)


def severity_of(f):
    """Triage-adjusted severity of a finding, falling back to the scanner label."""
    return f.get("triage", {}).get("adjusted_severity", f.get("severity", "info"))


# ============================================================
# Sidebar: brand + run picker
# ============================================================
st.sidebar.markdown('<div class="sb-brand"><span class="e">Echo</span> <span class="o">Oracle</span></div>'
                    '<div class="sb-sub">Security assessment console</div>', unsafe_allow_html=True)
runs = list_runs()
if not runs:
    st.warning("No runs with findings yet. Run `python -m echov assess` first.")
    st.stop()
st.sidebar.markdown('<div class="sb-h">Assessment</div>', unsafe_allow_html=True)
choice = st.sidebar.selectbox("Run", runs, format_func=lambda p: p.name, label_visibility="collapsed")

# ============================================================
# Load the selected run
# ============================================================
findings = read(choice, "triaged.json") or read(choice, "findings.json")
analysis = {}
if (choice / "oracle_analysis.json").exists():
    try:
        analysis = json.loads((choice / "oracle_analysis.json").read_text())
    except Exception:
        analysis = {}
leads = analysis.get("leads", [])
coverage = analysis.get("coverage", [])
assets = read(choice, "assets.json")
detections = read(choice, "detections.json")

seen, dec = set(), []
for d in read(choice, "scope_decisions.json"):
    k = (d.get("host"), d.get("verdict"))
    if k not in seen:
        seen.add(k)
        dec.append(d)
allowed = [d for d in dec if d.get("verdict") == "ALLOW"]
leads_hi = [l for l in leads if l.get("priority") in ("high", "medium")]

assessable = sum(1 for c in coverage if c.get("assessable"))
cov_pct = f"{round(100 * assessable / len(coverage))}%" if coverage else "—"
cov_frac = (assessable / len(coverage)) if coverage else 0.0
score = security_score(leads, findings)
grade, grade_label, _, grade_color = grade_of(score)
hi_plus = sum(1 for f in findings if severity_of(f) in ("high", "critical"))
sev_counts = {k: 0 for k in SEV_ORDER}
for f in findings:
    s = severity_of(f)
    sev_counts[s if s in sev_counts else "info"] += 1

md_path = choice / "report.md"
html_path = choice / "oracle_analysis.html"
json_path = choice / "oracle_analysis.json"

# ============================================================
# Sidebar: views, export, session
# ============================================================
st.sidebar.markdown('<div class="sb-h">Views</div>', unsafe_allow_html=True)
VIEWS = ["Overview", "Activity", "Leads", "Scope & coverage", "Report"]
nav_counts = {"Activity": len(findings), "Leads": len(leads), "Scope & coverage": len(dec)}
if "view" not in st.session_state:
    st.session_state.view = "Overview"
for v in VIEWS:
    label = f"{v}  ·  {nav_counts[v]}" if nav_counts.get(v) else v
    kind = "primary" if st.session_state.view == v else "secondary"
    if wide_button(st.sidebar, label, f"nav_{v}", kind):
        st.session_state.view = v
        st.rerun()
view = st.session_state.view

st.sidebar.markdown('<div class="sb-h">Export</div>', unsafe_allow_html=True)
if md_path.exists():
    wide_download(st.sidebar, "Markdown report", md_path.read_text(), "report.md", "sb_md")
if html_path.exists():
    wide_download(st.sidebar, "Oracle report (HTML)", html_path.read_text(),
                  "oracle_analysis.html", "sb_html", mime="text/html")
if json_path.exists():
    wide_download(st.sidebar, "Analysis (JSON)", json_path.read_text(),
                  "oracle_analysis.json", "sb_json", mime="application/json")
if not (md_path.exists() or html_path.exists() or json_path.exists()):
    st.sidebar.caption("Run `python -m echov report` to generate exports.")

st.sidebar.markdown('<div class="sb-h">Session</div>', unsafe_allow_html=True)
auto = st.sidebar.checkbox("Auto-refresh (5s)")
st.sidebar.caption(f"{len(runs)} assessment(s) on disk")

# ============================================================
# Header
# ============================================================
h1, h2 = st.columns([3, 2])
h1.markdown('<div class="hd-title">Security Dashboard</div>'
            '<div class="hd-sub">Echo gathers · Oracle reasons · a human decides</div>', unsafe_allow_html=True)
h2.markdown(f'<div style="text-align:right;padding-top:12px">'
            f'<span class="pill"><i style="background:{GREEN};box-shadow:0 0 8px {GREEN}"></i>authorized</span>'
            f'<span class="pill mono">{choice.name}</span></div>', unsafe_allow_html=True)
st.write("")

# ============================================================
# Views
# ============================================================
if view == "Overview":
    c = st.columns(5)
    stat(c[0], "Security score", f"{score}", f"grade {grade} · {grade_label.lower()}", "shield", grade_color)
    stat(c[1], "Findings", f"{len(findings)}", f"{hi_plus} high or critical", "list", ORACLE)
    stat(c[2], "Need attention", f"{len(leads_hi)}", "high + medium leads", "alert", AMBER)
    stat(c[3], "WSTG coverage", cov_pct,
         f"{assessable}/{len(coverage)} categories" if coverage else "run Oracle", "grid", ORACLE)
    stat(c[4], "Hosts scanned", f"{len(allowed)}", "in scope · guard verified", "server", ECHO)
    st.write("")

    # hero row: security level, attack surface, methodology coverage
    g1, g2, g3 = st.columns([1.15, 1.25, 1])
    gauge = f'<div style="display:flex;align-items:center;gap:22px">{grade_ring(score)}{sev_side(sev_counts)}</div>'
    g1.markdown(card("Security level", gauge, meta=f"{len(findings)} findings", cls="fixed"), unsafe_allow_html=True)

    vals = [0] * len(OWASP)
    for l in leads:
        code = str(l.get("owasp") or "")[:3].upper()
        if code in OWASP_IDX:
            vals[OWASP_IDX[code]] += 1
    radar_meta = f"{len(leads)} leads · OWASP Top 10" if leads else "run Oracle to map"
    g2.markdown(card("Attack surface map", radar_svg(vals, [f"{c} {n}" for c, n in OWASP]),
                     meta=radar_meta, cls="fixed"), unsafe_allow_html=True)

    cov_note = f"{assessable} of {len(coverage)} categories assessed" if coverage else "run Oracle to populate"
    cov_inner = (f'<div style="text-align:center">{tick_ring(cov_frac, cov_pct, "WSTG")}'
                 f'<div class="muted-note" style="margin-top:6px">{cov_note}</div></div>')
    g3.markdown(card("Methodology coverage", cov_inner, meta="OWASP WSTG", cls="fixed"), unsafe_allow_html=True)
    st.write("")

    # leads row
    left, right = st.columns([3, 2])
    rows = ""
    for l in sorted(leads, key=lambda x: PRIO_ORDER.get(x.get("priority"), 9))[:5]:
        pr = l.get("priority") or "?"
        col = PRIO.get(pr, "#6b7280")
        abbr = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(pr, "?")
        sub = " · ".join(x for x in (l.get("wstg_category", ""), l.get("owasp", "")) if x)
        cat = str(l.get("category", "")).replace("_", " ")
        rows += (f'<div class="lrow"><span class="lico" style="background:{col}1f;color:{col};box-shadow:0 0 12px {col}33">{abbr}</span>'
                 f'<div class="ltxt"><div class="ltitle">{l.get("title", "")}</div><div class="lsub">{sub}</div></div>'
                 f'<span class="lmeta">{cat}</span></div>')
    rows = rows or '<div class="muted-note">No Oracle leads — run <code>python -m echov oracle analyze</code>.</div>'
    left.markdown(card("Top leads", rows, meta=f"{len(leads)} total", cls="tall", center=False), unsafe_allow_html=True)

    pcounts = {p: sum(1 for l in leads if l.get("priority") == p) for p in ("high", "medium", "low")}
    pinner = donut_svg(pcounts, PRIO, "leads") if any(pcounts.values()) else '<div class="muted-note">No leads yet.</div>'
    right.markdown(card("Risk by priority", pinner, meta="Oracle leads", cls="tall"), unsafe_allow_html=True)

elif view == "Activity":
    st.caption("Real data from this run — Echo does targeted recon, so volumes are small by design, not inflated.")
    endpoints = {}
    for f in findings:
        u = f.get("matched_at") or ""
        if u:
            endpoints[u] = severity_of(f)
    sclass = {}
    for a in assets:
        code = a.get("status_code")
        if code:
            k = f"{str(code)[0]}xx"
            sclass[k] = sclass.get(k, 0) + 1
    servers = {}
    for d in detections:
        if d.get("category") == "security-headers":
            srv = (d.get("items") or {}).get("server", "")
            if srv:
                servers[srv] = servers.get(srv, 0) + 1

    c = st.columns(4)
    stat(c[0], "Hosts probed", f"{len(allowed)}", "in scope", "server", ECHO)
    stat(c[1], "Live hosts", f"{len(assets)}", "responded", "globe", GREEN)
    stat(c[2], "Endpoints", f"{len(endpoints)}", "observed", "grid", ORACLE)
    stat(c[3], "Findings", f"{len(findings)}", f"{hi_plus} high or critical", "list", ORACLE)
    st.write("")
    a, b = st.columns(2)
    a.markdown(card("Status codes", donut_svg(sclass, STATUS, "hosts"), meta="httpx", cls="fixed"), unsafe_allow_html=True)
    srv_rows = "".join(f'<div class="row"><span class="title">{s}</span><span class="rule">{n}</span></div>'
                       for s, n in servers.items()) or '<div class="muted-note">No server headers captured.</div>'
    b.markdown(card("Servers seen", srv_rows, meta="from headers", cls="fixed", center=False), unsafe_allow_html=True)
    erows = ""
    for u, sev in list(endpoints.items())[:30]:
        col = SEV.get(sev, "#6b7280")
        path = urlparse(u).path or "/"
        erows += (f'<div class="row"><span class="title tag">{path}</span>'
                  f'<span class="chip" style="background:{col}26;color:{col}">{sev}</span></div>')
    erows = erows or '<div class="muted-note">No endpoints recorded.</div>'
    st.markdown(card("Endpoints observed", erows, meta=f"{len(endpoints)} unique", center=False), unsafe_allow_html=True)

elif view == "Leads":
    for l in sorted(leads, key=lambda x: PRIO_ORDER.get(x.get("priority"), 9)):
        col = PRIO.get(l.get("priority"), "#6b7280")
        st.markdown(
            f'<div class="card"><div class="row" style="border:none;padding-top:0">'
            f'<span class="badge" style="background:{col}26;color:{col}">{l.get("priority", "?").upper()}</span>'
            f'<span class="title"><b>{l.get("title", "")}</b></span>'
            f'<span class="tag">{l.get("wstg_category", "")} · {l.get("owasp", "")}</span></div>'
            f'<div style="color:#d6dbe4;font-size:13px;line-height:1.7">'
            f'<b style="color:{ECHO}">Method:</b> {l.get("method", "")}<br>'
            f'<b style="color:{ECHO}">Result:</b> {l.get("result", "")}<br>'
            f'<b style="color:{ECHO}">Inference:</b> {l.get("inference", "")}<br>'
            f'<b style="color:{GREEN}">Read-only check:</b> {l.get("readonly_next_step", "")}<br>'
            f'<b style="color:{AMBER}">Test by hand:</b> {l.get("human_test", "")}</div></div>',
            unsafe_allow_html=True)
    if not leads:
        st.caption("No leads in this run.")

elif view == "Scope & coverage":
    a, b = st.columns(2)
    cmap = {"ALLOW": GREEN, "DENY": RED, "LEAD": AMBER}
    rows = "".join(f'<div class="row"><span class="chip" style="background:{cmap.get(d.get("verdict"), "#6b7280")}26;'
                   f'color:{cmap.get(d.get("verdict"), "#6b7280")}">{d.get("verdict")}</span>'
                   f'<span class="title">{d.get("host")}</span>'
                   f'<span class="rule">{d.get("rule", "")}</span></div>' for d in dec) or '<div class="muted-note">—</div>'
    a.markdown(card("Scope decisions", rows, meta=f"{len(dec)} hosts", center=False), unsafe_allow_html=True)
    crows = "".join(f'<div class="row"><span class="chip" style="background:'
                    f'{GREEN if c2.get("assessable") else AMBER}26;color:{GREEN if c2.get("assessable") else AMBER}">'
                    f'{"assessed" if c2.get("assessable") else "gap"}</span>'
                    f'<span class="title tag">{c2.get("wstg_category")}</span></div>' for c2 in coverage) \
        or '<div class="muted-note">Run Oracle to populate coverage.</div>'
    b.markdown(card("WSTG coverage", crows, meta=cov_pct, center=False), unsafe_allow_html=True)

else:  # Report
    st.markdown("#### Reports for this run")
    cols = st.columns(3)
    if md_path.exists():
        cols[0].download_button("Download report.md", md_path.read_text(), file_name="report.md", key="rp_md")
    if html_path.exists():
        cols[1].download_button("Download Oracle report (HTML)", html_path.read_text(),
                                file_name="oracle_analysis.html", mime="text/html", key="rp_html")
    if json_path.exists():
        cols[2].download_button("Download analysis (JSON)", json_path.read_text(),
                                file_name="oracle_analysis.json", mime="application/json", key="rp_json")
    st.write("")
    if html_path.exists():
        st.markdown("##### Oracle report preview")
        components.html(html_path.read_text(), height=800, scrolling=True)
    elif md_path.exists():
        st.markdown("##### Report preview")
        st.markdown(md_path.read_text())
    else:
        st.caption("No report generated yet. Run `python -m echov report` and `python -m echov oracle report`.")

if auto:
    time.sleep(5)
    st.rerun()
