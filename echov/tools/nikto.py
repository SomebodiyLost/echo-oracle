"""Nikto web-server misconfiguration scanner. OPT-IN ONLY — it is noisy and
sends many requests, so it never runs in a default detection pass."""
from __future__ import annotations
import json, shutil, subprocess
from pathlib import Path

NAME = "nikto"
CATEGORY = "web-misconfig"
BINARIES = ["nikto"]
OPT_IN = True   # registry only runs this when explicitly requested


def run(target, workdir):
    binary = next((b for b in BINARIES if shutil.which(b)), None)
    if not binary:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "skipped": True,
                "reason": "not installed (sudo apt install nikto)"}
    url = target if target.startswith(("http://", "https://")) else "http://" + target
    out = Path(workdir) / "nikto.json"
    cmd = [binary, "-h", url, "-Format", "json", "-output", str(out),
           "-maxtime", "300s", "-ask", "no"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=400)
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "reason": str(e)}

    items = []
    try:
        data = json.loads(out.read_text() or "{}")
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        for v in vulns:
            items.append({"id": v.get("id"), "msg": v.get("msg"), "url": v.get("url")})
    except Exception:
        pass
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": f"{len(items)} nikto observation(s)" if items else "no notable nikto findings",
            "items": items, "raw_path": str(out)}
