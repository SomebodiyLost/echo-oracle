from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAME = "wafw00f"
CATEGORY = "waf-detection"
BINARIES = ["wafw00f"]


def run(target, workdir):
    binary = next((b for b in BINARIES if shutil.which(b)), None)
    if not binary:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "skipped": True,
                "reason": "not installed (sudo apt install wafw00f)"}
    url = target if target.startswith(("http://", "https://")) else "http://" + target
    out = Path(workdir) / "wafw00f.json"
    cmd = [binary, url, "-f", "json", "-o", str(out)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "reason": str(e)}

    detected = []
    try:
        data = json.loads(out.read_text() or "[]")
        detected = [d for d in data if d.get("detected")]
    except Exception:
        pass
    if detected:
        names = ", ".join(d.get("firewall", "?") for d in detected)
        summary = f"WAF detected: {names}"
    else:
        summary = "no WAF detected"
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": summary, "items": detected, "raw_path": str(out)}
