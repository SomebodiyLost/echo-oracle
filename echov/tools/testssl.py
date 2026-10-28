from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAME = "testssl"
CATEGORY = "tls-config"
BINARIES = ["testssl.sh", "testssl"]


def run(target, workdir):
    binary = next((b for b in BINARIES if shutil.which(b)), None)
    if not binary:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "skipped": True,
                "reason": "not installed (sudo apt install testssl.sh)"}
    host = target.split("://", 1)[-1].rstrip("/")
    out = Path(workdir) / "testssl.json"
    # --quiet, machine-readable JSON, only LOW severity and above; testssl is SLOW
    cmd = [binary, "--quiet", "--color", "0", "--jsonfile", str(out), "--severity", "LOW", host]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "reason": str(e)}

    issues = []
    try:
        data = json.loads(out.read_text() or "[]")
        for f in (data if isinstance(data, list) else data.get("scanResult", [])):
            sev = (f.get("severity") or "").upper()
            if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                issues.append({"id": f.get("id"), "severity": sev, "finding": f.get("finding")})
    except Exception:
        pass
    if not issues:
        summary = "no TLS issues reported (or no TLS service on this port)"
    else:
        hi = sum(1 for i in issues if i["severity"] in ("HIGH", "CRITICAL"))
        summary = f"{len(issues)} TLS findings ({hi} high/critical)"
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": summary, "items": issues, "raw_path": str(out)}
