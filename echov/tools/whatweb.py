from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAME = "whatweb"
CATEGORY = "tech-fingerprint"
BINARIES = ["whatweb"]


def run(target, workdir):
    binary = next((b for b in BINARIES if shutil.which(b)), None)
    if not binary:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "skipped": True,
                "reason": "not installed (sudo apt install whatweb)"}
    out = Path(workdir) / "whatweb.json"
    cmd = [binary, "--color=never", "-a", "3", f"--log-json={out}", target]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "reason": str(e)}

    techs = []
    try:
        text = out.read_text().strip() or "[]"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = [json.loads(l) for l in text.splitlines() if l.strip()]
        for entry in (data if isinstance(data, list) else [data]):
            for name, info in (entry.get("plugins", {}) or {}).items():
                ver = (info or {}).get("version") or []
                techs.append({"name": name, "version": ver})
    except Exception:
        pass
    names = ", ".join(sorted({t["name"] for t in techs})[:8])
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": f"{len(techs)} tech signals: {names}" if techs else "no technologies identified",
            "items": techs, "raw_path": str(out)}
