from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path

NAME = "dnsrecon"
CATEGORY = "dns-enum"
BINARIES = ["dnsrecon"]


def run(target, workdir):
    binary = next((b for b in BINARIES if shutil.which(b)), None)
    if not binary:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "skipped": True,
                "reason": "not installed (sudo apt install dnsrecon)"}
    # domain only — strip scheme/port/path; skip bare IPs and localhost
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if host in ("localhost",) or host.replace(".", "").isdigit():
        return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
                "summary": "skipped — DNS enumeration only applies to domain names",
                "items": [], "raw_path": ""}
    out = Path(workdir) / "dnsrecon.json"
    cmd = [binary, "-d", host, "-t", "std", "-j", str(out)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "ok": False, "reason": str(e)}

    records = []
    try:
        data = json.loads(out.read_text() or "[]")
        for r in (data if isinstance(data, list) else []):
            if r.get("type") and r.get("type") != "ScanInfo":
                records.append({"type": r.get("type"), "name": r.get("name"),
                                "address": r.get("address") or r.get("target")})
    except Exception:
        pass
    kinds = ", ".join(sorted({r["type"] for r in records})[:8])
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": f"{len(records)} DNS records ({kinds})" if records else "no DNS records resolved",
            "items": records, "raw_path": str(out)}
