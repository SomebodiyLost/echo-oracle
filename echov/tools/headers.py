from __future__ import annotations
import json, urllib.request, urllib.error
from pathlib import Path

NAME = "headers"
CATEGORY = "security-headers"
BINARIES = []   # native — always available

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
]


def run(target, workdir):
    url = target if target.startswith(("http://", "https://")) else "http://" + target
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "Echo-Detect-ReadOnly/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        status = e.code
    except Exception as e:
        return {"tool": NAME, "category": CATEGORY, "target": target, "ok": False,
                "reason": f"{type(e).__name__}: {e}"}

    present = [h for h in SECURITY_HEADERS if h in hdrs]
    missing = [h for h in SECURITY_HEADERS if h not in hdrs]
    server = hdrs.get("server", "")
    out = Path(workdir) / "headers.json"
    try:
        out.write_text(json.dumps(
            {"status": status, "server": server, "present": present,
             "missing": missing, "all_headers": hdrs}, indent=2))
    except Exception:
        pass
    return {"tool": NAME, "category": CATEGORY, "target": target, "ok": True,
            "summary": f"status {status}; {len(present)} security headers set, "
                       f"{len(missing)} missing" + (f"; server: {server}" if server else ""),
            "items": {"present": present, "missing": missing, "server": server},
            "raw_path": str(out)}
