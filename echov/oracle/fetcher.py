"""Dedicated READ-ONLY fetcher for Oracle. Structurally cannot do anything but
read: GET/HEAD only, no request body, no auth headers. One URL at a time."""
from __future__ import annotations
import urllib.request
import urllib.error

ALLOWED_METHODS = {"GET", "HEAD"}
MAX_BODY = 200_000   # cap body so a huge response can't blow up context/cost


def fetch(url, method="GET", timeout=15):
    """Make ONE read-only request. Returns a dict; never raises."""
    method = method.upper()
    if method not in ALLOWED_METHODS:
        return {"url": url, "error": f"refused: {method} is not read-only"}
    if not url.lower().startswith(("http://", "https://")):
        return {"url": url, "error": "refused: only http(s) URLs"}

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "EchoOracle-ReadOnly/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY)
            body = raw.decode("utf-8", errors="replace")
            return {
                "url": url, "status": resp.status,
                "content_type": resp.headers.get("Content-Type", ""),
                "headers": dict(resp.headers),
                "body": body, "truncated": len(raw) >= MAX_BODY,
            }
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "error": f"HTTP {e.code}",
                "body": (e.read(2000).decode("utf-8", errors="replace") if e.fp else "")}
    except Exception as e:
        return {"url": url, "error": f"{type(e).__name__}: {e}"}
