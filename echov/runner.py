from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from echov.models import Asset, Finding, Verdict
from echov.scanners import httpx, nmap, nuclei, subfinder
from echov.scope import ScopeGuard, write_decision_log
from echov.severity import classify


def new_run_dir(base="data/runs"):
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S")
    d = Path(base) / ts
    d.mkdir(parents=True, exist_ok=True)
    return d


def _map_asset(d):
    url = d.get("url") or d.get("input") or ""
    return Asset(
        url=url,
        host=d.get("host") or d.get("input") or url,
        status_code=d.get("status_code") or d.get("status-code"),
        title=d.get("title", "") or "",
        tech=d.get("tech") or d.get("technologies") or [],
        raw=d,
    )


def _map_finding(d):
    info = d.get("info", {}) or {}
    return Finding(
        template_id=d.get("template-id") or "",
        name=info.get("name", ""),
        severity=classify(
            (info.get("classification") or {}).get("cvss-score"),
            info.get("severity"),
        ),
        matched_at=d.get("matched-at") or d.get("matched_at") or "",
        host=d.get("host", ""),
        matcher_name=d.get("matcher-name", "") or "",
        extracted=d.get("extracted-results") or [],
        raw=d,
    )


def gather_candidates(guard, domain, seeds):
    """Collect hosts from seeds + subfinder, then keep only ALLOW ones."""
    candidates = list(seeds or [])
    decisions = []
    if domain:
        dec = guard.check(domain, "input")
        decisions.append(dec)
        if dec.verdict == Verdict.ALLOW:
            candidates += subfinder.run(domain)
    allowed = []
    for c in candidates:
        dec = guard.check(c, "discovery")
        decisions.append(dec)
        if dec.verdict == Verdict.ALLOW:
            allowed.append(c)      # keep original string (port preserved)
    return allowed, decisions


def run_active(scope_path, allowed, decisions, run_nuclei=True,
               rate_limit=150, tags=None, nmap_profile=None):
    """Probe allowed hosts, re-check, scan, and persist results."""
    guard = ScopeGuard.from_yaml(scope_path)
    run_dir = new_run_dir()
    decisions = list(decisions)

    assets = [_map_asset(d) for d in httpx.run(allowed)] if allowed else []

    # OPT-IN port scan — only runs when --nmap passed (nmap_profile set)
    port_findings = []
    if nmap_profile:
        for host in allowed:
            dec = guard.check(host, "nmap")
            decisions.append(dec)
            if dec.verdict == Verdict.ALLOW:
                try:
                    port_findings.extend(
                        nmap.run(host.split(":")[0], profile=nmap_profile,
                                 rate_limit=rate_limit))
                except Exception:
                    pass

    # a redirect can move a live host off-scope — check again before nuclei
    live_urls = []
    for a in assets:
        dec = guard.check(a.host or a.url, "httpx")
        decisions.append(dec)
        if dec.verdict == Verdict.ALLOW:
            live_urls.append(a.url)

    findings = []
    if run_nuclei and live_urls:
        findings = [_map_finding(d)
                    for d in nuclei.run(live_urls, rate_limit=rate_limit, tags=tags)]

    write_decision_log(decisions, run_dir)
    (run_dir / "assets.json").write_text(
        json.dumps([a.to_dict() for a in assets], indent=2))
    (run_dir / "findings.json").write_text(
        json.dumps([f.to_dict() for f in findings], indent=2))
    (run_dir / "ports.json").write_text(json.dumps(port_findings, indent=2))

    return {"run_dir": str(run_dir), "decisions": decisions,
            "assets": assets, "live_urls": live_urls, "findings": findings,
            "ports": port_findings}
