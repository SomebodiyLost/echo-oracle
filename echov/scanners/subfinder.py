from __future__ import annotations
from echov.scanners.base import resolve_binary, run_lines


def run(domain, timeout=600):
    """Passive subdomain discovery. Sends nothing to the target."""
    binary = resolve_binary(["subfinder"])
    hosts, _ = run_lines([binary, "-d", domain, "-silent"], timeout=timeout)
    return hosts
