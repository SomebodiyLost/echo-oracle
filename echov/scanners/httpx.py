from __future__ import annotations
from echov.scanners.base import resolve_binary, run_json_lines


def run(targets, timeout=600):
    """Probe hosts for live HTTP services. Active — sends requests."""
    binary = resolve_binary(["httpx", "httpx-toolkit"])
    cmd = [binary, "-json", "-silent", "-no-color",
           "-title", "-tech-detect", "-status-code"]
    stdin = "\n".join(targets) + "\n"
    results, _ = run_json_lines(cmd, stdin_data=stdin, timeout=timeout)
    return results
