from __future__ import annotations

from echov.scanners.base import resolve_binary, run_json_lines


def run(urls, rate_limit=150, tags=None, timeout=1800):
    """Template-based vuln scan. Active and the noisiest step."""
    binary = resolve_binary(["nuclei"])
    cmd = [binary, "-jsonl", "-silent", "-no-color", "-rate-limit", str(rate_limit)]
    if tags:
        cmd += ["-tags", tags]
    stdin = "\n".join(urls) + "\n"
    results, _ = run_json_lines(cmd, stdin_data=stdin, timeout=timeout)
    return results
