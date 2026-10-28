from __future__ import annotations

import json
import shutil
import subprocess


class ToolNotFound(Exception):
    pass


def resolve_binary(candidates):
    """Return the first tool name that exists on PATH."""
    for name in candidates:
        if shutil.which(name):
            return name
    raise ToolNotFound(
        f"None of these were found on PATH: {', '.join(candidates)}."
    )


def run_lines(cmd, stdin_data=None, timeout=600):
    """Run a command; return (list of stdout lines, stderr)."""
    proc = subprocess.run(
        cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout
    )
    lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    return lines, proc.stderr


def run_json_lines(cmd, stdin_data=None, timeout=600):
    """Run a command whose stdout is one JSON object per line."""
    lines, stderr = run_lines(cmd, stdin_data=stdin_data, timeout=timeout)
    objs = []
    for line in lines:
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            continue   # skip banners / non-JSON noise
    return objs, stderr
