"""Nmap port/service discovery. OPT-IN ONLY — never runs unless --nmap is passed.
Port scanning is noisy and many programs restrict it, so it is never part of a
default scan. Runs behind the scope guard like every other active step."""
from __future__ import annotations
import shutil
import subprocess
import xml.etree.ElementTree as ET


class ToolNotFound(Exception):
    pass


# how many ports each depth scans — top-100 is the gentle default
PORT_PROFILES = {
    "100": ["--top-ports", "100"],
    "1000": ["--top-ports", "1000"],
    "all": ["-p-"],
}


def run(host, profile="100", rate_limit=10, timeout=900):
    """Scan one host's ports. Returns a list of open-port dicts.
    profile: '100' (default, fast/polite), '1000', or 'all' (loud)."""
    if not shutil.which("nmap"):
        raise ToolNotFound("nmap not found on PATH. Install it: sudo apt install nmap")

    ports = PORT_PROFILES.get(profile, PORT_PROFILES["100"])
    # -sV: service/version detection; -T3 + max-rate keep it measured, not aggressive
    cmd = ["nmap", "-sV", "-T3", "--max-rate", str(rate_limit),
           "-oX", "-", *ports, host]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    results = []
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return results

    for h in root.findall("host"):
        for port in h.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            results.append({
                "host": host,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
            })
    return results
