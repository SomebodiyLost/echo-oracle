from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import yaml

from echov.models import ScopeDecision, Verdict


def normalize_host(raw: str) -> str:
    h = raw.strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_matches(host: str, pattern: str, include_apex: bool = False) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        if host.endswith("." + base):
            return True
        return include_apex and host == base
    return host == pattern


class ScopeGuard:
    def __init__(self, allow_domains, allow_wildcards, allow_cidrs, deny_rules, deny_cidrs):
        self.allow_domains = [d.lower().rstrip(".") for d in allow_domains]
        self.allow_wildcards = [w.lower().rstrip(".") for w in allow_wildcards]
        self.allow_cidrs = [ipaddress.ip_network(c, strict=False) for c in allow_cidrs]
        self.deny_rules = [d.lower().rstrip(".") for d in deny_rules]
        self.deny_cidrs = [ipaddress.ip_network(c, strict=False) for c in deny_cidrs]

    @classmethod
    def from_yaml(cls, path):
        data = yaml.safe_load(Path(path).read_text()) or {}
        allow = data.get("allow", {}) or {}
        deny = data.get("deny", {}) or {}
        return cls(
            allow.get("domains", []) or [],
            allow.get("wildcards", []) or [],
            allow.get("cidrs", []) or [],
            deny.get("hosts", []) or [],
            deny.get("cidrs", []) or [],
        )

    def check(self, raw_host: str, stage: str = "input") -> ScopeDecision:
        host = normalize_host(raw_host)
        is_ip = _looks_like_ip(host)

        for rule in self.deny_rules:
            if _host_matches(host, rule, include_apex=True):
                return ScopeDecision(host, Verdict.DENY, f'matched deny rule "{rule}"', stage)
        if is_ip:
            ip = ipaddress.ip_address(host)
            for net in self.deny_cidrs:
                if ip in net:
                    return ScopeDecision(host, Verdict.DENY, f"inside denied CIDR {net}", stage)

        for d in self.allow_domains:
            if host == d:
                return ScopeDecision(host, Verdict.ALLOW, f'matched allow domain "{d}"', stage)
        for w in self.allow_wildcards:
            if _host_matches(host, w, include_apex=False):
                return ScopeDecision(host, Verdict.ALLOW, f'matched allow wildcard "{w}"', stage)
        if is_ip:
            ip = ipaddress.ip_address(host)
            for net in self.allow_cidrs:
                if ip in net:
                    return ScopeDecision(host, Verdict.ALLOW, f"inside allowed CIDR {net}", stage)

        return ScopeDecision(host, Verdict.LEAD, "not in allow list", stage)

    def filter(self, hosts, stage="input"):
        decisions = [self.check(h, stage) for h in hosts]
        allowed = [d.host for d in decisions if d.verdict == Verdict.ALLOW]
        return allowed, decisions


def write_decision_log(decisions, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "scope_decisions.json"
    path.write_text(json.dumps([d.to_dict() for d in decisions], indent=2))
    return path
