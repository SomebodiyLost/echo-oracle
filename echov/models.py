from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LEAD = "LEAD"


@dataclass
class ScopeDecision:
    host: str
    verdict: Verdict
    rule: str
    stage: str

    def to_dict(self):
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


@dataclass
class Asset:
    url: str
    host: str
    status_code: int | None = None
    title: str = ""
    tech: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    host: str
    matcher_name: str = ""
    extracted: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
