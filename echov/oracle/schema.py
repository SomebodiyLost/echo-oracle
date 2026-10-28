from __future__ import annotations
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

Priority = Literal["high", "medium", "low"]
Category = Literal["root_cause", "surface_gap", "anomaly", "known_issue"]

WSTG = Literal[
    "information_gathering", "configuration", "identity_auth", "session_management",
    "authorization", "input_validation", "error_handling", "business_logic",
    "client_side", "cryptography",
]
OWASP = Literal[
    "A01_broken_access_control", "A02_crypto_failures", "A03_injection",
    "A04_insecure_design", "A05_security_misconfig", "A06_vulnerable_components",
    "A07_auth_failures", "A08_integrity_failures", "A09_logging_failures",
    "A10_ssrf", "none",
]


class Lead(BaseModel):
    title: str
    priority: Priority
    category: Category
    wstg_category: str = "information_gathering"
    owasp: str = "none"
    # structured reasoning chain
    method: str = ""        # the assessment angle / what was checked
    result: str = ""        # what the evidence actually shows
    inference: str = ""     # what it implies about a systemic weakness
    reasoning: str = ""     # the connected narrative
    evidence: List[str] = Field(default_factory=list)
    readonly_next_step: str = ""
    human_test: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class CoverageItem(BaseModel):
    wstg_category: str = "information_gathering"
    assessable: bool        # could Oracle say anything from current evidence?
    note: str = ""


class OracleAnalysis(BaseModel):
    summary: str
    surface_notes: List[str] = Field(default_factory=list)
    leads: List[Lead]
    coverage: List[CoverageItem] = Field(default_factory=list)
