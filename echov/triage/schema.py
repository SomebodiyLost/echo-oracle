from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class DraftWriteup(BaseModel):
    title: str = ""
    summary: str = ""
    steps_to_reproduce: str = ""
    impact: str = ""
    remediation: str = ""


class TriageVerdict(BaseModel):
    finding_index: int
    is_likely_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    adjusted_severity: Severity
    reasoning: str
    needs_human_review: bool
    draft_writeup: DraftWriteup | None = None


class TriageBatch(BaseModel):
    verdicts: list[TriageVerdict]
