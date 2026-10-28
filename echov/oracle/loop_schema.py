from __future__ import annotations
from typing import List, Literal
from pydantic import BaseModel, Field


class ProposedFetch(BaseModel):
    url: str
    reason: str                       # why this read-only fetch is worth making
    method: Literal["GET", "HEAD"] = "GET"


class RoundOutput(BaseModel):
    thinking: str                     # what Oracle concluded this round
    proposed_fetches: List[ProposedFetch] = Field(default_factory=list)
    done: bool = False                # Oracle believes it has enough to conclude
    final_summary: str = ""           # filled only when done
