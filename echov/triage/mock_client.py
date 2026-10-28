"""Offline stand-in for TriageClient — no API key, no network.
Applies simple rules so you can test the whole pipeline end to end."""
from __future__ import annotations
from echov.triage.schema import TriageVerdict

INFO_NOISE = ("technology", "fingerprint", "wappalyzer",
              "missing security headers", "detect")


class MockTriageClient:
    def __init__(self, *a, **k):
        pass

    def triage(self, findings, context):
        results = {}
        for i, f in enumerate(findings):
            name = (f.get("name") or "").lower()
            is_noise = any(k in name for k in INFO_NOISE)
            results[i] = TriageVerdict(
                finding_index=i,
                is_likely_false_positive=is_noise,
                confidence=0.9 if is_noise else 0.5,
                adjusted_severity="info" if is_noise else f.get("severity", "info"),
                reasoning=("Informational detection, not a vulnerability on its own."
                           if is_noise else
                           "Potentially real — evidence is thin, verify manually."),
                needs_human_review=not is_noise,
                draft_writeup=None,
            )
        return results
