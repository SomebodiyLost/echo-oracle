"""Offline reasoning — no API key, no cost. Heuristic, not real reasoning,
but enough to test the whole Oracle pipeline for free."""
from __future__ import annotations

from echov.oracle.schema import Lead, OracleAnalysis


class MockOracleClient:
    def __init__(self, *a, **k):
        pass

    def analyze(self, context, findings, ports, tech, fetched=None):
        names = [f.get("name", "").lower() for f in findings]
        leads = []

        headers = [n for n in names if "missing security headers" in n]
        if headers:
            leads.append(Lead(
                title="No security-header policy (root cause of many findings)",
                priority="low", category="root_cause", wstg_category="configuration", owasp="A05_security_misconfig",
                reasoning=f"{len(headers)} findings share one cause: the app sets no "
                          "security-header policy. Common, obvious, usually already reported.",
                evidence=[f"HTTP Missing Security Headers x{len(headers)}"],
                readonly_next_step="None — the root cause is already clear.",
                human_test="If CSP is absent, a human tests inputs for XSS by hand.",
                confidence=0.8))

        if any("swagger" in n or "api" in n for n in names):
            leads.append(Lead(
                title="Exposed API docs map the full API surface",
                priority="high", category="surface_gap", wstg_category="information_gathering", owasp="A01_broken_access_control",
                reasoning="An exposed Swagger/OpenAPI spec lists every endpoint, including "
                          "ones recon never probed — unexamined in-scope surface, the best lead here.",
                evidence=["Public Swagger API - Detect"],
                readonly_next_step="Fetch the swagger JSON and list every endpoint it declares.",
                human_test="A human checks each listed endpoint for broken access control.",
                confidence=0.9))

        if any("prometheus" in n or "metrics" in n for n in names):
            leads.append(Lead(
                title="Exposed /metrics endpoint may leak internal data",
                priority="medium", category="anomaly", wstg_category="configuration", owasp="A05_security_misconfig",
                reasoning="An accessible metrics endpoint can leak internal counters, paths, "
                          "and timing. Impact depends on what it actually exposes.",
                evidence=["Prometheus Metrics - Detect"],
                readonly_next_step="Fetch /metrics and inspect the content for sensitive values.",
                human_test="A human judges whether the leaked internals aid further testing.",
                confidence=0.6))

        if not leads:
            leads.append(Lead(title="No notable leads from heuristics", priority="low",
                              category="known_issue", wstg_category="information_gathering", owasp="none",
                              reasoning="Nothing stood out to the offline rules.", confidence=0.3))

        return OracleAnalysis(
            summary="Offline heuristic analysis. The findings reduce to a few leads: an "
                    "exposed API spec (high value), a metrics endpoint to inspect, and a "
                    "low-value header root cause. Run without --mock for real AI reasoning.",
            surface_notes=[
                "Endpoints listed in the Swagger spec that recon did not probe.",
                "Additional paths implied by the detected technology stack.",
            ],
            leads=leads)
