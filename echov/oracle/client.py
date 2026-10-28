from __future__ import annotations

from anthropic import Anthropic
from dotenv import load_dotenv

from echov.oracle import prompts
from echov.oracle.schema import OracleAnalysis

load_dotenv(dotenv_path=".env")
DEFAULT_MODEL = "claude-sonnet-5-5"   # verify current string at docs.claude.com


class OracleRefused(Exception):
    """The model declined this run. Not a code bug — just re-run."""


def _extract_json(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1:
        return ""
    return text[start:end + 1] if end != -1 and end > start else text[start:]




def _normalize_wstg(analysis):
    valid = {"information_gathering","configuration","identity_auth","session_management",
             "authorization","input_validation","error_handling","business_logic",
             "client_side","cryptography"}
    for lead in analysis.leads:
        w = (lead.wstg_category or "").strip().lower().replace("-", "_").replace(" ", "_")
        lead.wstg_category = w if w in valid else "information_gathering"
    return analysis


def _normalize_owasp(analysis):
    import re
    valid = {f"A{i:02d}" for i in range(1, 11)}
    names = {
        "A01": "A01_broken_access_control", "A02": "A02_crypto_failures",
        "A03": "A03_injection", "A04": "A04_insecure_design",
        "A05": "A05_security_misconfig", "A06": "A06_vulnerable_components",
        "A07": "A07_auth_failures", "A08": "A08_integrity_failures",
        "A09": "A09_logging_failures", "A10": "A10_ssrf",
    }
    for lead in analysis.leads:
        raw = (lead.owasp or "none").strip()
        m = re.match(r"[Aa]?0*([1-9]|10)", raw)
        if m:
            key = f"A{int(m.group(1)):02d}"
            lead.owasp = names.get(key, "none")
        else:
            lead.owasp = "none"
    return analysis


class OracleClient:
    def __init__(self, model=None):
        self.client = Anthropic()
        self.model = model or DEFAULT_MODEL

    def _call(self, user, max_tokens=20000):
        with self.client.messages.stream(
            model=self.model, max_tokens=max_tokens,
            system=prompts.SYSTEM,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            text = ""
            for event in stream.text_stream:
                text += event
            final = stream.get_final_message()
        return text, final.stop_reason

    def analyze(self, context, findings, ports, tech, fetched=None):
        user = prompts.build_user_prompt(context, findings, ports, tech, fetched=fetched)
        raw, stop = self._call(user)
        if stop == "refusal" or not raw.strip():
            raise OracleRefused(
                "the model declined this run (this happens occasionally; just run it again)")
        try:
            return _normalize_wstg(_normalize_owasp(OracleAnalysis.model_validate_json(_extract_json(raw))))
        except Exception:
            raw2, stop2 = self._call(
                user + "\n\nReturn ONLY one valid, complete JSON object matching the schema. "
                "No prose, no markdown.")
            if stop2 == "refusal" or not raw2.strip():
                raise OracleRefused(
                    "the model declined this run (this happens occasionally; just run it again)")
            return _normalize_wstg(_normalize_owasp(OracleAnalysis.model_validate_json(_extract_json(raw2))))
