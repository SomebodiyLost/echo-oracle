from __future__ import annotations
from dotenv import load_dotenv
from openai import OpenAI
from echov.oracle.schema import OracleAnalysis
from echov.oracle import prompts
from echov.oracle.client import _extract_json, _normalize_owasp, _normalize_wstg

load_dotenv(dotenv_path=".env")
GPT_MODEL = "gpt-6.1-sol"   # verify current model string at developers.openai.com


class GPTRefused(Exception):
    pass


class GPTOracleClient:
    def __init__(self, model=None, effort="medium"):
        self.client = OpenAI()
        self.model = model or GPT_MODEL
        self.effort = effort

    def _call(self, user):
        r = self.client.responses.create(
            model=self.model,
            instructions=prompts.SYSTEM,
            input=user,
            reasoning={"effort": self.effort},
            max_output_tokens=16000,
        )
        return r.output_text or ""

    def analyze(self, context, findings, ports, tech, fetched=None):
        user = prompts.build_user_prompt(context, findings, ports, tech, fetched=fetched)
        raw = self._call(user)
        if not raw.strip():
            raise GPTRefused("empty response from GPT (declined or no output)")
        try:
            return _normalize_wstg(_normalize_owasp(
                OracleAnalysis.model_validate_json(_extract_json(raw))))
        except Exception:
            raw2 = self._call(user + "\n\nReturn ONLY one valid, complete JSON object "
                              "matching the schema. No prose, no markdown.")
            if not raw2.strip():
                raise GPTRefused("empty response from GPT on retry")
            return _normalize_wstg(_normalize_owasp(
                OracleAnalysis.model_validate_json(_extract_json(raw2))))
