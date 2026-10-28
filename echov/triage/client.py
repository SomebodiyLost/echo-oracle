from __future__ import annotations
from dotenv import load_dotenv
from anthropic import Anthropic
from echov.triage.schema import TriageBatch
from echov.triage import prompts

load_dotenv(dotenv_path=".env")
DEFAULT_MODEL = "claude-haiku-4-5-20251001"   # cheap + fast; verify at docs.claude.com


def _extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if start != -1 and end != -1 else text


class TriageClient:
    def __init__(self, model=None, chunk_size=10):
        self.client = Anthropic()          # reads ANTHROPIC_API_KEY from env
        self.model = model or DEFAULT_MODEL
        self.chunk_size = chunk_size

    def _call(self, user_prompt):
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=prompts.SYSTEM,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")

    def _triage_chunk(self, findings, context, start_index):
        prompt = prompts.build_user_prompt(findings, context, start_index)
        raw = self._call(prompt)
        try:
            return TriageBatch.model_validate_json(_extract_json(raw))
        except Exception:
            raw = self._call(prompt + "\n\nReturn ONLY valid JSON. No prose, no fences.")
            return TriageBatch.model_validate_json(_extract_json(raw))

    def triage(self, findings, context):
        """Return {finding_index: TriageVerdict or None}. Never raises per-chunk."""
        results = {}
        for i in range(0, len(findings), self.chunk_size):
            chunk = findings[i:i + self.chunk_size]
            try:
                batch = self._triage_chunk(chunk, context, i)
                for v in batch.verdicts:
                    results[v.finding_index] = v
            except Exception:
                for j in range(i, i + len(chunk)):
                    results.setdefault(j, None)   # fail safe -> human review
        return results
