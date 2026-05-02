import json

import httpx

from ..core.models import RequestContext, SignalResult
from .base import SoftSignal


def _generate_url(base_url: str) -> str:
    clean = base_url.rstrip("/")
    if clean.endswith("/api/generate"):
        return clean
    return f"{clean}/api/generate"


def _parse_json_response(raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    if "```" in text:
        parts = [part.strip() for part in text.split("```") if part.strip()]
        for part in parts:
            candidate = part
            if candidate.lower().startswith("json"):
                candidate = candidate[4:].strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return {}
    return {}


class AISignal(SoftSignal):
    name = "ai"
    weight = 0.05

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3",
        timeout: float = 5.0,
        api_key: str | None = None,
        caller=None,
    ) -> None:
        self._url = _generate_url(base_url)
        self._model = model
        self._timeout = timeout
        self._api_key = api_key
        self._caller = caller

    async def extract(self, ctx: RequestContext) -> SignalResult:
        return await self.review(ctx, 0.0)

    async def review(self, ctx: RequestContext, prior_score: float) -> SignalResult:
        if ctx.snapshot is None or ctx.snapshot.ai_mode == "off":
            return SignalResult(score=0.0, reason="ai_off")

        try:
            data = await self._ask(ctx, prior_score)
        except httpx.TimeoutException:
            return SignalResult(score=0.0, reason="ai_timeout")
        except Exception as exc:
            return SignalResult(score=0.0, reason="ai_error", exception=exc)

        verdict = str(data.get("verdict", "clean")).lower()
        conf = float(data.get("confidence", 0.0))
        reason = str(data.get("reason", "")).strip()

        score = 0.0
        if verdict == "suspicious":
            score = min(0.18, conf * 0.18)
        elif verdict == "malicious":
            score = min(0.30, conf * 0.30)

        return SignalResult(
            score=score,
            reason=f"ai_{verdict}",
            detail={
                "verdict": verdict,
                "confidence": conf,
                "note": reason,
                "model": self._model,
                "score_hint": score,
            },
        )

    async def complete_text(self, prompt: str, *, format_json: bool = False) -> str:
        if self._caller is not None:
            raise RuntimeError("ai_completion_unavailable_for_test_caller")

        payload = {"model": self._model, "prompt": prompt, "stream": False}
        if format_json:
            payload["format"] = "json"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            res = await client.post(
                self._url,
                headers=self._headers(),
                json=payload,
            )
            res.raise_for_status()
            return str(res.json().get("response", "")).strip()

    async def complete_json(self, prompt: str) -> dict:
        raw = await self.complete_text(prompt, format_json=True)
        return _parse_json_response(raw)

    async def _ask(self, ctx: RequestContext, prior_score: float) -> dict:
        if self._caller is not None:
            return await self._caller(ctx, prior_score)

        prompt = (
            "You are checking API input for abuse.\n"
            f"endpoint: {ctx.endpoint}\n"
            f"prior_score: {prior_score:.2f}\n"
            f"payload: {(ctx.payload or '')[:400]}\n"
            'reply with JSON only: {"verdict":"clean|suspicious|malicious","confidence":0.0,"reason":"..."}'
        )
        return await self.complete_json(prompt)

    def _headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        return {"Authorization": f"Bearer {self._api_key}"}
