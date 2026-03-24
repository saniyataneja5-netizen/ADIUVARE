from ..core.models import RequestContext, SignalResult
from .base import SoftSignal


class PayloadSignal(SoftSignal):
    name = "payload"
    weight = 0.40

    async def extract(self, ctx: RequestContext) -> SignalResult:
        if not ctx.payload:
            return SignalResult(score=0.0, reason="no_payload")

        text = ctx.payload.lower()

        if "select" in text or "union" in text or "drop" in text:
            return SignalResult(score=0.7, reason="sql_hit")

        if "<script" in text or "javascript:" in text:
            return SignalResult(score=0.6, reason="xss_hit")

        return SignalResult(score=0.0, reason="clean")

