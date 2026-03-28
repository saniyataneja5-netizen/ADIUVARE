from dataclasses import dataclass

from ..core.models import RequestContext
from ..state.identity_store import IdentityStore

trackA_limit = "200/minute"


@dataclass
class GateResult:
    passed: bool
    hold: bool = False
    status_code: int = 200
    block_reason: str | None = None


def run_trackA(ctx: RequestContext, id_store: IdentityStore) -> GateResult:
    if id_store.is_blocked(ctx.identity):
        return GateResult(
            passed=False,
            status_code=429,
            block_reason="identity_blocked",
        )

    seen = id_store.bump(ctx.identity)
    if seen > 200:
        id_store.set_blocked(ctx.identity)
        return GateResult(
            passed=False,
            status_code=429,
            block_reason="rate_limit_hit",
        )

    return GateResult(passed=True)
