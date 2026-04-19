import asyncio

from adiuvare import Guard
from adiuvare.core.models import RequestContext, SignalResult
from adiuvare.signals.base import HardSignal, SoftSignal, validate_hard_signal


class LoudSignal(SoftSignal):
    name = "payload"
    weight = 0.90

    async def extract(self, ctx: RequestContext) -> SignalResult:
        return SignalResult(score=0.9, reason="loud_hit")


class StopNow(HardSignal):
    name = "stop_now"

    def check(self, ctx: RequestContext) -> bool:
        return ctx.endpoint == "/stop"


class HoldNow(HardSignal):
    name = "hold_now"
    action = "hold"

    def check(self, ctx: RequestContext) -> bool:
        return ctx.endpoint == "/review"


def test_guard_uses_custom_signal_list():
    guard = Guard(soft_signals=[LoudSignal()])
    ctx = RequestContext(
        identity="u1",
        payload=None,
        url="/",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        ip="127.0.0.1",
        endpoint="/",
        snapshot=guard._cfg_snap,
    )

    gate, event = asyncio.run(guard.inspect(ctx))
    assert gate.passed is True
    assert event is not None
    assert event.score > 0.0


def test_validate_hard_signal_accepts_sync_checker():
    validate_hard_signal(StopNow())


def test_guard_hard_signal_can_block():
    guard = Guard(hard_signals=[StopNow()])
    ctx = RequestContext(
        identity="u1",
        payload=None,
        url="/stop",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        ip="127.0.0.1",
        endpoint="/stop",
        snapshot=guard._cfg_snap,
    )

    gate, event = asyncio.run(guard.inspect(ctx))
    assert gate.passed is False
    assert event is None


def test_guard_hard_signal_can_hold():
    guard = Guard(hard_signals=[HoldNow()])
    ctx = RequestContext(
        identity="u1",
        payload=None,
        url="/review",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        ip="127.0.0.1",
        endpoint="/review",
        snapshot=guard._cfg_snap,
    )

    gate, event = asyncio.run(guard.inspect(ctx))
    assert gate.passed is False
    assert gate.hold is True
    assert event is None
