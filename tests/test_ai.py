import asyncio

from adiuvare.core.models import ConfigSnapshot, RequestContext
from adiuvare.core.pipeline import Pipeline
from adiuvare.signals.ai import AISignal, _parse_json_response
from adiuvare.state.identity_store import IdentityStore


async def _fake_call(ctx, prior_score):
    return {
        "verdict": "suspicious",
        "confidence": 0.8,
        "reason": f"looked odd near {ctx.endpoint} at {prior_score:.2f}",
    }


def test_ai_signal_stays_off_without_mode():
    sig = AISignal(caller=_fake_call)
    ctx = RequestContext(
        identity="u1",
        payload="select * from users",
        url="/login",
        method="POST",
        headers={},
        ip="127.0.0.1",
        endpoint="/login",
    )

    res = asyncio.run(sig.extract(ctx))
    assert res.reason == "ai_off"


def test_ai_signal_parses_mock_result():
    sig = AISignal(caller=_fake_call)
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        ai_mode="assist",
    )
    ctx = RequestContext(
        identity="u1",
        payload="select * from users",
        url="/login",
        method="POST",
        headers={},
        ip="127.0.0.1",
        endpoint="/login",
        snapshot=snap,
    )

    res = asyncio.run(sig.review(ctx, 0.41))
    assert res.reason == "ai_suspicious"
    assert res.detail["verdict"] == "suspicious"


def test_pipeline_carries_ai_detail_in_event():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        ai_mode="assist",
    )
    ctx = RequestContext(
        identity="u1",
        payload="select * from users",
        url="/login",
        method="POST",
        headers={"User-Agent": "Mozilla/5.0"},
        ip="127.0.0.1",
        endpoint="/login",
        snapshot=snap,
    )

    pipe = Pipeline(IdentityStore(), ai_sig=AISignal(caller=_fake_call))
    gate, event = asyncio.run(pipe.process(ctx))
    assert gate.passed is True
    assert event is not None
    assert event.detail["ai"]["verdict"] == "suspicious"


async def _bad_call(ctx, prior_score):
    return {
        "verdict": "malicious",
        "confidence": 0.9,
        "reason": f"bad enough near {ctx.endpoint} at {prior_score:.2f}",
    }


def test_pipeline_critical_mode_can_short_circuit_to_block():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        ai_mode="critical",
    )
    ctx = RequestContext(
        identity="u1",
        payload="hello there",
        url="/review",
        method="POST",
        headers={"User-Agent": "Mozilla/5.0"},
        ip="127.0.0.1",
        endpoint="/review",
        snapshot=snap,
    )

    pipe = Pipeline(IdentityStore(), ai_sig=AISignal(caller=_bad_call))
    gate, event = asyncio.run(pipe.process(ctx))
    assert gate.passed is True
    assert event is not None
    assert event.verdict == "block"


def test_ai_signal_uses_configured_endpoint_model_and_auth(monkeypatch):
    seen = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"response": '{"verdict":"clean","confidence":1.0,"reason":"ok"}'}

    class FakeClient:
        def __init__(self, timeout):
            seen["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, headers=None, json=None):
            seen["url"] = url
            seen["headers"] = headers or {}
            seen["json"] = json or {}
            return FakeResponse()

    monkeypatch.setattr("adiuvare.signals.ai.httpx.AsyncClient", FakeClient)

    sig = AISignal(
        base_url="http://127.0.0.1:9000",
        model="mistral",
        timeout=7.5,
        api_key="demo-key",
    )
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        ai_mode="assist",
    )
    ctx = RequestContext(
        identity="u1",
        payload="hello",
        url="/review",
        method="POST",
        headers={},
        ip="127.0.0.1",
        endpoint="/review",
        snapshot=snap,
    )

    res = asyncio.run(sig.review(ctx, 0.12))
    assert res.reason == "ai_clean"
    assert seen["url"] == "http://127.0.0.1:9000/api/generate"
    assert seen["headers"]["Authorization"] == "Bearer demo-key"
    assert seen["json"]["model"] == "mistral"
    assert seen["json"]["format"] == "json"
    assert seen["timeout"] == 7.5


def test_ai_json_parser_handles_markdown_wrapped_json():
    parsed = _parse_json_response(
        '```json\n{"verdict":"suspicious","confidence":0.7,"reason":"odd"}\n```'
    )
    assert parsed["verdict"] == "suspicious"
    assert parsed["confidence"] == 0.7
