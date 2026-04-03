from adiuvare.core.models import AdiuvareEvent, ConfigSnapshot, RequestContext


def test_adiuvare_event_holds_score_breakdown():
    event = AdiuvareEvent(
        identity="u1",
        endpoint="/login",
        score=0.42,
        verdict="flag",
        breakdown={"payload": 0.28, "identity": 0.14},
    )

    assert event.verdict == "flag"
    assert event.breakdown["payload"] == 0.28


def test_request_context_can_hold_config_snapshot():
    snap = ConfigSnapshot(
        payload_weight=0.40,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.80,
    )
    ctx = RequestContext(
        identity="u1",
        payload=None,
        url="/",
        method="GET",
        headers={},
        ip="127.0.0.1",
        endpoint="/",
        snapshot=snap,
    )

    assert ctx.snapshot is snap
