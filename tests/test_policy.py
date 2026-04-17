import pytest

from adiuvare import Guard
from adiuvare.core.models import ConfigSnapshot
from adiuvare.core.policy_engine import reach_verdict


def test_guard_policy_decorator_uses_builtin_bundle():
    guard = Guard()

    @guard.policy("admin")
    async def view():
        return {"ok": True}

    assert view._adiuvare_cfg["ai_mode"] == "critical"
    assert view._adiuvare_cfg["sensitivity"] == "critical"


def test_guard_protect_decorator_sets_inline_cfg():
    guard = Guard()

    @guard.protect(sensitivity="public", ai_mode="assist", trackB=False)
    async def view():
        return {"ok": True}

    assert view._adiuvare_cfg["sensitivity"] == "public"
    assert view._adiuvare_cfg["trackB"] is False


def test_guard_protect_keeps_ai_mode_visible():
    guard = Guard()

    @guard.protect(ai_mode="critical")
    async def view():
        return {"ok": True}

    assert view._adiuvare_cfg["ai_mode"] == "critical"


def test_guard_exempt_marks_route():
    guard = Guard()

    @guard.exempt()
    async def view():
        return {"ok": True}

    assert view._adiuvare_exempt is True


def test_guard_policy_rejects_unknown_name():
    guard = Guard()
    with pytest.raises(ValueError):
        guard.policy("made_up")


def test_guard_configure_routes_keeps_mapping():
    guard = Guard()
    guard.configure_routes({"/login": {"policy": "auth"}})
    assert guard._route_cfg["/login"]["policy"] == "auth"


def test_policy_engine_raises_floor_for_strong_payload():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
    )
    out = reach_verdict(0.20, snap=snap, payload_risk=0.90)
    assert out.verdict == "throttle"


def test_policy_engine_identity_escalates_to_throttle():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
    )
    out = reach_verdict(0.30, snap=snap, identity_risk=0.70)
    assert out.verdict == "throttle"


def test_policy_engine_critical_ai_can_block():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        ai_mode="critical",
    )
    out = reach_verdict(0.10, snap=snap, ai_verdict="malicious", ai_conf=0.90, ai_mode="critical")
    assert out.verdict == "block"


def test_policy_engine_observe_only_keeps_logged_block():
    snap = ConfigSnapshot(
        payload_weight=0.4,
        behavior_weight=0.35,
        identity_weight=0.25,
        flag_threshold=0.25,
        throttle_threshold=0.55,
        block_threshold=0.8,
        observe_only=True,
    )
    out = reach_verdict(0.90, snap=snap)
    assert out.verdict == "allow"
    assert out.logged == "block"
