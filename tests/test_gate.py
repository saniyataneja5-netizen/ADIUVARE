import time

from adiuvare.core.gate import configure_trackA, run_trackA
from adiuvare.core.models import RequestContext
from adiuvare.state.identity_store import IdentityStore
from adiuvare.state.whitelist import WhitelistStore


def make_ctx(identity: str = "u1") -> RequestContext:
    return RequestContext(
        identity=identity,
        payload=None,
        url="/",
        method="GET",
        headers={},
        ip="127.0.0.1",
        endpoint="/",
    )


def test_gate_passes_clean_identity():
    res = run_trackA(make_ctx(), IdentityStore())
    assert res.passed is True


def test_gate_blocks_blocked_identity():
    store = IdentityStore()
    store.set_blocked("u1", 60)

    res = run_trackA(make_ctx(), store)
    assert res.passed is False
    assert res.status_code == 429


def test_gate_rate_limit_sets_block():
    store = IdentityStore()
    ctx = make_ctx()
    res = None

    for _ in range(201):
        res = run_trackA(ctx, store)

    assert res is not None
    assert res.passed is False
    assert res.block_reason == "rate_limit_hit"
    assert store.is_blocked("u1") is True


def test_gate_block_expires():
    store = IdentityStore(block_ttl=1)
    store.set_blocked("u1", 0.01)
    time.sleep(0.02)
    assert store.is_blocked("u1") is False


def test_gate_blocks_crude_decoy_path():
    ctx = make_ctx()
    ctx.endpoint = "/.git/config"
    res = run_trackA(ctx, IdentityStore())
    assert res.passed is False
    assert res.status_code == 403


def test_gate_returns_hold_for_admin_post():
    ctx = make_ctx()
    ctx.endpoint = "/admin/login"
    ctx.method = "POST"
    res = run_trackA(ctx, IdentityStore())
    assert res.passed is False
    assert res.hold is True
    assert res.status_code == 202


def test_gate_whitelist_skips_blocked_identity():
    wl = WhitelistStore()
    wl.add("u1")
    configure_trackA(wl=wl, hard_sigs=[])
    store = IdentityStore()
    store.set_blocked("u1", 60)
    res = run_trackA(make_ctx(), store)
    assert res.passed is True
    configure_trackA(wl=None, hard_sigs=[])


def test_gate_blocks_banned_ip():
    wl = WhitelistStore()
    wl.ban_ip("127.0.0.1")
    configure_trackA(wl=wl, hard_sigs=[])
    res = run_trackA(make_ctx(), IdentityStore())
    assert res.passed is False
    assert res.block_reason == "banned_ip"
    configure_trackA(wl=None, hard_sigs=[])
