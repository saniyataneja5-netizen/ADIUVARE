import asyncio
import json
import sqlite3

from adiuvare import Guard
from adiuvare.core.models import AdiuvareEvent
from adiuvare.state.audit_log import AuditLog
from adiuvare.state.identity_store import IdentityStore
from adiuvare.state.persistence import checkpoint_state, init_state_db, save_identity_state


def test_audit_log_writes_event(tmp_path):
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path)
    event = AdiuvareEvent(
        identity="u1",
        endpoint="/login",
        score=0.42,
        verdict="flag",
        breakdown={"payload": 0.28, "identity": 0.14},
    )

    log.write(event)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select identity, verdict, breakdown_json from audit_events"
        ).fetchone()

    assert row is not None
    assert row[0] == "u1"
    assert row[1] == "flag"
    assert json.loads(row[2])["payload"] == 0.28


def test_state_checkpoint_writes_identity_window(tmp_path):
    db_path = tmp_path / "audit.db"
    store = IdentityStore()
    win = store.get("u1")
    win.seen = 3
    win.score_ewma = 0.42
    store.update("u1", win)

    init_state_db(db_path)
    save_identity_state(db_path, store)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select identity, seen, score_ewma from identity_state"
        ).fetchone()

    assert row == ("u1", 3, 0.42)


def test_audit_log_query_helpers_work(tmp_path):
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path)
    first = AdiuvareEvent(
        identity="u1",
        endpoint="/login",
        score=0.42,
        verdict="flag",
        breakdown={"payload": 0.28},
        detail={"ai": {"verdict": "suspicious"}},
    )
    second = AdiuvareEvent(
        identity="u2",
        endpoint="/pay",
        score=0.88,
        verdict="block",
        breakdown={"payload": 0.4},
    )
    log.write(first)
    log.write(second)

    recent = log.recent()
    mine = log.by_identity("u1")
    assert recent[0]["identity"] == "u2"
    assert mine[0]["detail"]["ai"]["verdict"] == "suspicious"


def test_checkpoint_state_helper_runs(tmp_path):
    db_path = tmp_path / "audit.db"
    store = IdentityStore()
    store.bump("u1")
    checkpoint_state(db_path, store)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("select identity, seen from identity_state").fetchone()

    assert row == ("u1", 1)


def test_guard_stream_command_path_updates_runtime_state(tmp_path):
    guard = Guard()
    guard._audit = AuditLog(tmp_path / "audit.db")
    guard._state_DBpath = tmp_path / "state.db"

    snap = asyncio.run(guard.event_stream.command("get_runtime_snapshot", {}))
    assert "ai_mode" in snap

    block = asyncio.run(
        guard.event_stream.command(
            "confirm_block",
            {"identity": "u1", "ttl_secs": 60},
        )
    )
    assert block["ok"] is True
    assert guard._id_store.is_blocked("u1") is True

    allow = asyncio.run(
        guard.event_stream.command(
            "unblock_whitelist",
            {"identity": "u1"},
        )
    )
    assert allow["ok"] is True
    assert guard.whitelist.allows("u1") is True

    patched = asyncio.run(
        guard.event_stream.command(
            "patch_config",
            {"changes": {"ai_mode": "assist", "observe_only": True}},
        )
    )
    assert patched["ai_mode"] == "assist"
    assert patched["observe_only"] is True


def test_checkpoint_loop_picks_up_new_identity(tmp_path):
    db_path = tmp_path / "state.db"
    store = IdentityStore()
    store.bump("u9")

    async def run():
        from adiuvare.state.persistence import start_checkpoint_loop

        task = asyncio.create_task(start_checkpoint_loop(db_path, store, interval_secs=0.01))
        try:
            await asyncio.sleep(0.03)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    import contextlib

    asyncio.run(run())

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("select identity, seen from identity_state").fetchone()

    assert row == ("u9", 1)
