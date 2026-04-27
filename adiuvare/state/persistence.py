import sqlite3
import asyncio
from pathlib import Path

from .identity_store import IdentityStore


def init_state_db(db_path: str | Path) -> None:
    schema = Path(__file__).with_name("schema.sql").read_text()
    with sqlite3.connect(db_path) as conn:
        conn.executescript(schema)


def save_identity_state(db_path: str | Path, id_store: IdentityStore) -> None:
    with sqlite3.connect(db_path) as conn:
        for identity, win in id_store.items():
            conn.execute(
                """
                insert or replace into identity_state (
                    identity,
                    seen,
                    score_ewma,
                    blocked_until
                ) values (?, ?, ?, ?)
                """,
                (identity, win.seen, win.score_ewma, win.blocked_until),
            )
        conn.commit()


def load_identity_state(db_path: str | Path, id_store: IdentityStore) -> None:
    db_path = Path(db_path)
    if not db_path.exists():
        return

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "select identity, seen, score_ewma, blocked_until from identity_state"
        ).fetchall()

    for identity, seen, score_ewma, blocked_until in rows:
        win = id_store.get(identity)
        win.seen = seen
        win.score_ewma = score_ewma
        win.blocked_until = blocked_until
        id_store.update(identity, win)


def checkpoint_state(db_path: str | Path, id_store: IdentityStore) -> None:
    init_state_db(db_path)
    save_identity_state(db_path, id_store)


async def start_checkpoint_loop(
    db_path: str | Path,
    id_store: IdentityStore,
    interval_secs: int = 60,
) -> None:
    while True:
        await asyncio.sleep(interval_secs)
        checkpoint_state(db_path, id_store)
