import asyncio
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from adiuvare import Guard
from adiuvare.core.models import RequestContext, SignalResult
from adiuvare.signals.base import SoftSignal


class SlowSignal(SoftSignal):
    name = "slow"
    weight = 0.10

    async def extract(self, ctx: RequestContext) -> SignalResult:
        await asyncio.sleep(0.2)
        return SignalResult(score=0.0, reason="slow_clean")


def test_fastapi_middleware_allows_clean_request():
    app = FastAPI()
    guard = Guard()
    guard.use(app, framework="fastapi")

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/ping", headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u1"})
    assert res.status_code == 200
    assert res.json() == {"ok": True}


def test_fastapi_middleware_blocks_when_identity_is_blocked():
    app = FastAPI()
    guard = Guard()
    guard._id_store.set_blocked("u1", 60)
    guard.use(app, framework="fastapi")

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/ping", headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u1"})
    assert res.status_code == 429


def test_fastapi_runs_trackB_in_background():
    app = FastAPI()
    guard = Guard(soft_signals=[SlowSignal()])
    seen = []

    @guard.hooks.on_event
    def _take(event):
        seen.append(event.verdict)

    guard.use(app, framework="fastapi")

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    started = time.perf_counter()
    res = client.get("/ping", headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u2"})
    elapsed = time.perf_counter() - started

    assert res.status_code == 200
    assert elapsed < 0.18
    assert seen == []
    time.sleep(0.3)
    assert seen == ["allow"]


def test_fastapi_returns_hold_for_admin_post():
    app = FastAPI()
    guard = Guard()
    guard.use(app, framework="fastapi")

    @app.post("/admin/login")
    async def login():
        return {"ok": True}

    client = TestClient(app)
    res = client.post(
        "/admin/login",
        content="user=demo",
        headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u3"},
    )
    assert res.status_code == 202
