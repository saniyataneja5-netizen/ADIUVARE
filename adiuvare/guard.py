import asyncio
import contextlib
from pathlib import Path
from typing import Any
from functools import wraps

from .config import build_snapshot, load_config
from .core.events import EventHooks
from .core.gate import configure_trackA, run_trackA
from .core.models import RequestContext
from .core.pipeline import Pipeline
from .policies import BUILTIN_POLICIES
from .signals.behavior import BehaviorSignal
from .signals.context import ContextSignal
from .signals.identity import IdentitySignal
from .signals.ip_rep import IPRepSignal
from .signals.payload import PayloadSignal
from .state.audit_log import AuditLog
from .state.event_stream import RedisEventStream, UnixSocketEventStream
from .state.identity_store import IdentityStore, ThreadSafeIdentityStore
from .state.persistence import checkpoint_state, load_identity_state, start_checkpoint_loop
from .state.whitelist import WhitelistStore


class Guard:
    def __init__(
        self,
        preset: str = "balanced",
        config_path: str | Path | None = None,
        soft_signals: list | None = None,
        hard_signals: list | None = None,
        flaskmode: bool = False,
    ) -> None:
        self._cfg = load_config(config_path, preset=preset)
        self._cfg_snap = build_snapshot(self._cfg)
        self._id_store = ThreadSafeIdentityStore() if flaskmode else IdentityStore()
        self._wl = WhitelistStore()
        self._hard_sigs = list(hard_signals or [])
        Path(".adiuvare").mkdir(exist_ok=True)
        self._state_DBpath = Path(self._cfg.runtime.state_db_path)
        self._audit = AuditLog(self._cfg.runtime.audit_db_path)
        sigs = soft_signals or [
            PayloadSignal(),
            BehaviorSignal(self._id_store),
            IdentitySignal(self._id_store),
            ContextSignal(),
            IPRepSignal(),
        ]
        self._pipeline = Pipeline(self._id_store, soft_signals=sigs)
        self._hooks = EventHooks()
        self._stream = self._mkstream()
        if hasattr(self._stream, "set_command_handler"):
            self._stream.set_command_handler(self.handlestreamcmd)
        self.policies = dict(BUILTIN_POLICIES)
        self._route_cfg: dict[str, Any] = {}
        self._last_identity: str | None = None
        self._last_sink: dict[str, Any] | None = None
        self._bg_task: asyncio.Task | None = None
        self._bg_started = False
        configure_trackA(wl=self._wl, hard_sigs=self._hard_sigs)

    @property
    def hooks(self) -> EventHooks:
        return self._hooks

    @property
    def config(self):
        return self._cfg

    @property
    def pipeline(self):
        return self._pipeline

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        preset: str = "balanced",
        soft_signals: list | None = None,
        hard_signals: list | None = None,
    ):
        return cls(
            preset=preset,
            config_path=config_path,
            soft_signals=soft_signals,
            hard_signals=hard_signals,
        )

    @classmethod
    def auto(
        cls,
        app: Any,
        preset: str = "balanced",
        config_path: str | Path | None = None,
        soft_signals: list | None = None,
        hard_signals: list | None = None,
    ):
        guard = cls(
            preset=preset,
            config_path=config_path,
            soft_signals=soft_signals,
            hard_signals=hard_signals,
            flaskmode=hasattr(app, "wsgi_app"),
        )
        if hasattr(app, "wsgi_app"):
            guard.use(app, framework="flask")
        else:
            guard.use(app, framework="fastapi")
        return guard

    async def inspect(self, ctx: RequestContext):
        if ctx.snapshot is None:
            ctx.snapshot = self._cfg_snap

        self._last_identity = ctx.identity
        gate = run_trackA(ctx, self._id_store)
        if not gate.passed:
            self._hooks.emit_block(gate)
            return gate, None

        event = await self._pipeline.trackB(ctx)
        if event is not None:
            await self._stream.emit(event)
            self._audit.write(event)
        if event is not None:
            self._hooks.emit_event(event)
        return gate, event

    def handle(self, ctx: RequestContext):
        return self.inspect(ctx)

    @property
    def event_stream(self):
        return self._stream

    @property
    def whitelist(self):
        return self._wl

    def record_sink_detection(
        self,
        *,
        statement: str,
        normalised: str,
        confidence: float,
        fingerprint: str = "",
    ) -> None:
        self._last_sink = {
            "statement": statement,
            "normalised": normalised,
            "confidence": confidence,
            "fingerprint": fingerprint,
        }
        self._audit.write_patch("sink_hit", self._last_sink)

    def elevate_identity_from_sink(self, identity: str | None = None) -> None:
        who = identity or self._last_identity
        if not who:
            return
        self._id_store.apply_score(who, 0.85)

    def checkpoint(self) -> None:
        checkpoint_state(self._state_DBpath, self._id_store)

    async def startbgtasks(self) -> None:
        if self._bg_started:
            return

        load_identity_state(self._state_DBpath, self._id_store)
        await self._stream.start()
        self._bg_task = asyncio.create_task(
            start_checkpoint_loop(self._state_DBpath, self._id_store)
        )
        self._bg_started = True

    async def shutdown(self) -> None:
        if self._bg_task is not None:
            self._bg_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._bg_task
            self._bg_task = None

        self.checkpoint()
        await self._stream.stop()
        self._bg_started = False

    def runtimesnapshot(self) -> dict[str, Any]:
        recent = self._stream.recent() if hasattr(self._stream, "recent") else []
        return {
            "ai_mode": self._cfg_snap.ai_mode,
            "observe_only": self._cfg_snap.observe_only,
            "hard_sigs": [sig.name for sig in self._hard_sigs],
            "whitelist_size": len(self._wl._ids),
            "recent_events": len(recent),
            "state_db": str(self._state_DBpath),
        }

    async def handlestreamcmd(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "get_runtime_snapshot":
            return self.runtimesnapshot()

        if name == "confirm_block":
            identity = str(args["identity"])
            ttl = int(args.get("ttl_secs", 900))
            self._id_store.set_blocked(identity, ttl)
            self.checkpoint()
            return {"ok": True, "identity": identity, "ttl_secs": ttl}

        if name == "unblock_whitelist":
            identity = str(args["identity"])
            self._id_store.clear_block(identity)
            self._wl.add(identity)
            self.checkpoint()
            return {"ok": True, "identity": identity}

        if name == "unblock_note":
            note = str(args.get("note", "")).strip()
            identity = str(args.get("identity", ""))
            self._audit.write_patch("unblock_note", {"identity": identity, "note": note})
            return {"ok": True, "identity": identity}

        if name == "patch_config":
            changes = args.get("changes") or {}
            if "ai_mode" in changes:
                self._cfg.ai.mode = str(changes["ai_mode"])
                self._cfg.ai.enabled = self._cfg.ai.mode != "off"
            if "observe_only" in changes:
                self._cfg.runtime.observe_only = bool(changes["observe_only"])
            if "block_threshold" in changes:
                self._cfg.thresholds.block = float(changes["block_threshold"])
            self._cfg_snap = build_snapshot(self._cfg)
            self._audit.write_patch("patch_config", changes)
            return self.runtimesnapshot()

        raise ValueError(f"unknown stream command: {name}")

    def policy(self, name: str, **overrides: Any):
        pol = self.policies.get(name)
        if pol is None:
            raise ValueError(f"unknown policy: {name}")
        return self.protect(**pol.with_overrides(**overrides).__dict__)

    def protect(
        self,
        sensitivity: str = "internal",
        ai_mode: str = "off",
        trackB: bool = True,
        sink_mode: str = "off",
    ):
        def deco(fn):
            cfg = {
                "sensitivity": sensitivity,
                "ai_mode": ai_mode,
                "trackB": trackB,
                "sink_mode": sink_mode,
            }

            @wraps(fn)
            async def wrap(*args, **kwargs):
                return await fn(*args, **kwargs)

            wrap._adiuvare_cfg = cfg
            return wrap

        return deco

    def exempt(self):
        def deco(fn):
            @wraps(fn)
            async def wrap(*args, **kwargs):
                return await fn(*args, **kwargs)

            wrap._adiuvare_exempt = True
            return wrap

        return deco

    def configure_routes(self, routes: dict[str, Any]):
        self._route_cfg.update(routes)
        return self

    def use(self, app: Any, framework: str = "fastapi") -> None:
        if framework == "fastapi":
            from .integrations.fastapi import AdiuvareMiddleware

            app.add_middleware(AdiuvareMiddleware, guard=self)
            return

        if framework == "flask":
            self._use_flask_store()
            from .integrations.flask import AdiuvareMiddleware

            app.wsgi_app = AdiuvareMiddleware(app.wsgi_app, guard=self)
            return

        if framework == "django":
            from .integrations.django import AdiuvareMiddleware

            app._adiuvare_mw = AdiuvareMiddleware(app, guard=self)
            return

        raise ValueError(f"unsupported framework: {framework}")

    def _mkstream(self):
        if self._cfg.runtime.backend == "redis" and self._cfg.runtime.redis_url:
            return RedisEventStream(
                project="adiuvare",
                redis_url=self._cfg.runtime.redis_url,
            )
        return UnixSocketEventStream()

    def _use_flask_store(self) -> None:
        if isinstance(self._id_store, ThreadSafeIdentityStore):
            return

        store = ThreadSafeIdentityStore()
        for identity, win in self._id_store.items():
            store.update(identity, win)

        self._id_store = store
        self._pipeline._id_store = store
        for sig in self._pipeline._soft_signals:
            if hasattr(sig, "_id_store"):
                sig._id_store = store
