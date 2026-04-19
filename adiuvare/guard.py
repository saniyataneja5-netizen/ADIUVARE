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
from .state.event_stream import UnixSocketEventStream
from .state.identity_store import IdentityStore
from .state.whitelist import WhitelistStore


class Guard:
    def __init__(
        self,
        preset: str = "balanced",
        config_path: str | Path | None = None,
        soft_signals: list | None = None,
        hard_signals: list | None = None,
    ) -> None:
        self._cfg = load_config(config_path, preset=preset)
        self._cfg_snap = build_snapshot(self._cfg)
        self._id_store = IdentityStore()
        self._wl = WhitelistStore()
        self._hard_sigs = list(hard_signals or [])
        sigs = soft_signals or [
            PayloadSignal(),
            BehaviorSignal(self._id_store),
            IdentitySignal(self._id_store),
            ContextSignal(),
            IPRepSignal(),
        ]
        self._pipeline = Pipeline(self._id_store, soft_signals=sigs)
        self._hooks = EventHooks()
        self._stream = UnixSocketEventStream()
        self.policies = dict(BUILTIN_POLICIES)
        self._route_cfg: dict[str, Any] = {}
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
        )
        if hasattr(app, "wsgi_app"):
            guard.use(app, framework="flask")
        else:
            guard.use(app, framework="fastapi")
        return guard

    async def inspect(self, ctx: RequestContext):
        if ctx.snapshot is None:
            ctx.snapshot = self._cfg_snap

        gate = run_trackA(ctx, self._id_store)
        if not gate.passed:
            self._hooks.emit_block(gate)
            return gate, None

        event = await self._pipeline.trackB(ctx)
        if event is not None:
            await self._stream.emit(event)
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
            from .integrations.flask import AdiuvareMiddleware

            app.wsgi_app = AdiuvareMiddleware(app.wsgi_app, guard=self)
            return

        raise ValueError(f"unsupported framework: {framework}")
