import os
from pathlib import Path

import yaml

from ..core.models import ConfigSnapshot
from .schema import AdiuvareConfig, PRESETS


def load_config(path: str | Path | None = None, preset: str = "balanced") -> AdiuvareConfig:
    base = PRESETS[preset].model_copy(deep=True).model_dump()
    data = {}

    if path:
        file_data = yaml.safe_load(Path(path).read_text()) or {}
        data = file_data

    merged = _merge_dicts(base, data)
    merged = _env_overrides(merged)
    return AdiuvareConfig.model_validate(merged)


def build_snapshot(cfg: AdiuvareConfig) -> ConfigSnapshot:
    return ConfigSnapshot(
        payload_weight=cfg.weights.payload,
        behavior_weight=cfg.weights.behavior,
        identity_weight=cfg.weights.identity,
        flag_threshold=cfg.thresholds.flag,
        throttle_threshold=cfg.thresholds.throttle,
        block_threshold=cfg.thresholds.block,
        observe_only=cfg.runtime.observe_only,
        ai_mode=cfg.ai.mode,
    )


def _merge_dicts(base: dict, patch: dict) -> dict:
    out = dict(base)
    for key, val in patch.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _merge_dicts(out[key], val)
        else:
            out[key] = val
    return out


def _env_overrides(data: dict) -> dict:
    if ai_mode := os.getenv("ADIUVARE_AI_MODE"):
        data.setdefault("ai", {})
        data["ai"]["mode"] = ai_mode
        data["ai"]["enabled"] = ai_mode != "off"

    if observe := os.getenv("ADIUVARE_OBSERVE_ONLY"):
        data.setdefault("runtime", {})
        data["runtime"]["observe_only"] = observe.lower() in {"1", "true", "yes", "on"}

    if block := os.getenv("ADIUVARE_BLOCK_THRESHOLD"):
        data.setdefault("thresholds", {})
        data["thresholds"]["block"] = float(block)

    return data
