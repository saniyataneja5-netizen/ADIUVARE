from pathlib import Path
from typing import Any

import yaml

from .schema import PRESETS


def merge_sections(path: str | Path, changes: dict[str, Any]) -> dict[str, Any]:
    file_path = Path(path)
    raw = _read_yaml(file_path)
    _merge(raw, changes)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return raw


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return loaded if isinstance(loaded, dict) else {}


def _merge(base: dict[str, Any], changes: dict[str, Any]) -> None:
    for key, val in changes.items():
        if isinstance(base.get(key), dict) and isinstance(val, dict):
            _merge(base[key], val)
        else:
            base[key] = val


def starter_config(
    *,
    framework: str,
    instances: str,
    strictness: str,
    mode: str,
    ai_mode: str,
    ai_model: str = "llama3",
    ai_api_key: str | None = None,
) -> dict[str, Any]:
    preset = "strict" if strictness == "critical" else "balanced"
    cfg = PRESETS[preset].model_copy(deep=True)
    cfg.runtime.observe_only = mode == "observe"
    cfg.ai.mode = ai_mode
    cfg.ai.enabled = ai_mode != "off"
    cfg.ai.model = ai_model.strip() or cfg.ai.model
    cfg.ai.api_key = ai_api_key.strip() if ai_api_key else None
    cfg.meta.framework = framework
    cfg.meta.instances = instances
    cfg.meta.strictness = strictness
    return cfg.model_dump()
