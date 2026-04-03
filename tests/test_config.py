import pytest

from adiuvare.config import SignalWeights, Thresholds, build_snapshot, load_config
from adiuvare.config.schema import AdiuvareConfig, PRESETS


def test_signal_weights_default_shape():
    weights = SignalWeights()
    assert weights.payload == 0.40
    assert weights.behavior == 0.35
    assert weights.identity == 0.25


def test_thresholds_default_shape():
    thresholds = Thresholds()
    assert thresholds.flag == 0.25
    assert thresholds.throttle == 0.55
    assert thresholds.block == 0.80


def test_thresholds_reject_bad_order():
    with pytest.raises(ValueError):
        Thresholds(flag=0.70, throttle=0.50, block=0.80)


def test_adiuvare_config_builds_with_runtime_and_ai():
    cfg = AdiuvareConfig()
    assert cfg.runtime.audit_db_path == ".adiuvare/audit.db"
    assert cfg.ai.mode == "off"


def test_presets_keep_distinct_thresholds():
    assert PRESETS["strict"].thresholds.block == 0.70
    assert PRESETS["balanced"].thresholds.block == 0.80


def test_load_config_reads_yaml(tmp_path):
    cfg_path = tmp_path / "adiuvare.yaml"
    cfg_path.write_text(
        """
weights:
  payload: 0.50
runtime:
  observe_only: true
"""
    )

    cfg = load_config(cfg_path)
    assert cfg.weights.payload == 0.50
    assert cfg.runtime.observe_only is True


def test_load_config_applies_env_overrides(monkeypatch):
    monkeypatch.setenv("ADIUVARE_AI_MODE", "assist")
    monkeypatch.setenv("ADIUVARE_BLOCK_THRESHOLD", "0.72")
    cfg = load_config()
    assert cfg.ai.mode == "assist"
    assert cfg.thresholds.block == 0.72


def test_build_snapshot_pulls_runtime_values():
    snap = build_snapshot(AdiuvareConfig())
    assert snap.payload_weight == 0.40
    assert snap.block_threshold == 0.80
