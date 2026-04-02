import pytest

from adiuvare.config import SignalWeights, Thresholds


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
