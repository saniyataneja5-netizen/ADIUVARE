from .models import PolicyDecision

_rank = {
    "allow": 0,
    "flag": 1,
    "throttle": 2,
    "block": 3,
}


def _raise_to(now: str, want: str) -> str:
    if _rank[want] > _rank[now]:
        return want
    return now


def reach_verdict(
    score: float,
    snap=None,
    payload_risk: float = 0.0,
    identity_risk: float = 0.0,
    ai_verdict: str = "",
    ai_conf: float = 0.0,
    ai_mode: str = "off",
) -> PolicyDecision:
    block = snap.block_threshold if snap else 0.80
    throttle = snap.throttle_threshold if snap else 0.55
    flag = snap.flag_threshold if snap else 0.25

    verdict = "allow"
    if payload_risk >= 0.85:
        verdict = "throttle"
    elif payload_risk >= 0.70:
        verdict = "flag"

    if score >= block:
        verdict = _raise_to(verdict, "block")
    elif score >= throttle:
        verdict = _raise_to(verdict, "throttle")
    elif score >= flag:
        verdict = _raise_to(verdict, "flag")

    if identity_risk >= 0.85:
        verdict = _raise_to(verdict, "block")
    elif identity_risk >= 0.60:
        verdict = _raise_to(verdict, "throttle")

    if ai_mode == "critical" and ai_verdict == "malicious" and ai_conf >= 0.60:
        verdict = _raise_to(verdict, "block")
    elif ai_mode in {"assist", "critical"} and ai_verdict == "suspicious" and ai_conf >= 0.50:
        verdict = _raise_to(verdict, "throttle")

    logged = verdict
    if snap and getattr(snap, "observe_only", False) and verdict in {"throttle", "block"}:
        verdict = "allow"

    return PolicyDecision(verdict=verdict, logged=logged)
