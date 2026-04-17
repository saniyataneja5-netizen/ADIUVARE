from .policy_engine import reach_verdict


def compute_verdict(
    score: float,
    snap=None,
    identity_risk: float = 0.0,
    payload_risk: float = 0.0,
    ai_verdict: str = "",
    ai_conf: float = 0.0,
    ai_mode: str = "off",
) -> str:
    return reach_verdict(
        score,
        snap=snap,
        payload_risk=payload_risk,
        identity_risk=identity_risk,
        ai_verdict=ai_verdict,
        ai_conf=ai_conf,
        ai_mode=ai_mode,
    ).verdict
