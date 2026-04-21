from ..vendor import detect_sqli, normalize


class AdiuvareBlockError(Exception):
    pass


def check_statement(
    guard,
    statement: str,
    *,
    sink_mode: str = "async",
    identity: str | None = None,
) -> None:
    cleaned = normalize(statement)
    res = detect_sqli(cleaned)
    if not res["hit"]:
        return

    guard.record_sink_detection(
        statement=statement,
        normalised=cleaned,
        confidence=res["conf"],
        fingerprint=res.get("fp", ""),
    )

    if sink_mode == "inline":
        raise AdiuvareBlockError("blocked_at_sink")

    guard.elevate_identity_from_sink(identity)


def attach_sink(engine, guard) -> None:
    engine._adiuvare_guard = guard
