import json
from collections import Counter
from typing import Any


def build_report(rows: list[dict[str, Any]], runtime: dict[str, Any], *, window: str) -> dict[str, Any]:
    counts = Counter(str(row.get("verdict", "allow")) for row in rows)
    signal_pressure = Counter()
    identity_counts = Counter()
    endpoint_counts = Counter()

    top_row = None
    top_score = -1.0
    for row in rows:
        identity_counts[str(row.get("identity", "?"))] += 1
        endpoint_counts[str(row.get("endpoint", "?"))] += 1
        for name, score in (row.get("breakdown") or {}).items():
            signal_pressure[str(name)] += float(score)
        score = float(row.get("score", 0.0) or 0.0)
        if score >= top_score:
            top_score = score
            top_row = row

    total = len(rows)
    block_rate = round((counts.get("block", 0) / total) * 100.0, 1) if total else 0.0
    top_signal = signal_pressure.most_common(1)[0][0] if signal_pressure else "none"

    summary = (
        f"Reviewed {total} events from the {window} window. "
        f"Decision mix: allow={counts.get('allow', 0)}, flag={counts.get('flag', 0)}, "
        f"throttle={counts.get('throttle', 0)}, block={counts.get('block', 0)}. "
        f"Dominant signal pressure: {top_signal}."
    )

    findings = []
    if counts.get("block", 0):
        findings.append(f"Block rate is {block_rate:.1f}% across the current {window} window.")
    if top_signal != "none":
        findings.append(f"{top_signal} is the strongest repeated signal family in recent events.")
    if identity_counts:
        ident, seen = identity_counts.most_common(1)[0]
        findings.append(f"Most active identity in the current window: {ident} ({seen} events).")
    if top_row is not None:
        findings.append(
            f"Highest recent score was {float(top_row.get('score', 0.0)):.3f} on "
            f"{top_row.get('endpoint', '?')} for {top_row.get('identity', '?')}."
        )

    recommendations = []
    if top_signal == "payload":
        recommendations.append("Review payload thresholds and payload-focused routes first.")
    elif top_signal == "behavior":
        recommendations.append("Review bursty traffic and rate behavior on the busiest routes.")
    elif top_signal == "identity":
        recommendations.append("Review repeated identity activity and whether caller state should tighten.")

    if counts.get("flag", 0) > counts.get("block", 0):
        recommendations.append("Review whether the block threshold is too high for the current traffic mix.")
    if not runtime.get("ai_enabled", False):
        recommendations.append("AI enrichment is off. Enable it only on the routes where deeper triage helps.")
    if runtime.get("backend") == "redis" and runtime.get("instances") == "single":
        recommendations.append("Redis is active in single-instance mode; keep multi-instance claims conservative.")
    if not recommendations:
        recommendations.append("Current traffic looks stable; keep monitoring before changing thresholds.")

    return {
        "window": window,
        "source": "local",
        "summary": summary,
        "stats": {
            "events": total,
            "allow": counts.get("allow", 0),
            "flag": counts.get("flag", 0),
            "throttle": counts.get("throttle", 0),
            "block": counts.get("block", 0),
            "blocked": counts.get("block", 0),
            "flagged": counts.get("flag", 0),
            "block_rate": block_rate,
        },
        "top_identities": [
            {"identity": identity, "count": count}
            for identity, count in identity_counts.most_common(5)
        ],
        "top_endpoints": [
            {"endpoint": endpoint, "count": count}
            for endpoint, count in endpoint_counts.most_common(5)
        ],
        "signal_pressure": [
            {"signal": name, "score": round(score, 3)}
            for name, score in signal_pressure.most_common()
        ],
        "findings": findings,
        "recommendations": recommendations,
    }


def report_prompt(report: dict[str, Any]) -> str:
    return (
        "You are summarizing a security runtime report.\n"
        "Use the provided local summary and reply with JSON only.\n"
        'Return exactly: {"summary":"...","findings":["..."],"recommendations":["..."]}\n'
        f"local_report: {json.dumps(report)}"
    )


def report_summary_prompt(report: dict[str, Any]) -> str:
    return (
        "You are summarizing a security runtime report for an operator dashboard.\n"
        "Reply with one short paragraph only.\n"
        f"local_report: {json.dumps(report)}"
    )


def analyst_prompt(question: str, report: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    sample = rows[:15]
    return (
        "You are answering a security operator question about recent API events.\n"
        "Be concise, grounded in the supplied report, and avoid making up unsupported actions.\n"
        f"question: {question}\n"
        f"report: {json.dumps(report)}\n"
        f"recent_rows: {json.dumps(sample)}\n"
        "Reply with plain text only."
    )


def local_analyst_answer(question: str, report: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    q = question.strip().lower()
    top_identity = report.get("top_identities", [{}])[0]
    top_endpoint = report.get("top_endpoints", [{}])[0]
    top_signal = report.get("signal_pressure", [{}])[0]
    stats = report.get("stats", {})

    if "identity" in q and top_identity:
        return (
            f"The most active identity in the current window is {top_identity.get('identity', '?')} "
            f"with {top_identity.get('count', 0)} events."
        )
    if "endpoint" in q or "route" in q:
        return (
            f"The busiest endpoint in the current window is {top_endpoint.get('endpoint', '?')} "
            f"with {top_endpoint.get('count', 0)} events."
        )
    if "signal" in q:
        return (
            f"The strongest repeated signal family right now is {top_signal.get('signal', 'none')} "
            f"with aggregate pressure {top_signal.get('score', 0.0)}."
        )
    if "threshold" in q or "config" in q:
        return (
            f"Current block rate is {stats.get('block_rate', 0.0)}%. "
            f"Start by reviewing the block threshold and payload-heavy routes before broader config changes."
        )
    if "top threat" in q or "biggest" in q or "worst" in q:
        scored = sorted(rows, key=lambda row: float(row.get("score", 0.0) or 0.0), reverse=True)
        if scored:
            row = scored[0]
            return (
                f"The strongest recent event is {row.get('identity', '?')} on {row.get('endpoint', '?')} "
                f"with score {float(row.get('score', 0.0)):.3f} and verdict {row.get('verdict', 'allow')}."
            )

    return report.get("summary", "Recent traffic looks quiet.")
