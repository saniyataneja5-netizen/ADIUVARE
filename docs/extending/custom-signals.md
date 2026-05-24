# Custom Signals

Custom signals are how you teach Adiuvare about rules that only make sense in
your app. Use a soft signal when you want to add score, and a hard signal when
you want to stop a request immediately.

## Quick example

```python
from adiuvare import Guard
from adiuvare.core.models import SignalResult
from adiuvare.signals import SoftSignal


class SuspiciousHeaderSignal(SoftSignal):
    name = "header_hint"
    weight = 0.10

    async def extract(self, ctx):
        agent = ctx.headers.get("user-agent", "")
        if "sqlmap" in agent.lower():
            return SignalResult(score=0.25, reason="sqlmap_ua")
        return SignalResult(score=0.0, reason="clean")


guard = Guard.from_config("adiuvare.yaml", soft_signals=[SuspiciousHeaderSignal()])
gate, event = guard.check_sync(
    "user:42",
    context={"path": "/search", "method": "GET", "headers": {"user-agent": "sqlmap/1.8"}},
)

print(gate.passed)
print(event.detail["signal_reasons"]["header_hint"] if event else None)
```

```text
True
sqlmap_ua
```

The request still passed `trackA`, but the scored event kept your custom reason
for later review.

## SoftSignal

Use `SoftSignal` when you want to add risk without forcing a block. Good uses
include hostile client fingerprints, tenant-specific headers, or route-family
heuristics that should influence scoring.

```python
class SoftSignal:
    name: str = "unnamed"
    weight: float = 0.10

    async def extract(self, ctx: RequestContext) -> SignalResult:
        ...
```

`name` is the label that shows up in signal breakdowns. Keep it short and
stable. `weight` controls how much the signal family matters in the final
score.

`extract()` receives a `RequestContext` and returns a `SignalResult`. Most
custom signals read a small subset of the context:

- `ctx.identity`
- `ctx.payload`
- `ctx.headers`
- `ctx.endpoint`
- `ctx.method`
- `ctx.ip`
- `ctx.sensitivity`
- `ctx.snapshot`

Return `score=0.0` for the quiet path. Use `reason` for the short label you
want preserved in event detail.

### SignalResult

```python
SignalResult(
    score: float,
    reason: str,
    detail: dict[str, Any] = {},
    exception: Exception | None = None,
)
```

You will usually set `score`, `reason`, and sometimes `detail`. The runtime
will preserve those fields in the event.

Example:

```python
from adiuvare.core.models import SignalResult

res = SignalResult(
    score=0.42,
    reason="tenant_header",
    detail={"header": "x-tenant", "value": "red-team"},
)

print(res.score)
print(res.reason)
print(res.detail["header"])
```

```text
0.42
tenant_header
x-tenant
```

## HardSignal

Use `HardSignal` when a request should stop in `trackA` before the slower
scoring path matters.

```python
class HardSignal:
    name: str = "unnamed"
    action: str = "block"

    def check(self, ctx: RequestContext) -> bool:
        ...
```

`action` is usually `"block"` or `"hold"`. `check()` must stay synchronous and
fast. It should return `True` only for the cases you want to stop immediately.

Example:

```python
from adiuvare import Guard
from adiuvare.signals import HardSignal


class PrivatePathSignal(HardSignal):
    name = "private_path"
    action = "block"

    def check(self, ctx):
        return ctx.endpoint.startswith("/_internal")


guard = Guard.from_config("adiuvare.yaml", hard_signals=[PrivatePathSignal()])
gate, event = guard.check_sync(
    "user:42",
    context={"path": "/_internal/jobs", "endpoint": "/_internal/jobs", "method": "GET"},
)

print(gate.passed)
print(gate.block_reason)
print(event)
```

```text
False
private_path
None
```

There is no scored event here because the fast gate stopped the request first.

### validate_hard_signal()

```python
validate_hard_signal(sig: HardSignal) -> None
```

Use this when you want to verify that a hard signal is valid before wiring it
into `Guard`.

```python
from adiuvare.signals import AdiuvareStartupError, HardSignal, validate_hard_signal


class BadHardSignal(HardSignal):
    async def check(self, ctx):
        return True


try:
    validate_hard_signal(BadHardSignal())
except AdiuvareStartupError as exc:
    print(str(exc))
```

```text
BadHardSignal.check() must stay sync in track a
```

> Hard signals run in `trackA`. Keep them synchronous and deterministic.
 ## Choosing Between HardSignal and SoftSignal

Use a HardSignal when the condition is high-confidence, deterministic, and should stop a request immediately in trackA.

Examples:
- obvious leaked credentials
- known malicious paths
- requests targeting internal-only endpoints
- exact matches for blocked indicators

Hard signals should remain:
- synchronous
- cheap to evaluate
- deterministic
- free of expensive network or database calls

Use a SoftSignal when the condition contributes risk but should not automatically block a request.

Examples:
- suspicious user-agent strings
- unusual request patterns
- tenant-specific heuristics
- context-dependent indicators

Soft signals contribute to the scored trackB path and allow multiple weaker indicators to combine into a final risk decision.

### Testing Guidance

Before opening a PR:

- Verify HardSignal behavior through `guard.check_sync(...)` or the real guard path.
- Verify SoftSignal scoring through the resulting event score and signal breakdown.
- Avoid testing signals only in isolation when the real guard path can be exercised.

### Quick Decision Guide

| Question | HardSignal | SoftSignal |
|----------|------------|------------|
| Should the request stop immediately? | Yes | No |
| Is the condition deterministic? | Yes | Usually not required |
| Runs in trackA? | Yes | No |
| Contributes risk score? | No | Yes |
| Should remain fast and synchronous? | Yes | Not required |

## Registering signals

### Guard.from_config()

```python
guard = Guard.from_config(
    "adiuvare.yaml",
    soft_signals=[SuspiciousHeaderSignal()],
)
```

Passing `soft_signals=[...]` replaces the default soft-signal list with your
own.

### PayloadSignal

If you still want Adiuvare's built-in payload scanner in that custom list, add
`PayloadSignal()` explicitly.

```python
from adiuvare.signals import PayloadSignal

guard = Guard.from_config(
    "adiuvare.yaml",
    soft_signals=[PayloadSignal(), SuspiciousHeaderSignal()],
)
```

### hard_signals

```python
guard = Guard.from_config(
    "adiuvare.yaml",
    hard_signals=[PrivatePathSignal()],
)
```

## Good habits

- keep `name` short and stable
- keep `reason` short and readable
- return `score=0.0` when the signal is quiet
- use hard signals only for cases you really want to stop immediately
- keep hard signals fast

## Related

- [Built-in signals](../signals.md)
- [Signals API](../api/signals.md)
- [Route policies](route-policies.md)
- [Guard API](../api/guard.md)
