# Django

Django has a smaller integration than FastAPI or Flask, but it still gives you
the same core request path: fast gate, scored inspection, route-aware config,
and direct block or throttle outcomes.

Use the explicit Django attach path here. `Guard.auto(...)` is not the right
shortcut for Django at the moment.

## Quick example

```python
from adiuvare import Guard
from adiuvare.integrations.django import AdiuvareMiddleware

guard = Guard.from_config("adiuvare.yaml")


def adiuvare_middleware(get_response):
    return AdiuvareMiddleware(get_response, guard)
```

Add that wrapper to your Django middleware stack where you want request
inspection to happen.

## What the adapter reads

For each request, the Django adapter pulls:

- request body text
- `QUERY_STRING`
- request headers
- `REMOTE_ADDR`
- the path as the route lookup key

Then it:

1. builds a `RequestContext`
2. applies `trackA`
3. runs `trackB`
4. either returns a small direct response or continues to the view

Blocked response shape:

```text
status_code: 403
data: {"detail": "blocked"}
```

Throttled response shape:

```text
status_code: 429
data: {"detail": "throttled"}
```

## Route config

The cleanest current path in Django is programmatic route config.

```python
guard.configure_routes(
    {
        "/health": {"exempt": True},
        "/admin/login": {"policy": "admin"},
        "/search": {"policy": "search"},
    }
)
```

That keeps route posture easy to reason about even when your Django URL and
view shape does not make decorators the best control point.

## Query and body scanning

Like the other adapters, Django combines body text and query-string text into
one payload context. That means a hostile query string can influence the same
payload scoring path as a hostile POST body.

## Operator flow

```bash
adv status
adv logs --tail 20
adv
```

Typical connected status:

```text
config: H:\ADIUVARE\adiuvare.yaml
runtime: connected
socket: C:\Users\me\AppData\Local\Temp\adiuvare.sock
backend: sqlite
framework: django
instances: single
observe_only: False
ai_mode: off
banned_ips: 0
recent_events: 3
```

## Current boundaries

Compared with FastAPI and Flask, the Django integration is:

- smaller
- more path-config oriented
- less decorator-driven

That does not make it unusable. It just means the cleanest Django story today
is middleware attach, programmatic route config, and CLI or TUI for operator
visibility.

## Related

- [Configuration](../configuration.md)
- [Route policies](../extending/route-policies.md)
- [Guard API](../api/guard.md)
