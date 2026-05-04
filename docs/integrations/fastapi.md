# FastAPI

FastAPI is still the clearest first integration path in Adiuvare. The route
model is direct, the middleware flow is easy to see, and the operator story is
the least surprising here.

## Quick example

```python
from fastapi import FastAPI

from adiuvare import Guard

app = FastAPI()

guard = Guard.from_config("adiuvare.yaml")
guard.use(app, framework="fastapi")


@app.get("/health")
@guard.exempt()
async def health():
    return {"ok": True}


@app.post("/admin/login")
@guard.policy("admin")
async def admin_login():
    return {"ok": True}
```

That keeps `/health` light and gives `/admin/login` the built-in stricter
admin posture.

## Guard.auto()

If you want the one-liner:

```python
from fastapi import FastAPI

from adiuvare import Guard

app = FastAPI()
guard = Guard.auto(app, config_path="adiuvare.yaml")
```

Use `Guard.from_config(...)` plus `guard.use(...)` when you want the setup
steps to stay explicit in app code.

You can also write `guard.use(app)` directly in FastAPI code. `fastapi` is the
default framework value there.

## What the middleware does

For each request, the FastAPI adapter:

1. ensures the runtime has started
2. reads the request body
3. reads the query string
4. chooses the client IP
5. resolves route config
6. builds a `RequestContext`
7. runs `trackA`
8. runs `trackB` when needed

The adapter prefers `x-forwarded-for` before `request.client.host`, which
matters when the app sits behind a proxy and you want IP bans to use the
forwarded client address.

It combines body text and query-string text into the payload context, so both
can influence the payload signal path.

## Route helpers

Built-in policy:

```python
@app.post("/payments/charge")
@guard.policy("payment")
async def charge():
    return {"ok": True}
```

Explicit posture:

```python
@app.post("/billing")
@guard.protect(
    sensitivity="critical",
    ai_mode="assist",
    sink_mode="inline",
)
async def billing():
    return {"ok": True}
```

Exempt route:

```python
@app.get("/health")
@guard.exempt()
async def health():
    return {"ok": True}
```

## Query and body scanning

Because FastAPI merges query and body text into the same payload context, both
of these can matter:

```bash
curl "http://127.0.0.1:8000/search?q=hello"
curl "http://127.0.0.1:8000/search?q=' UNION SELECT password FROM users--"
curl -X POST http://127.0.0.1:8000/billing -d "select * from users where id = '' or 1=1"
```

Typical clean response:

```text
{"ok":true}
```

Typical stronger responses:

```text
{"detail":"throttled"}
```

or:

```text
{"detail":"blocked"}
```

## Background `trackB`

FastAPI has one important split:

- if `ctx.payload` exists, `trackB` runs inline
- if there is no payload, the request can return first and `trackB` runs in a
  background thread path

That keeps payload-heavy risky requests immediate while cheap harmless GET-style
traffic can stay lighter.

## Operator flow

Once the app is running, the normal operator path is:

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
framework: fastapi
instances: single
observe_only: False
ai_mode: off
banned_ips: 0
recent_events: 3
```

## Related

- [Quickstart](../quickstart.md)
- [Configuration](../configuration.md)
- [Route policies](../extending/route-policies.md)
- [SQLAlchemy sink hooks](sqlalchemy.md)
- [Guard API](../api/guard.md)
