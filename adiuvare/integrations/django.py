import asyncio

from . import build_http_ctx


class JsonResponse:
    def __init__(self, data: dict, status: int = 200) -> None:
        self.data = data
        self.status_code = status


class AdiuvareMiddleware:
    def __init__(self, get_response, guard) -> None:
        self._get_response = get_response
        self._guard = guard

    def __call__(self, request):
        raw = getattr(request, "body", b"")
        if callable(raw):
            raw = raw()
        if isinstance(raw, bytes):
            body = raw.decode(errors="replace")
        else:
            body = raw or None

        headers = dict(getattr(request, "headers", {}))
        meta = getattr(request, "META", {})
        path = getattr(request, "path", "/")
        method = getattr(request, "method", "GET")
        identity = headers.get("x-user-id", meta.get("REMOTE_USER", "anon"))
        ip = meta.get("REMOTE_ADDR", "127.0.0.1")

        ctx = build_http_ctx(
            identity=identity,
            payload=body,
            url=path,
            method=method,
            headers=headers,
            ip=ip,
            endpoint=path,
            snapshot=self._guard._cfg_snap,
        )
        gate, event = asyncio.run(self._guard.inspect(ctx))
        if not gate.passed:
            return JsonResponse({"detail": gate.block_reason or "blocked"}, status=gate.status_code)

        request.adiuvare_event = event
        return self._get_response(request)
