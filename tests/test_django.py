from adiuvare import Guard
from adiuvare.integrations.django import AdiuvareMiddleware


class DummyReq:
    def __init__(self, path: str, method: str = "GET", body: bytes = b"", headers=None, ip: str = "127.0.0.1"):
        self.path = path
        self.method = method
        self.body = body
        self.headers = headers or {}
        self.META = {"REMOTE_ADDR": ip}


class DummyRes:
    def __init__(self, status: int) -> None:
        self.status_code = status


def test_django_middleware_allows_clean_request():
    guard = Guard()
    mw = AdiuvareMiddleware(lambda req: DummyRes(200), guard)
    req = DummyReq("/ping", headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u1"})
    res = mw(req)
    assert res.status_code == 200
    assert req.adiuvare_event is not None


def test_django_middleware_blocks_banned_identity():
    guard = Guard()
    guard._id_store.set_blocked("u1", 60)
    mw = AdiuvareMiddleware(lambda req: DummyRes(200), guard)
    req = DummyReq("/ping", headers={"User-Agent": "Mozilla/5.0", "x-user-id": "u1"})
    res = mw(req)
    assert res.status_code == 429
