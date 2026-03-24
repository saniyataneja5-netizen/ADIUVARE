import asyncio

from adiuvare.core.models import RequestContext
from adiuvare.signals.payload import PayloadSignal


def test_payload_stays_clean_when_empty():
    ctx = RequestContext(
        identity="u1",
        payload=None,
        url="/",
        method="GET",
        headers={},
        ip="127.0.0.1",
        endpoint="/",
    )

    res = asyncio.run(PayloadSignal().extract(ctx))
    assert res.score == 0.0


def test_payload_marks_sqlish_text():
    ctx = RequestContext(
        identity="u1",
        payload="select * from users",
        url="/login",
        method="POST",
        headers={},
        ip="127.0.0.1",
        endpoint="/login",
    )

    res = asyncio.run(PayloadSignal().extract(ctx))
    assert res.score == 0.7


def test_payload_marks_script_text():
    ctx = RequestContext(
        identity="u1",
        payload="<script>alert(1)</script>",
        url="/comment",
        method="POST",
        headers={},
        ip="127.0.0.1",
        endpoint="/comment",
    )

    res = asyncio.run(PayloadSignal().extract(ctx))
    assert res.score == 0.6

