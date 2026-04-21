import pytest

from adiuvare import Guard
from adiuvare.integrations.django_sink import wrap_query
from adiuvare.integrations.sqlalchemy import AdiuvareBlockError, check_statement


def test_sqlalchemy_sink_can_block_inline():
    guard = Guard()
    with pytest.raises(AdiuvareBlockError):
        check_statement(
            guard,
            "select * from users where id = '' or 1=1",
            sink_mode="inline",
            identity="u1",
        )


def test_sqlalchemy_sink_can_elevate_identity_async():
    guard = Guard()
    check_statement(
        guard,
        "select * from users where id = '' or 1=1",
        sink_mode="async",
        identity="u1",
    )
    assert guard._id_store.get("u1").score_ewma > 0.0


def test_django_sink_wrapper_uses_same_check():
    guard = Guard()
    seen = []

    def execute(statement, *args, **kwargs):
        seen.append(statement)
        return "ok"

    wrapped = wrap_query(guard, execute)
    out = wrapped("select * from users", sink_mode="async", identity="u1")
    assert out == "ok"
    assert seen == ["select * from users"]
