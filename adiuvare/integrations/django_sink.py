from .sqlalchemy import AdiuvareBlockError, check_statement


def wrap_query(guard, execute):
    def inner(statement: str, *args, sink_mode: str = "async", identity: str | None = None, **kwargs):
        check_statement(
            guard,
            statement,
            sink_mode=sink_mode,
            identity=identity,
        )
        return execute(statement, *args, **kwargs)

    return inner


def attach_django_sink(connection, guard) -> None:
    connection._adiuvare_guard = guard
