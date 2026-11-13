"""The tenant session prelude every RLS transaction runs waits on the server twice, not once per setting.

A read opens a dozen tenant transactions. Each blocking round trip releases the
GIL, and while an ingest keeps another thread busy, taking it back again costs
up to the 5 ms switch interval. So the number of blocking round trips a read
makes, not the SQL it runs, sets its latency during an ingest. A proxy that
holds every server reply for ``_REPLY_DELAY`` seconds makes each round trip
visible as wall time.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Iterator

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres round-trip measurements",
)

_REPLY_DELAY = 0.04


def _forward(source: socket.socket, sink: socket.socket, delay: float) -> None:
    try:
        while data := source.recv(65536):
            if delay:
                time.sleep(delay)
            sink.sendall(data)
    except OSError:
        pass  # Either side closed; the other forwarder ends the pair.
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Already closed by the peer forwarder.


@pytest.fixture
def delayed_reply_dsn() -> Iterator[str]:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(os.environ["AGENT_BOM_POSTGRES_URL"])
    upstream = (str(params.get("host") or "127.0.0.1"), int(params.get("port") or 5432))
    listener = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except OSError:
                return
            server = socket.create_connection(upstream)
            for sock in (client, server):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=_forward, args=(client, server, 0.0), daemon=True).start()
            threading.Thread(target=_forward, args=(server, client, _REPLY_DELAY), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    from agent_bom.api.postgres_common import resolve_postgres_secret

    # The URL may carry no password; the app reads it from a file the same way the pool does.
    if (secret := resolve_postgres_secret()) is not None:
        params["password"] = secret
    params.update(host="127.0.0.1", port=str(listener.getsockname()[1]), sslmode="disable")
    try:
        yield make_conninfo(**params)
    finally:
        stop.set()
        listener.close()


def _prelude_round_trips(dsn: str, *, repeatable_read: bool) -> tuple[float, tuple]:
    import psycopg

    from agent_bom.api import postgres_common

    token = postgres_common.set_current_tenant("tenant-round-trips")
    try:
        with psycopg.connect(dsn) as conn:
            best = float("inf")
            for _ in range(5):
                conn.rollback()
                began = time.perf_counter()
                postgres_common._apply_tenant_session(conn, repeatable_read=repeatable_read)
                best = min(best, time.perf_counter() - began)
            settings = conn.execute(
                "SELECT current_setting('app.tenant_id'), current_setting('app.bypass_rls'),"
                " current_setting('transaction_isolation'), current_setting('transaction_read_only')"
            ).fetchone()
            conn.rollback()
    finally:
        postgres_common.reset_current_tenant(token)
    return best / _REPLY_DELAY, tuple(settings or ())


@pytest.mark.parametrize(
    ("repeatable_read", "isolation", "read_only"),
    [(False, "read committed", "off"), (True, "repeatable read", "on")],
)
def test_tenant_session_prelude_waits_twice_not_once_per_setting(delayed_reply_dsn, monkeypatch, repeatable_read, isolation, read_only):
    from agent_bom.api import postgres_common

    monkeypatch.setattr(postgres_common, "POSTGRES_STATEMENT_TIMEOUT_MS", 30_000, raising=False)

    round_trips, settings = _prelude_round_trips(delayed_reply_dsn, repeatable_read=repeatable_read)

    # BEGIN, the isolation level and three set_config calls used to wait in turn: four or five delays. psycopg
    # still syncs a pipelined BEGIN on its own, so the floor is two: BEGIN, then everything else. The bound leaves room
    # for a loaded runner and stays below the four waits the unpipelined prelude cannot go under.
    assert round_trips < 3.5, f"tenant session prelude took {round_trips:.1f} reply delays"
    assert settings == ("tenant-round-trips", "0", isolation, read_only)
