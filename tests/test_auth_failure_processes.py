"""Lockout behaviour between separate server and client processes, on both backends.

Each client is its own Python process, and each identifies itself through a
trusted forwarded address so the server sees independent sources.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.timeout(240)

_REPO = Path(__file__).resolve().parents[1]
_ME = "/v1/auth/me"
_CLIENT = """
import http.client, json, sys
port, count, spec = int(sys.argv[1]), int(sys.argv[2]), json.loads(sys.argv[3])
statuses = []
for _ in range(count):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    connection.putrequest(spec.get("method", "GET"), spec.get("path", "/v1/auth/me"))
    for name, value in spec["headers"]:
        connection.putheader(name, value)
    connection.endheaders()
    try:
        statuses.append(connection.getresponse().status)
    except OSError:
        statuses.append(0)
    connection.close()
print(json.dumps(statuses))
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_client(port: int, count: int, headers: list[tuple[str, str]], path: str = _ME, method: str = "GET") -> subprocess.Popen:
    spec = json.dumps({"headers": headers, "path": path, "method": method})
    return subprocess.Popen([sys.executable, "-I", "-c", _CLIENT, str(port), str(count), spec], stdout=subprocess.PIPE, text=True)


def _finish(client: subprocess.Popen) -> list[int]:
    out, _ = client.communicate(timeout=120)
    assert client.returncode == 0
    return json.loads(out)


def _client(port: int, count: int, headers: list[tuple[str, str]], path: str = _ME, method: str = "GET") -> list[int]:
    return _finish(_start_client(port, count, headers, path, method))


# The API process with CPU-bound threads of its own, started on a signal file, that hold
# the interpreter lock in long encode/decode calls as a large ingest and graph read do.
_BUSY_API = """
import json, os, runpy, sys, threading, time
signal_file, workers = sys.argv.pop(1), int(sys.argv.pop(1))
packages = lambda n: [{"name": f"p-{n}-{m}", "version": "1.0"} for m in range(40)]
report = {"agents": [{"name": f"agent-{n}", "packages": packages(n)} for n in range(1500)]}
def burn():
    while not os.path.exists(signal_file):
        time.sleep(0.1)
    while True:
        json.loads(json.dumps(report))
for _ in range(workers):
    threading.Thread(target=burn, daemon=True).start()
sys.argv[0] = "agent-bom"
runpy.run_module("agent_bom", run_name="__main__")
"""


class _Server:
    def __init__(self, env: dict[str, str], log: Path, launcher: list[str] | None = None):
        self.port = _free_port()
        self.key = secrets.token_hex(24)
        self.log_path = log
        environment = {name: value for name, value in os.environ.items() if not name.startswith("AGENT_BOM_")}
        environment.update(
            {
                "PYTHONPATH": str(_REPO / "src"),
                "AGENT_BOM_API_KEY": self.key,
                "AGENT_BOM_AUDIT_HMAC_KEY": secrets.token_hex(32),
                "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY": secrets.token_hex(32),
                "AGENT_BOM_TRUSTED_PROXY_HOPS": "1",
                "AGENT_BOM_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
                "AGENT_BOM_AUTH_FAILURE_LIMIT": "5",
                "AGENT_BOM_GLOBAL_IP_RATE_LIMIT_RPM": "100000",
                "AGENT_BOM_API_RATE_LIMIT_RPM": "100000",
                "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
                "AGENT_BOM_DISABLE_NVD": "1",
            }
        )
        environment.update(env)
        self._log = log.open("w")
        self.process = subprocess.Popen(
            [sys.executable, *(launcher or ["-m", "agent_bom"]), "api", "--host", "127.0.0.1", "--port", str(self.port)],
            env=environment,
            cwd=str(log.parent),
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"API exited during startup: {log.read_text()[-2000:]}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            raise AssertionError(f"API did not start: {log.read_text()[-2000:]}")

    def valid(self, source: str) -> list[tuple[str, str]]:
        return [("x-api-key", self.key), ("x-forwarded-for", source)]

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=15)
        self._log.close()


class _Postgres:
    def __init__(self, data: Path):
        self.data = data
        self.port = _free_port()
        env = {**os.environ, "LC_ALL": "C"}
        subprocess.run(
            ["initdb", "-D", str(data), "-U", "auth_test", "-A", "trust", "-E", "UTF8"], check=True, capture_output=True, env=env
        )
        with (data / "postgresql.conf").open("a") as config:
            config.write(f"port = {self.port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = ''\nfsync = off\n")
        self.start()
        self._bootstrap()

    def _bootstrap(self) -> None:
        admin = ["psql", "-h", "127.0.0.1", "-p", str(self.port), "-U", "auth_test", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q"]
        settings = (
            "ALTER DATABASE postgres SET init.app_password = 'test-only'; "
            "ALTER DATABASE postgres SET init.maintenance_password = 'test-only';"
        )
        subprocess.run([*admin, "-c", settings], check=True, capture_output=True)
        for script in ("init.sql", "runtime-schema.sql"):
            subprocess.run([*admin, "-f", str(_REPO / "deploy/supabase/postgres" / script)], check=True, capture_output=True)
        env = {
            **os.environ,
            "PYTHONPATH": str(_REPO / "src"),
            "ALEMBIC_DATABASE_URL": self.admin_url.replace("postgresql://", "postgresql+psycopg://"),
        }
        for step in (("stamp", "20260416_01"), ("upgrade", "head")):
            result = subprocess.run(
                [sys.executable, "-m", "alembic", "-c", "deploy/supabase/postgres/alembic.ini", *step],
                cwd=str(_REPO),
                env=env,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr[-1500:]

    @property
    def admin_url(self) -> str:
        return f"postgresql://auth_test@127.0.0.1:{self.port}/postgres"

    @property
    def url(self) -> str:
        return f"postgresql://agent_bom_app@127.0.0.1:{self.port}/postgres"

    def start(self) -> None:
        subprocess.run(
            ["pg_ctl", "-D", str(self.data), "-w", "-l", str(self.data / "server.log"), "start"], check=True, capture_output=True
        )

    def stop(self) -> None:
        subprocess.run(["pg_ctl", "-D", str(self.data), "-w", "-m", "fast", "stop"], check=False, capture_output=True)


@pytest.fixture
def workdir():
    # Short path outside the shared pytest temp tree: the data directory path
    # is included in Postgres socket and lock file names.
    path = Path(tempfile.mkdtemp(prefix="abom-auth-"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def postgres(workdir):
    if shutil.which("initdb") is None or shutil.which("pg_ctl") is None:
        pytest.skip("Postgres server binaries are not on PATH")
    pytest.importorskip("psycopg")
    cluster = _Postgres(workdir / "pg")
    yield cluster
    cluster.stop()


def _server(backend: str, workdir: Path, postgres_url: str = "") -> _Server:
    env = (
        {
            "AGENT_BOM_POSTGRES_URL": postgres_url,
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL": postgres_url.replace("agent_bom_app", "agent_bom_maintenance"),
        }
        if backend == "postgres"
        else {"AGENT_BOM_DB": str(workdir / "api.db")}
    )
    return _Server(env, workdir / "api.log")


def _wait_ready(server: _Server, source: str = "203.0.113.200") -> None:
    deadline = time.monotonic() + 60
    last: list[int] = []
    while time.monotonic() < deadline:
        last = _client(server.port, 1, server.valid(source))
        if last == [200]:
            return
        time.sleep(0.5)
    raise AssertionError(f"valid key never answered 200: {last}: {server.log_path.read_text()[-2000:]}")


@pytest.fixture(params=["sqlite", "postgres"])
def backend_server(request, workdir):
    if request.param == "postgres":
        cluster = request.getfixturevalue("postgres")
        server = _server("postgres", workdir, cluster.url)
    else:
        server = _server("sqlite", workdir)
    _wait_ready(server)
    yield request.param, server
    server.stop()


def test_lockout_is_per_source_and_only_for_failed_credentials(backend_server):
    _backend, server = backend_server
    attacker = [("x-api-key", "wrong-" + secrets.token_hex(8)), ("x-forwarded-for", "198.51.100.1")]
    statuses = _client(server.port, 12, attacker)
    assert statuses[:4] == [401] * 4
    assert statuses[-1] == 429

    # Another process and source with a valid key is unaffected; the blocked
    # source is refused even with a valid key, before verification.
    assert _client(server.port, 3, server.valid("198.51.100.2")) == [200] * 3
    assert _client(server.port, 1, server.valid("198.51.100.1")) == [429]

    # Nothing presented, repeatedly, is not a failed authentication.
    assert set(_client(server.port, 12, [("x-forwarded-for", "198.51.100.3")])) == {401}
    # A presented session that cannot be read still counts as a failure.
    forged = [("cookie", "agent_bom_session=not-a-session"), ("x-forwarded-for", "198.51.100.4")]
    assert _client(server.port, 12, forged)[-1] == 429


def test_multiple_forwarded_lines_cannot_evade_or_frame(backend_server):
    _backend, server = backend_server
    statuses = []
    for number in range(12):
        statuses += _client(
            server.port,
            1,
            [
                ("x-api-key", "wrong-" + secrets.token_hex(8)),
                ("x-forwarded-for", f"198.51.100.{number + 50}"),
                ("x-forwarded-for", "198.51.100.40"),
            ],
        )
    assert statuses[-1] == 429
    assert _client(server.port, 1, server.valid("198.51.100.50")) == [200]


def test_ipv6_rotation_within_one_prefix_is_blocked(backend_server):
    _backend, server = backend_server
    statuses = []
    for number in range(8):
        statuses += _client(server.port, 1, [("x-api-key", "wrong"), ("x-forwarded-for", f"2001:db8:1:2::{number + 1:x}")])
    assert statuses[-1] == 429
    assert _client(server.port, 1, server.valid("2001:db8:1:3::1")) == [200]


def test_public_reads_ignore_backoff_and_auth_state(backend_server):
    _backend, server = backend_server
    blocked = [("x-api-key", "wrong"), ("x-forwarded-for", "198.51.100.77")]
    assert _client(server.port, 8, blocked)[-1] == 429
    assert _client(server.port, 1, blocked, path="/version") == [200]
    assert _client(server.port, 1, blocked, path="/docs") == [200]


def test_sqlite_held_audit_lock_does_not_refuse_other_callers(workdir):
    # The API stores its audit log in AGENT_BOM_DB, so this is the lock its receipts wait on.
    server = _server("sqlite", workdir)
    try:
        _wait_ready(server)
        holder = sqlite3.connect(str(workdir / "api.db"), isolation_level=None, timeout=5)
        holder.execute("BEGIN IMMEDIATE")
        try:
            attacker = [
                _start_client(server.port, 4, [("x-api-key", "wrong"), ("x-forwarded-for", f"198.51.100.{n}")]) for n in range(10, 20)
            ]
            innocent = _client(server.port, 20, server.valid("198.51.100.200"))
            failed = [status for client in attacker for status in _finish(client)]
        finally:
            holder.rollback()
            holder.close()
        assert Counter(innocent) == {200: 20}, (Counter(innocent), Counter(failed))
        assert 503 not in failed
    finally:
        server.stop()


def test_postgres_held_audit_lock_does_not_refuse_other_callers(workdir, postgres):
    import psycopg

    server = _server("postgres", workdir, postgres.url)
    try:
        _wait_ready(server)
        with psycopg.connect(postgres.admin_url) as holder:
            holder.execute("LOCK TABLE audit_log IN ACCESS EXCLUSIVE MODE")
            attacker = [
                _start_client(server.port, 4, [("x-api-key", "wrong"), ("x-forwarded-for", f"198.51.100.{n}")]) for n in range(10, 20)
            ]
            innocent = _client(server.port, 20, server.valid("198.51.100.200"))
            failed = [status for client in attacker for status in _finish(client)]
            holder.rollback()
        assert Counter(innocent) == {200: 20}, (Counter(innocent), Counter(failed))
        assert 503 not in failed
    finally:
        server.stop()


def test_postgres_restart_does_not_extend_outage_for_valid_keys(workdir, postgres):
    server = _server("postgres", workdir, postgres.url)
    try:
        _wait_ready(server)
        # Fill the pool: every distinct concurrent source reads its own state.
        for _ in range(3):
            fillers = [_start_client(server.port, 5, server.valid(f"203.0.113.{n}")) for n in range(1, 9)]
            for filler in fillers:
                _finish(filler)
        postgres.stop()
        time.sleep(0.5)
        postgres.start()
        started = time.monotonic()
        statuses = []
        while time.monotonic() - started < 45:
            statuses += _client(server.port, 1, server.valid("203.0.113.50"))
            if statuses[-3:] == [200, 200, 200]:
                break
            time.sleep(0.1)
        recovered = time.monotonic() - started
        assert statuses[-3:] == [200, 200, 200], Counter(statuses)
        # The driver reconnects with backoff from its first failure. Stale
        # connections must add nothing beyond that.
        print(f"recovered in {recovered:.1f}s: {Counter(statuses)}")
        assert recovered < 12, (recovered, Counter(statuses))
    finally:
        server.stop()


def test_postgres_valid_keys_are_admitted_while_the_api_is_cpu_bound(workdir, postgres):
    # A large ingest keeps the API's own threads busy for minutes. Admission
    # must not lose its deadline to them: every valid key, from sources with
    # nothing cached, is answered 200 rather than 503.
    burn = workdir / "burn"
    env = {
        "AGENT_BOM_POSTGRES_URL": postgres.url,
        "AGENT_BOM_POSTGRES_MAINTENANCE_URL": postgres.url.replace("agent_bom_app", "agent_bom_maintenance"),
    }
    server = _Server(env, workdir / "api.log", launcher=["-c", _BUSY_API, str(burn), "2"])
    try:
        _wait_ready(server)
        burn.touch()
        time.sleep(1)
        statuses: list[int] = []
        for wave in range(4):
            clients = [_start_client(server.port, 3, server.valid(f"198.18.{wave}.{n}")) for n in range(1, 11)]
            statuses += [status for client in clients for status in _finish(client)]
        assert Counter(statuses) == {200: 120}, (Counter(statuses), server.log_path.read_text()[-1500:])
    finally:
        server.stop()


def test_postgres_outage_keeps_public_documents_and_fails_credentials_closed(workdir, postgres):
    server = _server("postgres", workdir, postgres.url)
    try:
        _wait_ready(server)
        postgres.stop()
        for path in ("/version", "/health"):
            assert _client(server.port, 1, server.valid("203.0.113.60"), path=path) == [200], path
        assert _client(server.port, 1, [("x-forwarded-for", "203.0.113.61")], path="/version") == [200]
        # Credentials cannot be admitted without their protection state.
        assert set(_client(server.port, 3, server.valid("203.0.113.62"))) == {503}
    finally:
        server.stop()


def test_postgres_outage_anonymous_read_reports_unavailable(workdir, postgres):
    server = _Server(
        {
            "AGENT_BOM_POSTGRES_URL": postgres.url,
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL": postgres.url.replace("agent_bom_app", "agent_bom_maintenance"),
            "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1",
        },
        workdir / "api.log",
    )
    try:
        _wait_ready(server)
        assert _client(server.port, 1, [("x-forwarded-for", "203.0.113.70")], path="/v1/findings") == [200]
        postgres.stop()
        statuses = _client(server.port, 2, [("x-forwarded-for", "203.0.113.70")], path="/v1/findings")
        assert set(statuses) == {503}, statuses
    finally:
        server.stop()


def test_sqlite_anonymous_read_survives_a_broken_auth_sidecar(workdir):
    server = _Server({"AGENT_BOM_DB": str(workdir / "api.db"), "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1"}, workdir / "api.log")
    try:
        _wait_ready(server)
        for suffix in ("", "-wal", "-shm"):
            Path(str(workdir / "api.db.auth-limits.db") + suffix).unlink(missing_ok=True)
        assert _client(server.port, 2, [("x-forwarded-for", "203.0.113.71")], path="/v1/findings") == [200, 200]
    finally:
        server.stop()
