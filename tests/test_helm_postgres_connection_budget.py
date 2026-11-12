"""Postgres role connection limits cover every replica the chart can run, including the rolling-update surge."""

from __future__ import annotations

import math

import pytest

from agent_bom.api.postgres_common import _IDEMPOTENCY_FENCE_POOL_MAX_SIZE, _MAINTENANCE_POOL_MAX_SIZE
from agent_bom.api.rate_limit_store import _ADMISSION_POOL_MAX_SIZE
from tests._helm_render import container_env, find, objects, render, requires_helm

pytestmark = requires_helm

# One direct connection per concurrent graph build; scan workers default to at most four.
GRAPH_BUILD_CONNECTIONS = 4
APP_HEADROOM = 5  # post-install verification (pool of 2), the migration's role check, operator sessions
MAINTENANCE_HEADROOM = 4


def _processes(*capacities: int) -> int:
    # A Deployment's default rolling update surges 25% of its replicas, rounded up.
    return sum(capacity + math.ceil(capacity / 4) for capacity in capacities)


def _app_limit(pool_max: int, *capacities: int) -> int:
    per_process = (
        pool_max + min(_IDEMPOTENCY_FENCE_POOL_MAX_SIZE, pool_max) + min(_ADMISSION_POOL_MAX_SIZE, pool_max) + GRAPH_BUILD_CONNECTIONS
    )
    return _processes(*capacities) * per_process + APP_HEADROOM


def _maintenance_limit(pool_max: int, *capacities: int) -> int:
    return _processes(*capacities) * min(_MAINTENANCE_POOL_MAX_SIZE, pool_max) + MAINTENANCE_HEADROOM


def _migration_env(control_plane: dict) -> dict[str, str]:
    return container_env(find(objects(render(control_plane)), "Job", "agent-bom-postgres-migrate"))


def test_api_pods_keep_few_idle_connections_and_a_bounded_pool() -> None:
    docs = objects(render({}))
    env = container_env(find(docs, "Deployment", "agent-bom-api"))
    assert env["AGENT_BOM_POSTGRES_POOL_MIN_SIZE"] == "2"
    assert env["AGENT_BOM_POSTGRES_POOL_MAX_SIZE"] == "20"


def test_post_install_verification_opens_a_small_pool() -> None:
    env = container_env(find(objects(render({})), "Job", "agent-bom-postgres-verify"))
    assert env["AGENT_BOM_POSTGRES_POOL_MIN_SIZE"] == "1"
    assert env["AGENT_BOM_POSTGRES_POOL_MAX_SIZE"] == "2"


@pytest.mark.parametrize(
    ("control_plane", "capacities"),
    [
        ({}, (2,)),
        ({"api": {"replicas": 3}}, (3,)),
        ({"api": {"autoscaling": {"enabled": True, "maxReplicas": 6}}}, (6,)),
        ({"api": {"replicas": 3}, "worker": {"enabled": True, "replicas": 2}}, (3, 2)),
    ],
)
def test_migration_sets_role_limits_for_every_process_and_the_surge(control_plane: dict, capacities: tuple[int, ...]) -> None:
    env = _migration_env(control_plane)
    assert env["AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT"] == str(_app_limit(20, *capacities))
    assert env["AGENT_BOM_POSTGRES_MAINTENANCE_CONNECTION_LIMIT"] == str(_maintenance_limit(20, *capacities))


def test_three_replicas_fit_what_the_old_fixed_limit_refused() -> None:
    env = _migration_env({"api": {"replicas": 3}})
    # Migrations used to pin agent_bom_app at 20; three idle replicas already held 18 to 21.
    assert int(env["AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT"]) > 3 * 7 + 7


def test_limits_follow_the_pool_size() -> None:
    env = _migration_env({"postgres": {"pool": {"maxSize": 8}}})
    assert env["AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT"] == str(_app_limit(8, 2))


def test_an_explicit_limit_at_or_above_demand_is_used() -> None:
    env = _migration_env({"postgres": {"connectionLimits": {"app": 400, "maintenance": 64}}})
    assert env["AGENT_BOM_POSTGRES_APP_CONNECTION_LIMIT"] == "400"
    assert env["AGENT_BOM_POSTGRES_MAINTENANCE_CONNECTION_LIMIT"] == "64"


@pytest.mark.parametrize("role", ["app", "maintenance"])
def test_an_explicit_limit_below_demand_fails_rendering(role: str) -> None:
    result = render({"api": {"replicas": 3}, "postgres": {"connectionLimits": {role: 10}}})
    assert result.returncode != 0
    assert f"controlPlane.postgres.connectionLimits.{role}" in result.stderr
    assert "rolling update" in result.stderr


@pytest.mark.parametrize("name", ["AGENT_BOM_POSTGRES_POOL_MIN_SIZE", "AGENT_BOM_POSTGRES_POOL_MAX_SIZE"])
def test_pool_size_comes_only_from_chart_values(name: str) -> None:
    result = render({"api": {"env": [{"name": name, "value": "50"}]}})
    assert result.returncode != 0
    assert "controlPlane.postgres.pool" in result.stderr


def test_pool_minimum_cannot_exceed_maximum() -> None:
    result = render({"postgres": {"pool": {"minSize": 30, "maxSize": 20}}})
    assert result.returncode != 0
    assert "controlPlane.postgres.pool.minSize" in result.stderr
