"""Azure database, messaging and cache discovery for the inventory facade."""

from __future__ import annotations

import importlib
from typing import Any

from ._base import _clean_tags, _record_failure, _resource_group_from_id

_FACADE = "agent_bom.cloud.azure_inventory"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _append_db_servers(databases: list[dict[str, Any]], servers: Any, *, native_type: str, engine: str) -> None:
    """Append SQL-family servers (Azure SQL / PostgreSQL / MySQL) in the shared shape.

    Public-network posture lives either directly on the server (Azure SQL) or
    under ``server.network`` (the flexible-server engines); read both.
    """
    for server in servers:
        server_id = str(getattr(server, "id", "") or "")
        name = str(getattr(server, "name", "") or "").strip()
        if not name:
            continue
        network = getattr(server, "network", None)
        public_access = str(getattr(server, "public_network_access", "") or "") or (
            str(getattr(network, "public_network_access", "") or "") if network else ""
        )
        databases.append(
            {
                "name": name,
                "id": server_id,
                "native_type": native_type,
                "engine": engine,
                "location": str(getattr(server, "location", "") or ""),
                "resource_group": _resource_group_from_id(server_id),
                "tags": _clean_tags(getattr(server, "tags", None)),
                "public_network_access": public_access,
            }
        )


def _discover_databases(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate managed databases in the subscription (read-only).

    Covers Cosmos DB, Azure SQL, PostgreSQL, and MySQL — each item carries its
    own ``native_type`` so the normalized model maps them all to ``DATABASE``
    without losing the provider-native type. Each engine is enumerated
    independently so a missing SDK or access denial never sinks the others;
    control-plane metadata only, never row / data-plane contents.
    """
    databases: list[dict[str, Any]] = []

    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        client = CosmosDBManagementClient(credential, subscription_id)
        for account in client.database_accounts.list():
            account_id = str(getattr(account, "id", "") or "")
            name = str(getattr(account, "name", "") or "").strip()
            if not name:
                continue
            databases.append(
                {
                    "name": name,
                    "id": account_id,
                    "native_type": "Microsoft.DocumentDB/databaseAccounts",
                    "engine": "cosmosdb",
                    "location": str(getattr(account, "location", "") or ""),
                    "resource_group": _resource_group_from_id(account_id),
                    "tags": _clean_tags(getattr(account, "tags", None)),
                    "public_network_access": str(getattr(account, "public_network_access", "") or ""),
                    "is_virtual_network_filter_enabled": bool(getattr(account, "is_virtual_network_filter_enabled", False)),
                }
            )
    except ImportError:
        warnings.append("azure-mgmt-cosmosdb not installed. Skipping Cosmos DB inventory.")
    except Exception as exc:  # noqa: BLE001 — one failed Azure Cosmos DB accounts list must not sink the scan
        _record_failure(exc, "Azure Cosmos DB accounts", "Microsoft.DocumentDB/databaseAccounts/read", warnings, missing)

    try:
        from azure.mgmt.sql import SqlManagementClient

        sql_client = SqlManagementClient(credential, subscription_id)
        _seams()._append_db_servers(databases, sql_client.servers.list(), native_type="Microsoft.Sql/servers", engine="azure-sql")
    except ImportError:
        warnings.append("azure-mgmt-sql not installed. Skipping Azure SQL inventory.")
    except Exception as exc:  # noqa: BLE001 — one failed Azure SQL servers list must not sink the scan
        _record_failure(exc, "Azure SQL servers", "Microsoft.Sql/servers/read", warnings, missing)

    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient

        pg_client = PostgreSQLManagementClient(credential, subscription_id)
        _seams()._append_db_servers(
            databases,
            pg_client.servers.list(),
            native_type="Microsoft.DBforPostgreSQL/flexibleServers",
            engine="postgresql",
        )
    except ImportError:
        warnings.append("azure-mgmt-rdbms not installed. Skipping PostgreSQL inventory.")
    except Exception as exc:  # noqa: BLE001 — one failed Azure PostgreSQL servers list must not sink the scan
        _record_failure(exc, "Azure PostgreSQL servers", "Microsoft.DBforPostgreSQL/flexibleServers/read", warnings, missing)

    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        mysql_client = MySQLManagementClient(credential, subscription_id)
        _seams()._append_db_servers(
            databases, mysql_client.servers.list(), native_type="Microsoft.DBforMySQL/flexibleServers", engine="mysql"
        )
    except ImportError:
        warnings.append("azure-mgmt-rdbms not installed. Skipping MySQL inventory.")
    except Exception as exc:  # noqa: BLE001 — one failed Azure MySQL servers list must not sink the scan
        _record_failure(exc, "Azure MySQL servers", "Microsoft.DBforMySQL/flexibleServers/read", warnings, missing)

    return databases


def _discover_event_hubs(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Event Hub namespace in the subscription (read-only).

    Control-plane metadata only (SKU, public-network posture); never reads
    event/message payloads.
    """
    try:
        from azure.mgmt.eventhub import EventHubManagementClient
    except ImportError:
        warnings.append("azure-mgmt-eventhub not installed. Skipping Event Hub inventory.")
        return []

    namespaces: list[dict[str, Any]] = []
    try:
        client = EventHubManagementClient(credential, subscription_id)
        for namespace in client.namespaces.list():
            namespace_id = str(getattr(namespace, "id", "") or "")
            name = str(getattr(namespace, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(namespace, "sku", None)
            namespaces.append(
                {
                    "name": name,
                    "id": namespace_id,
                    "native_type": "Microsoft.EventHub/namespaces",
                    "location": str(getattr(namespace, "location", "") or ""),
                    "resource_group": _resource_group_from_id(namespace_id),
                    "tags": _clean_tags(getattr(namespace, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "public_network_access": str(getattr(namespace, "public_network_access", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Event Hub namespaces list must not sink the scan
        _record_failure(exc, "Azure Event Hub namespaces", "Microsoft.EventHub/namespaces/read", warnings, missing)
    return namespaces


def _discover_service_bus(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Service Bus namespace in the subscription (read-only).

    Control-plane metadata only (SKU, public-network posture); never reads
    queue/topic message contents.
    """
    try:
        from azure.mgmt.servicebus import ServiceBusManagementClient
    except ImportError:
        warnings.append("azure-mgmt-servicebus not installed. Skipping Service Bus inventory.")
        return []

    namespaces: list[dict[str, Any]] = []
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        for namespace in client.namespaces.list():
            namespace_id = str(getattr(namespace, "id", "") or "")
            name = str(getattr(namespace, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(namespace, "sku", None)
            namespaces.append(
                {
                    "name": name,
                    "id": namespace_id,
                    "native_type": "Microsoft.ServiceBus/namespaces",
                    "location": str(getattr(namespace, "location", "") or ""),
                    "resource_group": _resource_group_from_id(namespace_id),
                    "tags": _clean_tags(getattr(namespace, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "public_network_access": str(getattr(namespace, "public_network_access", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Service Bus namespaces list must not sink the scan
        _record_failure(exc, "Azure Service Bus namespaces", "Microsoft.ServiceBus/namespaces/read", warnings, missing)
    return namespaces


def _discover_redis_caches(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Azure Cache for Redis instance in the subscription (read-only).

    Control-plane metadata only (SKU, public-network posture, non-SSL port);
    never connects to the cache data plane or reads keys.
    """
    try:
        from azure.mgmt.redis import RedisManagementClient
    except ImportError:
        warnings.append("azure-mgmt-redis not installed. Skipping Azure Cache for Redis inventory.")
        return []

    caches: list[dict[str, Any]] = []
    try:
        client = RedisManagementClient(credential, subscription_id)
        for cache in client.redis.list_by_subscription():
            cache_id = str(getattr(cache, "id", "") or "")
            name = str(getattr(cache, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(cache, "sku", None)
            caches.append(
                {
                    "name": name,
                    "id": cache_id,
                    "native_type": "Microsoft.Cache/Redis",
                    "location": str(getattr(cache, "location", "") or ""),
                    "resource_group": _resource_group_from_id(cache_id),
                    "tags": _clean_tags(getattr(cache, "tags", None)),
                    "public_network_access": str(getattr(cache, "public_network_access", "") or ""),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "non_ssl_port_enabled": bool(getattr(cache, "enable_non_ssl_port", False)),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Cache for Redis instances list must not sink the scan
        _record_failure(exc, "Azure Cache for Redis instances", "Microsoft.Cache/redis/read", warnings, missing)
    return caches
