"""Validated create/update contracts for tenant-scoped cloud connections."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_bom.api.connection_store import SCAN_MODE_FULL


class CloudConnectionCreate(BaseModel):
    """Request body for creating a connection. ``external_id`` is write-only.

    ``scan_interval_minutes`` opts the connection into recurring background scans
    (Phase B.2). Null (the default) means manual-only — the scheduler ignores it.
    ``scan_mode`` is ``full`` (default) or ``continuous``; continuous drains
    provider event queues on each scheduler tick when a queue env is set.
    ``auto_scan_on_create`` defaults true and queues the brokered scan path
    after persistence (a queue failure marks ``error``; the row is kept).
    """

    model_config = ConfigDict(extra="forbid")

    provider: str
    display_name: str = Field(min_length=1, max_length=200)
    role_ref: str = Field(min_length=1, max_length=2048)
    external_id: str = Field(default="", max_length=8192)
    regions: list[str] = Field(default_factory=list)
    scan_interval_minutes: int | None = None
    # Non-secret provider-specific params (Azure tenant/subscription, GCP
    # project, Snowflake user/role/warehouse). Never a secret — the one secret is ``external_id``.
    auth_params: dict[str, str] = Field(default_factory=dict)
    # ``account`` (the default when omitted) = connected target only;
    # ``organization`` = fan-out across member accounts / subscriptions /
    # projects on Connections scan. Optional so an omitted field can still pick
    # up a legacy ``auth_params["inventory_scope"]``; an explicit value here
    # always wins and is what the stored column carries.
    inventory_scope: str | None = None
    scan_mode: str = SCAN_MODE_FULL
    auto_scan_on_create: bool = True

    @model_validator(mode="after")
    def normalize_databricks(self) -> CloudConnectionCreate:
        if self.provider.strip().lower() == "databricks":
            from agent_bom.cloud.databricks_connection import validate_scan_options

            self.provider = "databricks"
            self.role_ref = validate_scan_options(
                self.role_ref, self.inventory_scope or self.auth_params.get("inventory_scope"), self.scan_mode, self.regions
            )
        return self


class CloudConnectionUpdate(BaseModel):
    """Request body for updating a connection's recurring scan schedule.

    ``scan_interval_minutes`` is set to the supplied value; null disables the
    recurring scan (back to manual-only). Optional ``inventory_scope``,
    ``scan_mode``, and ``auto_scan_on_create`` update when provided.
    """

    model_config = ConfigDict(extra="forbid")

    scan_interval_minutes: int | None = None
    inventory_scope: str | None = None
    scan_mode: str | None = None
    auto_scan_on_create: bool | None = None
