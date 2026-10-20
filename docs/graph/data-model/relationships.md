# Relationship pairs

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Allowed source → target pairs for every relationship type (`RelationshipSpec.allowed_pairs`), and the modules found emitting it. Back to the [data model](../DATA_MODEL.md).

## `accessed`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 34 pairs

- `agent` → `cloud_resource`, `data_store`, `dataset`, `resource`
- `federated_identity` → `cloud_resource`, `data_store`, `dataset`, `resource`
- `role` → `cloud_resource`, `data_store`, `dataset`, `resource`
- `service_account` → `cloud_resource`, `data_store`, `dataset`, `resource`
- `service_principal` → `cloud_resource`, `data_store`, `dataset`, `resource`
- `tool` → `cloud_resource`, `credential`, `credential_ref`, `dataset`, `resource`
- `tool_call` → `cloud_resource`, `credential`, `credential_ref`, `dataset`, `resource`
- `user` → `cloud_resource`, `data_store`, `dataset`, `resource`

Emitted by: `graph/builder_snowflake_governance.py`, `graph/cloud_audit_projection.py`, `graph/runtime_projection.py`, `graph/trace_projection.py`

## `acted_as`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 4 pairs

- `federated_identity` → `agent`
- `service_account` → `agent`
- `service_principal` → `agent`
- `user` → `agent`

Emitted by: —

## `affects`

Class `finding` · directed · traversable · required evidence `source`, `tier` · 28 pairs

- `misconfiguration` → `access_policy`, `account`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `org`, `package`, `role`, `server`, `service_account`, `service_principal`, `source_file`, `tool`
- `vulnerability` → `config_file`, `container`, `package`, `resource`, `server`, `source_file`

Emitted by: `graph/benchmark_projection.py`, `graph/finding_projection.py`, `graph/organization_findings.py`, `graph/repo_structure_overlay.py`, `graph/supabase_projection.py`, `graph/vercel_projection.py`, `hardware_evidence.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `assumes`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 29 pairs

- `agent` → `managed_identity`, `role`, `service_account`, `service_principal`
- `cloud_resource` → `managed_identity`, `role`, `service_account`, `service_principal`
- `cluster` → `managed_identity`, `role`, `service_account`, `service_principal`
- `container` → `managed_identity`, `role`, `service_account`, `service_principal`
- `federated_identity` → `role`
- `model` → `managed_identity`, `role`, `service_account`, `service_principal`
- `role` → `role`
- `server` → `managed_identity`, `role`, `service_account`, `service_principal`
- `service_account` → `role`
- `service_principal` → `role`
- `user` → `role`

Emitted by: `graph/builder_cloud_inventory.py`, `graph/builder_snowflake_cortex.py`, `graph/builder_snowflake_objects.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_compute_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `attached`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 12 pairs

- `group` → `access_grant`, `policy`
- `managed_identity` → `access_grant`, `policy`
- `role` → `access_grant`, `policy`
- `service_account` → `access_grant`, `policy`
- `service_principal` → `access_grant`, `policy`
- `user` → `access_grant`, `policy`

Emitted by: `graph/builder.py`, `graph/builder_cloud_lineage.py`, `graph/governance_overlay.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `authenticates_as`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 7 pairs

- `agent` → `managed_identity`, `service_account`, `service_principal`
- `credential` → `managed_identity`, `role`, `service_account`, `service_principal`

Emitted by: `graph/credential_bindings.py`, `graph/governance_overlay.py`

## `belongs_to`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 7 pairs

- `cloud_resource` → `application`
- `container` → `application`
- `credential` → `application`
- `misconfiguration` → `application`
- `package` → `application`
- `server` → `application`
- `vulnerability` → `application`

Emitted by: `graph/aspm_overlay.py`

## `called`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 4 pairs

- `agent` → `server`, `tool`
- `tool_call` → `server`, `tool`

Emitted by: `graph/runtime_projection.py`, `graph/trace_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `can_access`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 183 pairs

- `account` → `cloud_resource`, `credential`, `dataset`, `resource`
- `agent` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `application` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `cloud_resource` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `cluster` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `container` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `federated_identity` → `cloud_resource`, `credential`, `dataset`, `resource`
- `group` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `credential`, `data_store`, `dataset`, `model`, `resource`, `server`
- `managed_identity` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `managed_identity`, `model`, `resource`, `role`, `server`, `service_account`, `service_principal`
- `model` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `role` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `credential`, `data_store`, `dataset`, `managed_identity`, `model`, `resource`, `role`, `server`, `service_account`, `service_principal`
- `server` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `service_account` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `credential`, `data_store`, `dataset`, `managed_identity`, `model`, `resource`, `role`, `server`, `service_account`, `service_principal`
- `service_principal` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `credential`, `data_store`, `dataset`, `managed_identity`, `model`, `resource`, `role`, `server`, `service_account`, `service_principal`
- `tool` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `model`, `resource`, `server`
- `user` → `agent`, `api_gateway`, `cloud_resource`, `cluster`, `config_file`, `container`, `credential`, `data_store`, `dataset`, `model`, `resource`, `server`

Emitted by: `graph/authorization_evidence.py`, `graph/builder.py`, `graph/builder_cloud_lineage.py`, `graph/builder_snowflake_cortex.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `configures`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 4 pairs

- `config_file` → `agent`, `ci_job`, `server`, `tool`

Emitted by: `graph/ci_graph_overlay.py`

## `contains`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 93 pairs

- `access_policy` → `misconfiguration`, `vulnerability`
- `account` → `api_gateway`, `application`, `cloud_resource`, `data_store`, `environment`
- `agent` → `misconfiguration`, `vulnerability`
- `api_gateway` → `misconfiguration`, `vulnerability`
- `application` → `misconfiguration`, `vulnerability`
- `ci_job` → `misconfiguration`, `vulnerability`
- `cloud_resource` → `cloud_resource`, `misconfiguration`, `vulnerability`
- `cluster` → `config_file`, `container`, `directory`, `misconfiguration`, `package`, `server`, `source_file`, `vulnerability`
- `config_file` → `misconfiguration`, `vulnerability`
- `container` → `agent`, `config_file`, `container`, `directory`, `misconfiguration`, `package`, `server`, `source_file`, `vulnerability`
- `data_store` → `data_store`, `misconfiguration`, `vulnerability`
- `dataset` → `misconfiguration`, `vulnerability`
- `directory` → `code_module`, `config_file`, `container`, `directory`, `package`, `server`, `source_file`
- `environment` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`
- `fleet` → `config_file`, `container`, `directory`, `package`, `server`, `source_file`
- `framework` → `misconfiguration`, `vulnerability`
- `model` → `misconfiguration`, `vulnerability`
- `org` → `account`, `org`
- `package` → `misconfiguration`, `vulnerability`
- `role` → `misconfiguration`, `vulnerability`
- `server` → `misconfiguration`, `vulnerability`
- `service_account` → `misconfiguration`, `vulnerability`
- `service_principal` → `misconfiguration`, `vulnerability`
- `source_file` → `package`
- `tool` → `misconfiguration`, `vulnerability`

Emitted by: `graph/agent_projection.py`, `graph/builder_cloud_inventory.py`, `graph/builder_cloud_lineage.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_context.py`, `graph/code_graph_overlay.py`, `graph/organization_aws.py`, `graph/organization_gcp.py`, `graph/repo_structure_overlay.py`, `graph/vercel_projection.py`; demo fixtures: `demo_estate/compute_identity_lane.py`, `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `correlates_with`

Class `correlation` · bidirectional · not traversable · required evidence `source`, `tier` · 4 pairs

- `agent` → `agent`, `server`
- `server` → `agent`, `server`

Emitted by: `graph/builder_frameworks.py`

## `cross_account_trust`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 16 pairs

- `account` → `account`, `federated_identity`, `role`, `service_principal`
- `federated_identity` → `account`, `federated_identity`, `role`, `service_principal`
- `role` → `account`, `federated_identity`, `role`, `service_principal`
- `service_principal` → `account`, `federated_identity`, `role`, `service_principal`

Emitted by: `graph/builder.py`, `graph/builder_cloud_lineage.py`

## `defines`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 3 pairs

- `source_file` → `ci_job`, `code_module`, `tool`

Emitted by: `graph/ast_tool_projection.py`, `graph/code_graph_overlay.py`

## `delegated_to`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `agent`

Emitted by: `graph/runtime_projection.py`

## `depends_on`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 11 pairs

- `cloud_resource` → `cloud_resource`
- `config_file` → `package`
- `container` → `container`, `package`
- `data_store` → `cloud_resource`, `data_store`
- `directory` → `package`
- `framework` → `package`
- `package` → `package`
- `server` → `package`
- `source_file` → `package`

Emitted by: `graph/agent_projection.py`, `graph/builder_snowflake_data_movement.py`, `graph/builder_snowflake_objects.py`, `graph/builder_snowflake_platform.py`, `graph/framework_topology_projection.py`, `graph/package_dependency_projection.py`, `graph/repo_structure_overlay.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `exhibits_drift`

Class `governance` · bidirectional · traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `drift_incident`

Emitted by: `graph/governance_overlay.py`

## `exploitable_via`

Class `finding` · directed · traversable · required evidence `source`, `tier` · 4 pairs

- `misconfiguration` → `credential`, `tool`
- `vulnerability` → `credential`, `tool`

Emitted by: `graph/package_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `exposed_to`

Class `exposure` · directed · traversable · required evidence `source`, `tier` · 20 pairs

- `agent` → `cloud_resource`, `data_store`, `resource`
- `api_gateway` → `cloud_resource`, `data_store`, `resource`
- `cloud_resource` → `cloud_resource`, `data_store`, `resource`
- `container` → `cloud_resource`, `data_store`, `resource`
- `data_store` → `account`, `cloud_resource`, `data_store`, `resource`
- `server` → `agent`, `cloud_resource`, `data_store`, `resource`

Emitted by: `graph/builder_network_exposure.py`, `graph/builder_snowflake_data_movement.py`, `graph/cloud_compute_projection.py`, `graph/cnapp_overlay.py`, `graph/normalized_resource_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `exposes_cred`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 2 pairs

- `agent` → `credential`
- `server` → `credential`

Emitted by: `graph/component_paths.py`, `graph/credential_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `governs`

Class `governance` · directed · not traversable · required evidence `source`, `tier` · 10 pairs

- `access_policy` → `agent`, `drift_incident`, `managed_identity`, `tool`
- `blueprint` → `agent`, `drift_incident`, `managed_identity`, `tool`
- `policy` → `account`, `org`

Emitted by: `graph/governance_overlay.py`, `graph/organization_aws.py`, `graph/organization_gcp.py`

## `has_permission`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 36 pairs

- `group` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`
- `managed_identity` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`
- `role` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`
- `service_account` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`
- `service_principal` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`
- `user` → `account`, `cloud_resource`, `data_store`, `org`, `resource`, `tool`

Emitted by: `graph/builder_cloud_principals.py`, `graph/builder_snowflake_objects.py`, `graph/cloud_rbac.py`, `graph/effective_permissions.py`, `graph/organization_gcp.py`

## `hosted_on`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 12 pairs

- `agent` → `cloud_resource`, `cluster`, `container`, `fleet`
- `container` → `cloud_resource`, `cluster`, `container`, `fleet`
- `server` → `cloud_resource`, `cluster`, `container`, `fleet`

Emitted by: `graph/builder_cloud_lineage.py`, `graph/hosting_projection.py`

## `hosts`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 25 pairs

- `account` → `account`, `agent`, `cloud_resource`, `org`, `server`
- `cloud_resource` → `account`, `agent`, `cloud_resource`, `org`, `server`
- `environment` → `account`, `agent`, `cloud_resource`, `org`, `server`
- `fleet` → `account`, `agent`, `cloud_resource`, `org`, `server`
- `provider` → `account`, `agent`, `cloud_resource`, `org`, `server`

Emitted by: `graph/agent_projection.py`, `graph/builder_cloud_lineage.py`, `graph/endpoint_overlay.py`

## `imports`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 6 pairs

- `code_module` → `code_module`, `external_import`, `package`
- `source_file` → `code_module`, `external_import`, `package`

Emitted by: —

## `inherits`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 10 pairs

- `group` → `policy`, `role`
- `role` → `policy`, `role`
- `service_account` → `policy`, `role`
- `service_principal` → `policy`, `role`
- `user` → `policy`, `role`

Emitted by: —

## `invoked`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 9 pairs

- `agent` → `tool`, `tool_call`
- `federated_identity` → `cloud_resource`
- `role` → `cloud_resource`
- `service_account` → `cloud_resource`
- `service_principal` → `cloud_resource`
- `user` → `cloud_resource`, `tool`, `tool_call`

Emitted by: `graph/cloud_audit_projection.py`, `graph/runtime_projection.py`, `graph/trace_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `lateral_path`

Class `derived` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `agent`

Emitted by: —

## `manages`

Class `governance` · directed · traversable · required evidence `source`, `tier` · 24 pairs

- `federated_identity` → `agent`, `cloud_resource`, `environment`, `fleet`
- `group` → `agent`, `cloud_resource`, `environment`, `fleet`
- `role` → `agent`, `cloud_resource`, `environment`, `fleet`
- `service_account` → `agent`, `cloud_resource`, `environment`, `fleet`
- `service_principal` → `agent`, `cloud_resource`, `environment`, `fleet`
- `user` → `agent`, `cloud_resource`, `environment`, `fleet`

Emitted by: `graph/builder_cloud_lineage.py`

## `member_of`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 31 pairs

- `agent` → `account`, `agent`, `fleet`, `group`
- `federated_identity` → `account`, `agent`, `fleet`, `group`
- `group` → `account`, `agent`, `fleet`, `group`
- `managed_identity` → `account`
- `role` → `account`, `agent`, `fleet`, `group`, `role`
- `service_account` → `account`, `agent`, `fleet`, `group`
- `service_principal` → `account`, `agent`, `fleet`, `group`
- `user` → `account`, `agent`, `fleet`, `group`, `role`

Emitted by: `graph/builder.py`, `graph/builder_cloud_lineage.py`, `graph/builder_snowflake_objects.py`, `graph/nhi_overlay.py`

## `observes`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 2 pairs

- `framework` → `agent`, `server`

Emitted by: `graph/framework_topology_projection.py`

## `owns`

Class `governance` · directed · traversable · required evidence `source`, `tier` · 30 pairs

- `account` → `agent`, `api_gateway`, `cloud_resource`, `data_store`, `environment`, `group`, `policy`, `role`, `service_account`, `service_principal`, `user`
- `group` → `agent`, `cloud_resource`, `environment`
- `org` → `agent`, `cloud_resource`, `environment`, `policy`
- `role` → `agent`, `cloud_resource`, `environment`
- `service_account` → `agent`, `cloud_resource`, `environment`
- `service_principal` → `agent`, `cloud_resource`, `environment`
- `user` → `agent`, `cloud_resource`, `environment`

Emitted by: `graph/builder_snowflake_cortex.py`, `graph/builder_snowflake_governance.py`, `graph/cloud_audit_projection.py`, `graph/cloud_context.py`, `graph/organization_aws.py`, `graph/organization_gcp.py`, `graph/supabase_projection.py`, `graph/vercel_projection.py`

## `part_of`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 20 pairs

- `account` → `cluster`, `environment`, `fleet`, `org`
- `agent` → `cluster`, `environment`, `fleet`, `org`
- `ci_job` → `application`
- `cloud_resource` → `cloud_resource`
- `container` → `cluster`, `environment`, `fleet`, `org`
- `resource` → `resource`
- `server` → `cluster`, `environment`, `fleet`, `org`
- `tool` → `server`

Emitted by: `graph/builder_cloud_lineage.py`, `graph/builder_network_inventory.py`, `graph/cloud_compute_projection.py`, `hardware_evidence.py`

## `possibly_correlates_with`

Class `correlation` · bidirectional · not traversable · required evidence `source`, `tier` · 39 pairs

- `agent` → `agent`, `server`
- `cloud_resource` → `cloud_resource`, `cluster`, `container`
- `cluster` → `cloud_resource`, `cluster`, `container`
- `container` → `cloud_resource`, `cluster`, `container`
- `data_store` → `data_store`
- `managed_identity` → `managed_identity`, `role`, `service_account`, `service_principal`, `user`
- `role` → `managed_identity`, `role`, `service_account`, `service_principal`, `user`
- `server` → `agent`, `server`
- `service_account` → `managed_identity`, `role`, `service_account`, `service_principal`, `user`
- `service_principal` → `managed_identity`, `role`, `service_account`, `service_principal`, `user`
- `user` → `managed_identity`, `role`, `service_account`, `service_principal`, `user`

Emitted by: `graph/asset_canonicalize.py`, `graph/builder_frameworks.py`, `graph/credential_bindings.py`, `graph/finding_row_projection.py`

## `protects`

Class `exposure` · directed · traversable · required evidence `source`, `tier` · 6 pairs

- `api_gateway` → `cloud_resource`, `data_store`, `resource`
- `cloud_resource` → `cloud_resource`, `data_store`, `resource`

Emitted by: `graph/builder_network_inventory.py`

## `provides_tool`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `server` → `tool`

Emitted by: `graph/agent_projection.py`, `graph/component_paths.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `reaches_tool`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 2 pairs

- `agent` → `tool`
- `credential` → `tool`

Emitted by: `graph/builder_snowflake_cortex.py`, `graph/credential_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `remediates`

Class `finding` · directed · not traversable · required evidence `source`, `tier` · 2 pairs

- `package` → `misconfiguration`, `vulnerability`

Emitted by: —

## `runs`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 3 pairs

- `ci_job` → `agent`, `server`, `tool`

Emitted by: `graph/ci_graph_overlay.py`

## `scoped_to`

Class `governance` · directed · traversable · required evidence `source`, `tier` · 3 pairs

- `access_grant` → `tool`
- `drift_incident` → `tool`
- `managed_identity` → `tool`

Emitted by: `graph/governance_overlay.py`

## `serves_model`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 4 pairs

- `agent` → `model`
- `container` → `model`
- `framework` → `model`
- `server` → `model`

Emitted by: `graph/framework_topology_projection.py`, `graph/training_projection.py`

## `shares_cred`

Class `correlation` · bidirectional · not traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `agent`

Emitted by: —

## `shares_server`

Class `correlation` · bidirectional · not traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `agent`

Emitted by: `graph/blast_projection.py`

## `stores`

Class `structural` · directed · traversable · required evidence `source`, `tier` · 8 pairs

- `cloud_resource` → `data_store`, `dataset`
- `data_store` → `data_store`, `dataset`
- `resource` → `data_store`, `dataset`
- `server` → `data_store`, `dataset`

Emitted by: `graph/cnapp_overlay.py`

## `trace_step`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 400 pairs

- `access_policy` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `agent` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `api_gateway` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `application` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `ci_job` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `cloud_resource` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `cluster` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `config_file` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `container` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `data_store` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `dataset` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `framework` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `model` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `package` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `role` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `server` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `service_account` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `service_principal` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `tool` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`
- `user` → `access_policy`, `agent`, `api_gateway`, `application`, `ci_job`, `cloud_resource`, `cluster`, `config_file`, `container`, `data_store`, `dataset`, `framework`, `model`, `package`, `role`, `server`, `service_account`, `service_principal`, `tool`, `user`

Emitted by: —; demo fixtures: `demo_estate/estate_graph.py`

## `triggers`

Class `finding` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `vulnerability` → `misconfiguration`

Emitted by: `graph/finding_projection.py`

## `trusts`

Class `authority` · directed · traversable · required evidence `source`, `tier` · 14 pairs

- `account` → `account`, `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user`
- `role` → `account`, `federated_identity`, `group`, `role`, `service_account`, `service_principal`, `user`

Emitted by: `graph/builder.py`, `graph/builder_cloud_lineage.py`

## `used_credential`

Class `runtime` · directed · traversable · required evidence `source`, `tier` · 6 pairs

- `agent` → `credential`, `credential_ref`
- `tool` → `credential`, `credential_ref`
- `tool_call` → `credential`, `credential_ref`

Emitted by: `graph/runtime_projection.py`, `graph/trace_projection.py`

## `uses`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `server`

Emitted by: `graph/agent_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `uses_framework`

Class `dependency` · directed · traversable · required evidence `source`, `tier` · 1 pairs

- `agent` → `framework`

Emitted by: `graph/framework_topology_projection.py`

## `vulnerable_to`

Class `finding` · directed · traversable · required evidence `source`, `tier` · 20 pairs

- `agent` → `misconfiguration`, `vulnerability`
- `cloud_resource` → `misconfiguration`, `vulnerability`
- `container` → `misconfiguration`, `vulnerability`
- `credential` → `misconfiguration`, `vulnerability`
- `credential_ref` → `misconfiguration`, `vulnerability`
- `directory` → `misconfiguration`, `vulnerability`
- `package` → `misconfiguration`, `vulnerability`
- `role` → `misconfiguration`, `vulnerability`
- `server` → `misconfiguration`, `vulnerability`
- `tool` → `misconfiguration`, `vulnerability`

Emitted by: `graph/blast_projection.py`, `graph/component_paths.py`, `graph/credential_findings.py`, `graph/mcp_audit_projection.py`, `graph/package_projection.py`, `graph/rollup_issues.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_findings.py`, `demo_estate/showcase_graph.py`
