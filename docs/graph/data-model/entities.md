# Entity emitters and id formats

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Modules found emitting each entity type, and node id formats from `UnifiedNode(id=…)` call sites that pass a literal entity type. Back to the [data model](../DATA_MODEL.md).

## `access_grant`

Emitted by: `graph/governance_overlay.py`

## `access_policy`

Emitted by: `graph/governance_overlay.py`; demo fixtures: `demo_estate/estate_graph.py`

## `account`

Emitted by: `graph/benchmark_projection.py`, `graph/builder.py`, `graph/builder_cloud_inventory.py`, `graph/builder_cloud_lineage.py`, `graph/builder_snowflake_data_movement.py`, `graph/builder_snowflake_governance.py`, `graph/builder_snowflake_lane.py`, `graph/builder_snowflake_objects.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_audit_projection.py`, `graph/cloud_context.py`, `graph/cloud_rbac.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `account:{provider}:{account_scope}`

## `agent`

Emitted by: `graph/agent_projection.py`, `graph/builder_overlays.py`, `graph/builder_snowflake_cortex.py`, `graph/builder_snowflake_governance.py`, `graph/compat.py`, `graph/delta_digest.py`, `graph/dependency_reach.py`, `graph/framework_topology_projection.py`, `graph/governance_overlay.py`, `graph/runtime_projection.py`, `graph/toxic_findings.py`, `graph/trace_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `api_gateway`

Emitted by: `graph/builder_network_inventory.py`

Id formats:

- `api_gateway:{provider}:{api_id}`

## `application`

Emitted by: `graph/aspm_overlay.py`, `graph/repo_trust_overlay.py`; demo fixtures: `demo_estate/estate_graph.py`

## `blueprint`

Emitted by: `graph/governance_overlay.py`

## `ci_job`

Emitted by: `graph/ci_graph_overlay.py`; demo fixtures: `demo_estate/estate_graph.py`

## `cloud_resource`

Emitted by: `api/routes/cloud.py`, `graph/benchmark_projection.py`, `graph/builder.py`, `graph/builder_cloud_lineage.py`, `graph/builder_network_inventory.py`, `graph/builder_snowflake_data_movement.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_audit_projection.py`, `graph/cloud_compute_projection.py`, `graph/cloud_rbac.py`, `graph/cloud_service_projection.py`, `graph/cloud_storage_projection.py`, `graph/finding_projection.py`, `graph/resource_aliases.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `cloud_resource:runtime:{stable_id}`
- `cloud_resource:snowflake:integration:{name}`
- `cloud_resource:snowflake:pipe:{fqn}`
- `cloud_resource:snowflake:stage:{stage_name}`
- `cloud_resource:snowflake:task:{fqn}`
- `cloud_resource:snowflake:warehouse:{name}`
- `cloud_resource:{cloud}:{service}:bucket:{bucket}`
- `cloud_resource:{provider}:audit:resource:{resource}`
- `cloud_resource:{provider}:database:{db_name}`
- `cloud_resource:{provider}:{bucket_service}:bucket:{name}`
- `cloud_resource:{provider}:{inst_service}:instance:{instance_id}`
- `cloud_resource:{provider}:{kind}:{normalized}`
- `cloud_resource:{provider}:{sg_service}:{sg_resource_type}:{group_id}`
- `cloud_resource:{target_provider}:cwpp:{target_type}:{target_id}`
- `iac_target:{category}:{finding_path}`

## `cluster`

Emitted by: —; demo fixtures: `demo_estate/estate_graph.py`

## `code_module`

Emitted by: `graph/ast_tool_projection.py`, `graph/code_graph_overlay.py`

Id formats:

- `application_entrypoint:source:{…}`

## `config_file`

Emitted by: `graph/finding_row_projection.py`, `graph/repo_structure_overlay.py`; demo fixtures: `demo_estate/estate_graph.py`

## `container`

Emitted by: `graph/finding_row_projection.py`, `graph/training_projection.py`; demo fixtures: `demo_estate/estate_graph.py`

Id formats:

- `container:{container_image}`

## `credential`

Emitted by: `graph/compat.py`, `graph/credential_projection.py`; demo fixtures: `demo_estate/showcase_graph.py`

## `credential_ref`

Emitted by: —

## `data_store`

Emitted by: `graph/builder_snowflake_data_movement.py`, `graph/builder_snowflake_governance.py`, `graph/builder_snowflake_lane.py`, `graph/builder_snowflake_objects.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_service_projection.py`, `graph/cnapp_overlay.py`, `graph/resource_aliases.py`; demo fixtures: `demo_estate/estate_graph.py`

Id formats:

- `data_store:snowflake:db:{name}`
- `data_store:snowflake:schema:{fqn}`
- `data_store:snowflake:share:{share_name}`
- `data_store:snowflake:stream:{fqn}`
- `data_store:snowflake:{fqn}`
- `data_store:snowflake:{object_name}`
- `data_store:{id}`

## `dataset`

Emitted by: `graph/training_projection.py`; demo fixtures: `demo_estate/estate_graph.py`

Id formats:

- `dataset:{dataset_name}`

## `directory`

Emitted by: `graph/agent_projection.py`, `graph/repo_structure_overlay.py`

Id formats:

- `directory:manifest:{agent_node_key}:{srv_name}`

## `drift_incident`

Emitted by: `graph/governance_overlay.py`

## `environment`

Emitted by: —; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `env:{provider}:{account_scope}:{environment}`

## `external_import`

Emitted by: —

## `federated_identity`

Emitted by: `graph/authorization_evidence.py`, `graph/cloud_context.py`

## `fleet`

Emitted by: `graph/endpoint_overlay.py`

Id formats:

- `endpoint:{endpoint_id}`

## `framework`

Emitted by: `graph/framework_topology_projection.py`; demo fixtures: `demo_estate/estate_graph.py`

Id formats:

- `stable_node_id(…) — UUIDv5`

## `group`

Emitted by: `graph/authorization_evidence.py`, `graph/builder.py`, `graph/cloud_context.py`, `graph/cloud_rbac.py`

## `managed_identity`

Emitted by: `graph/authorization_evidence.py`, `graph/cloud_compute_projection.py`, `graph/cloud_context.py`, `graph/cloud_rbac.py`, `graph/credential_projection.py`, `graph/governance_overlay.py`, `graph/identity_nodes.py`, `graph/nhi_overlay.py`

Id formats:

- `managed_identity:{provider}:{identity_id}`

## `misconfiguration`

Emitted by: `graph/benchmark_projection.py`, `graph/builder.py`, `graph/credential_findings.py`, `graph/finding_projection.py`, `graph/finding_row_projection.py`, `graph/mcp_audit_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `misconfig:cloud-org:{provider}:{check_id}`
- `misconfig:graph_analysis:{fid}`
- `misconfig:iac:{rule_id}:{finding_path}:{finding_line}`
- `misconfig:mcp_audit:{finding_id}`
- `misconfig:sast:{rule_id}:{finding_path}:{finding_line}`
- `misconfig:secret_scan:{finding_id}`
- `misconfig:{section_key}:{check_id}`
- `toxic:{combo_key}`

## `model`

Emitted by: `graph/finding_row_projection.py`, `graph/framework_topology_projection.py`, `graph/training_projection.py`; demo fixtures: `demo_estate/estate_graph.py`

## `org`

Emitted by: `graph/builder.py`, `graph/builder_cloud_inventory.py`, `graph/builder_cloud_lineage.py`, `graph/builder_snowflake_platform.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `org:snowflake:{org_name}`

## `package`

Emitted by: `graph/agent_projection.py`, `graph/blast_projection.py`, `graph/compat.py`, `graph/dependency_reach.py`, `graph/framework_topology_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `stable_node_id(…) — UUIDv5`

## `policy`

Emitted by: `graph/builder.py`, `graph/builder_cloud_lineage.py`, `graph/cloud_context.py`; demo fixtures: `demo_estate/showcase_graph.py`

Id formats:

- `policy:aws:scp:{scp_id}`
- `policy:gcp:orgpolicy:{constraint}`

## `provider`

Emitted by: `graph/agent_projection.py`, `graph/builder.py`, `graph/builder_cloud_lineage.py`

Id formats:

- `provider:{provider}`

## `resource`

Emitted by: `graph/builder_cloud_principals.py`, `graph/delta_digest.py`, `hardware_evidence.py`

Id formats:

- `stable_node_id(…) — UUIDv5`

## `role`

Emitted by: `graph/builder_cloud_inventory.py`, `graph/builder_snowflake_cortex.py`, `graph/builder_snowflake_objects.py`, `graph/builder_snowflake_platform.py`, `graph/cloud_audit_projection.py`, `graph/cloud_context.py`, `graph/finding_row_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

## `server`

Emitted by: `context_graph.py`, `graph/agent_projection.py`, `graph/compat.py`, `graph/trace_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `directory:manifest:{agent_node_key}:{srv_name}`

## `service_account`

Emitted by: `graph/authorization_evidence.py`, `graph/builder.py`, `graph/cloud_context.py`, `graph/compat.py`; demo fixtures: `demo_estate/estate_graph.py`

## `service_principal`

Emitted by: `graph/authorization_evidence.py`, `graph/cloud_context.py`, `graph/cloud_rbac.py`; demo fixtures: `demo_estate/estate_graph.py`

## `source_file`

Emitted by: `graph/agent_projection.py`, `graph/ast_tool_projection.py`, `graph/repo_structure_overlay.py`

Id formats:

- `{value}:{source_file}`

## `tool`

Emitted by: `graph/agent_projection.py`, `graph/ast_tool_projection.py`, `graph/builder_snowflake_cortex.py`, `graph/compat.py`, `graph/governance_overlay.py`, `graph/runtime_projection.py`, `graph/trace_projection.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `tool:source:{…}`
- `tool:{srv_id}:{tool_name}`

## `tool_call`

Emitted by: —; demo fixtures: `demo_estate/showcase_graph.py`

## `user`

Emitted by: `graph/authorization_evidence.py`, `graph/builder.py`, `graph/builder_snowflake_governance.py`, `graph/builder_snowflake_objects.py`, `graph/cloud_audit_projection.py`, `graph/cloud_context.py`, `graph/cloud_rbac.py`; demo fixtures: `demo_estate/showcase_graph.py`

Id formats:

- `user:snowflake:{name}`

## `vulnerability`

Emitted by: `graph/blast_projection.py`, `graph/builder_overlays.py`, `graph/compat.py`, `graph/dependency_reach.py`, `graph/finding_row_projection.py`, `graph/package_projection.py`, `hardware_evidence.py`; demo fixtures: `demo_estate/estate_graph.py`, `demo_estate/showcase_graph.py`

Id formats:

- `stable_node_id(…) — UUIDv5`
- `vuln:{vuln_id_str}`
