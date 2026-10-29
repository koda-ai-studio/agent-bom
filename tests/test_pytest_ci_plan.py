from __future__ import annotations

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import discover_test_files, plan_shards, select_targeted_tests


def _write(path: Path, lines: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n" * lines, encoding="utf-8")


@pytest.mark.parametrize("owner", ["models", "templates", "findings"])
def test_narrative_owners_keep_public_contract_selection(tmp_path: Path, owner: str) -> None:
    contract = tmp_path / "tests/test_compliance_narrative.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    selected = select_targeted_tests(changed_files=[Path(f"src/agent_bom/output/compliance_narrative_{owner}.py")], root=tmp_path)
    assert contract in selected


@pytest.mark.parametrize("owner", ["common", "scanners"])
def test_sarif_owners_keep_schema_and_characterization_selection(tmp_path: Path, owner: str) -> None:
    contracts = [
        tmp_path / "tests" / name
        for name in ("test_sarif_schema_2_1_0.py", "test_sarif_severity_agreement.py", "test_output_render_characterization.py")
    ]
    for contract in contracts:
        _write(contract, 1)
    selected = select_targeted_tests(changed_files=[Path(f"src/agent_bom/output/sarif_{owner}.py")], root=tmp_path)
    assert set(contracts) <= set(selected)


@pytest.mark.parametrize("source", [".github/workflows/ci.yml", ".github/workflows/release.yml"])
def test_workflow_edits_select_deployment_contracts(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_deployment.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/parsers/skills.py",
        "src/agent_bom/parsers/skill_audit_behavior.py",
        "tests/fixtures/skill_accuracy/benign-pinned-launchers/label.json",
    ],
)
def test_skill_parser_and_corpus_edits_select_the_accuracy_gate(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_skill_audit_accuracy_gate.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize("source", ["ui/lib/graph-schema.ts", "ui/lib/graph-schema.generated.ts", "ui/scripts/codegen-graph-schema.mjs"])
def test_ui_graph_schema_edits_select_python_parity_contract(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_graph_schema_ui_parity.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize(
    "source", ["src/agent_bom/domain/asset_identity.py", "src/agent_bom/domain/finding_model.py", "tests/fixtures/domain_contracts.json"]
)
def test_domain_identity_edits_select_serialized_projection_contract(tmp_path: Path, source: str) -> None:
    contracts = [tmp_path / "tests" / name for name in ("test_domain_split_characterization.py", "test_output_render_characterization.py")]
    for contract in contracts:
        _write(contract, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == contracts


@pytest.mark.parametrize("source", ["demo_estate/bootstrap.py", "api/read_models/posture.py"])
def test_seeded_estate_and_read_models_select_live_body_contracts(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_api_read_contracts.py"
    _write(contract, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == [contract]


@pytest.mark.parametrize("module", ["server_routes", "server_storage", "server_dashboard", "server_schedules"])
def test_server_module_edits_select_auth_and_composition_contracts(tmp_path: Path, module: str) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "api/test_server_composition_contract.py",
            "api/test_api_auth_boundary.py",
            "api/test_api_dashboard_deeplink_routes.py",
            "test_postgres_store.py",
        )
    )
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/api/{module}.py")], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [
        "api/trace_collection/langfuse.py",
        "api/native_trace_import.py",
        "api/storage/cooperative.py",
        "api/storage/runtime_trace_revisions.py",
    ],
)
def test_trace_collection_edits_select_scheduling_and_replay_contracts(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_trace_collection_scheduling.py",
            "test_trace_collection_store.py",
            "test_trace_collection_postgres.py",
            "test_trace_collection_qualification.py",
            "test_native_trace_import.py",
            "test_runtime_trace_revision_retention.py",
        )
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source", ["src/agent_bom/security.py", "src/agent_bom/redaction/payload.py", "src/agent_bom/redaction/cloud_coordinates.py"]
)
def test_redaction_edits_select_identity_and_traversal_contracts(tmp_path, source):
    expected = sorted(tmp_path / "tests" / name for name in ("test_scan_export_perf.py", "test_cloud_coordinate_redaction.py"))
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["src/agent_bom/parsers/new_module.py", "src/agent_bom/removed_module.py", "docs/PRODUCT_METRICS.json"])
def test_module_and_metric_edits_select_snapshot_contract(tmp_path, source):
    expected = tmp_path / "tests/test_product_metrics_snapshot.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [expected]


@pytest.mark.parametrize(
    "source", ["src/agent_bom/sbom.py", "src/agent_bom/parsers/sbom_context.py", "src/agent_bom/cli/agents/_discovery.py"]
)
def test_sbom_import_edits_select_cli_and_scope_contracts(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name for name in ("test_cli_check.py", "test_sbom_scan_scope.py", "test_sbom_cloud_roundtrip.py")
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["pyproject.toml", "uv.lock", ".pre-commit-config.yaml", "Makefile", ".github/workflows/ci.yml"])
def test_dependency_and_checker_changes_select_pin_agreement(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_toolchain_pin_agreement.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)

    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize("total", [2, 4])
def test_shard_plan_is_deterministic_disjoint_and_complete(tmp_path: Path, total: int) -> None:
    for index, lines in enumerate((200, 150, 120, 90, 70, 50, 30, 20, 10)):
        _write(tmp_path / f"group_{index % 3}" / f"test_{index}.py", lines)

    files = discover_test_files(tmp_path)
    first = plan_shards(files, total=total)
    second = plan_shards(files, total=total)

    assert first == second
    assert {path for shard in first for path in shard} == set(files)
    assert sum(len(shard) for shard in first) == len(files)

    loads = [sum(path.stat().st_size for path in shard) for shard in first]
    largest = max(path.stat().st_size for path in files)
    assert max(loads) - min(loads) <= largest


@pytest.mark.parametrize("total", [2, 4])
def test_expensive_demo_rebuild_suite_has_a_dedicated_shard(tmp_path, total):
    # CI timings show this small module rebuilding the whole demo per test;
    # source-byte balancing must not stack other suites on that runner.
    expensive = tmp_path / "tests/test_demo_estate_bootstrap.py"
    _write(expensive, 1)
    files = [expensive]
    for index in range(12):
        path = tmp_path / f"tests/test_regular_{index}.py"
        _write(path, 100 + index)
        files.append(path)
    shards = plan_shards(files, total=total)
    assert [expensive] in shards
    assert all(shards)
    assert {path for shard in shards for path in shard} == set(files)
    assert sum(map(len, shards)) == len(files)
    assert shards == plan_shards(reversed(files), total=total)


def test_single_shard_preserves_the_demo_and_other_modules(tmp_path):
    files = [tmp_path / "tests/test_demo_estate_bootstrap.py", tmp_path / "tests/test_regular.py"]
    for path in files:
        _write(path, 1)
    assert plan_shards(files, total=1) == [sorted(files)]


def test_explicit_file_shards_preserve_only_the_selected_suite(tmp_path, monkeypatch, capsys) -> None:
    import sys

    from scripts.pytest_ci_plan import main

    files = [tmp_path / f"test_selected_{i}.py" for i in range(7)]
    for i, path in enumerate(files):
        _write(path, (i + 1) * 20)
    _write(tmp_path / "test_unrelated.py", 100)
    shards = []
    for index in range(2):
        monkeypatch.setattr(
            sys,
            "argv",
            ["plan", "shard", "--root", str(tmp_path), "--index", str(index), "--total", "2", "--files", *map(str, files), str(files[0])],
        )
        assert main() == 0
        shards.append(set(map(Path, capsys.readouterr().out.splitlines())))
    assert all(shards)
    assert shards[0].isdisjoint(shards[1])
    assert shards[0] | shards[1] == set(files)


@pytest.mark.parametrize("invalid", ["missing", "not_test", "empty"])
def test_explicit_file_shards_reject_invalid_selection(tmp_path, monkeypatch, invalid) -> None:
    import sys

    from scripts.pytest_ci_plan import main

    path = tmp_path / ("config.py" if invalid == "not_test" else "test_missing.py")
    if invalid == "not_test":
        _write(path, 1)
    args = [] if invalid == "empty" else [str(path)]
    monkeypatch.setattr(sys, "argv", ["plan", "shard", "--index", "0", "--total", "2", "--files", *args])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code != 0


def test_targeted_tests_include_changed_tests_and_source_name_matches(tmp_path: Path) -> None:
    direct = tmp_path / "tests" / "test_direct.py"
    matching = tmp_path / "tests" / "db" / "test_local_analytics.py"
    unrelated = tmp_path / "tests" / "test_other.py"
    for path in (direct, matching, unrelated):
        _write(path, 1)

    selected = select_targeted_tests(
        changed_files=[Path("tests/test_direct.py"), Path("src/agent_bom/db/local_analytics.py")],
        root=tmp_path,
    )

    assert selected == [matching, direct]


def test_ast_edits_select_characterization_and_console_reconciliation(tmp_path: Path) -> None:
    expected = sorted(tmp_path / "tests" / name for name in ("test_ast_analysis_characterization.py", "test_console_reconciliation.py"))
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    for source in (
        "src/agent_bom/ast_analyzer.py",
        "src/agent_bom/ast_python_analysis.py",
        "src/agent_bom/ast/js_ts/facade.py",
        "tests/fixtures/analysis_characterization/multilang/server.ts",
        "tests/fixtures/analysis_characterization_golden.json",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_route_and_shared_auth_edits_always_select_mounted_operation_matrix(tmp_path: Path) -> None:
    from scripts.pytest_ci_plan import AUTHORIZATION_CONTRACTS, AUTHORIZATION_SOURCES

    expected = sorted(tmp_path / path for path in AUTHORIZATION_CONTRACTS)
    for path in expected:
        _write(path, 1)
    for source in [*AUTHORIZATION_SOURCES, "src/agent_bom/api/browser_session.py", "src/agent_bom/api/routes/new_surface.py"]:
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_tenant_worker_edits_select_scheduler_and_persistence_callers(tmp_path):
    names = (
        "test_connection_scheduler.py",
        "test_side_scan_scheduler.py",
        "test_auto_correlation_scheduler.py",
        "test_scan_jobs_active_gauge.py",
        "test_graph_persistence_characterization.py",
        "test_tenant_dispatch_boundaries.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api/tenant_worker.py")], root=tmp_path) == expected


def test_mcp_registration_edits_select_tool_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_mcp_server.py",
            "test_mcp_tool_output_contract.py",
            "test_mcp_strict_args.py",
            "test_deployment.py",
            "test_stats_alignment.py",
            "test_fleet_scan.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for source in (
        "src/agent_bom/mcp_tools/endpoint_connectors.py",
        "src/agent_bom/mcp_tools/new_tools.py",
        "src/agent_bom/mcp_tools/__init__.py",
        "src/agent_bom/mcp_server.py",
        "src/agent_bom/mcp_server_metadata.py",
        "src/agent_bom/mcp_server_specialized.py",
        "src/agent_bom/mcp_strict_args.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/cloud/aws.py")], root=tmp_path) == []


def test_tenant_worker_edits_cover_each_dispatch_surface(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / path
        for path in (
            "tests/test_report_worker_recovery.py",
            "tests/test_report_jobs_postgres.py",
            "tests/test_distributed_scan_queue.py",
            "tests/test_exports_api.py",
            "tests/api/test_api_scan_worker_tenant_binding.py",
        )
    )
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api/tenant_worker.py")], root=tmp_path) == expected


def test_gateway_modules_select_cross_surface_enforcement_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_gateway_server.py",
            "test_gateway_firewall.py",
            "test_gateway_relay_lifecycle.py",
            "test_gateway_audit_delivery.py",
            "api/test_api_gateway.py",
            "api/test_gateway_runtime_acceptance.py",
        )
    )
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_other.py", 1)
    for source in (
        "src/agent_bom/gateway_server.py",
        "src/agent_bom/runtime/gateway_relay.py",
        "src/agent_bom/runtime/gateway_settings.py",
        "src/agent_bom/api/gateway_auth.py",
        "src/agent_bom/api/gateway_request.py",
        "src/agent_bom/api/gateway_context.py",
        "src/agent_bom/runtime/risk_conditions.py",
        "src/agent_bom/api/gateway_rate_limit.py",
        "src/agent_bom/api/gateway_policy.py",
        "src/agent_bom/runtime/gateway_policy_reload.py",
        "src/agent_bom/runtime/trace_metadata.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_credential_bindings_select_store_backed_build_contract(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / path for path in ("tests/test_graph_credential_bindings.py", "tests/graph/test_store_backed_build_wiring.py")
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/graph/credential_bindings.py")], root=tmp_path) == expected


def test_report_projection_edits_select_builder_store_and_runtime_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_graph_builder.py",
            "test_graph_projection_contracts.py",
            "test_runtime_incident_feedback.py",
            "graph/test_store_backed_unified_graph.py",
            "graph/test_snowflake_account_staging.py",
            "graph/projection/test_workspace_cleanup.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for module in (
        "builder",
        "package_projection",
        "runtime_projection",
        "projection_support",
        "ports",
        "cloud_compute_projection",
        "cloud_service_projection",
        "cloud_storage_projection",
        "agent_cloud_lineage",
        "organization_aws",
        "organization_gcp",
        "organization_findings",
        "normalized_resource_projection",
        "network_entry_projection",
        "snowflake_source_lanes",
    ):
        assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/graph/{module}.py")], root=tmp_path) == expected


def test_shared_judgments_select_caller_parity(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_transitive.py",
            "test_version_utils.py",
            "test_compliance_narrative.py",
            "test_credential_policy_kernel.py",
            "test_graph_nhi_governance.py",
            "test_shared_semantic_hygiene.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for name in ("packages", "severity", "timestamps"):
        assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/core/{name}.py")], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["core/package_artifacts.py", "core/versions/ruby.py", "parsers/uv_lock.py", "parsers/uv_workspace.py"])
def test_artifact_version_helpers_select_parser_and_check_consumers(tmp_path: Path, source: str) -> None:
    names = [
        "test_scanner_package_identities.py",
        "test_scanner_artifact_versions.py",
        "test_cli_check.py",
        "test_mcp_package_scan_ecosystem.py",
        "test_parser_interop.py",
    ]
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in [*expected, tmp_path / "tests/test_unrelated.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


def test_delegation_sources_select_lifecycle_and_authority_contracts(tmp_path):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_delegation_identity_authority.py",
            "test_governance_abac_delegation.py",
            "test_agent_identity_lifecycle.py",
            "test_identity_governance_3687.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for source in ("delegation_token.py", "delegation_service.py", "agent_identity_store.py", "routes/identities.py"):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_jit_grant_changes_select_store_lifecycle_and_runtime_callers(tmp_path):
    names = (
        "test_jit_grant_tenant_boundary.py",
        "test_identity_policy_tenant_boundary.py",
        "test_device_posture.py",
        "test_nhi_lifecycle_enforcement.py",
        "test_durable_store_default.py",
        "test_graph_governance_overlay.py",
        "test_agent_identity_lifecycle.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    for source in ("identity_grants.py", "identity_policies.py", "agent_identity_store.py", "postgres_agent_identity.py"):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_shared_sql_changes_select_finding_and_storage_contracts(tmp_path):
    names = (
        "test_findings_sql_read_contract.py",
        "test_finding_lifecycle.py",
        "test_finding_sla_lifecycle.py",
        "test_postgres_ledger_scan_filter.py",
        "test_overview.py",
        "test_findings_sql_backfill.py",
        "test_hub_ingest_atomic.py",
        "test_storage_sql.py",
        "test_tenant_quota_store.py",
        "test_tenant_graph_retention_store.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    for source in (
        "storage/sql.py",
        "storage/finding_reads.py",
        "storage/finding_payloads.py",
        "compliance_hub_store.py",
        "postgres_compliance_hub.py",
    ):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_job_storage_changes_select_tenant_lifecycle_and_correlation_callers(tmp_path: Path) -> None:
    expected = [
        tmp_path / "tests/api/test_api_tenant_isolation.py",
        tmp_path / "tests/test_agent_lifecycle_history.py",
        tmp_path / "tests/test_auto_correlation_scheduler.py",
    ]
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    for source in ["store.py", "stores.py", "postgres_job_store.py", "scan_queue.py", "storage/jobs.py", "storage/job_cache.py"]:
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == sorted(expected)


@pytest.mark.parametrize(
    "source",
    ["push_evidence.py", "push_models.py", "correlation_cohort_ingest.py", "finding_collection.py", "routes/observability.py"],
)
def test_push_edits_select_tenant_summary_and_ingest_contracts(tmp_path: Path, source: str) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "api/test_api_tenant_isolation.py",
            "api/test_push_evidence_hardening.py",
            "api/test_push_replacement_scope.py",
            "api/test_correlation_cohort_push_ingest.py",
            "test_ingest_idempotency.py",
            "test_findings_push.py",
        )
    )
    for path in [*expected, tmp_path / "tests/test_unrelated.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_graph_storage_edits_include_startup_and_writer_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_graph_wal_startup.py",
            "test_graph_writer_admission.py",
            "test_graph_bootstrap_cost.py",
            "test_graph_initialization_lock.py",
            "test_graph_store_streamed_persistence.py",
        )
    )
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    for source in (
        "src/agent_bom/db/graph_store.py",
        "src/agent_bom/db/graph_bootstrap.py",
        "src/agent_bom/db/graph_revision.py",
        "src/agent_bom/db/graph_write_admission.py",
        "src/agent_bom/api/graph_store.py",
        "src/agent_bom/storage/sqlite_wal.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/api/inventory_service.py",
        "src/agent_bom/api/routes/inventory_assets.py",
        "src/agent_bom/api/routes/graph.py",
        "src/agent_bom/api/routes/graph_routes/reads.py",
        "src/agent_bom/api/neptune_graph.py",
    ],
)
def test_inventory_graph_edits_select_backend_support_contract(tmp_path, source):
    expected = tmp_path / "tests/test_neptune_unsupported_501.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [expected]


@pytest.mark.parametrize(
    "source", ["src/agent_bom/runtime/policy_validation.py", "src/agent_bom/proxy_policy.py", "src/agent_bom/api/policy_inputs.py"]
)
def test_shared_regex_edits_select_policy_enforcement_callers(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name
        for name in ("test_gateway_invalid_policy.py", "test_api_gateway.py", "test_proxy_policy.py", "test_policy_regex_budget.py")
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/models.py",
        "src/agent_bom/enrichment.py",
        "src/agent_bom/enrichment/epss.py",
        "src/agent_bom/output/sarif.py",
        "src/agent_bom/cli/_check_command.py",
        "src/agent_bom/cli/agents/scan_pipeline/matching.py",
        "src/agent_bom/scanners/package_scan.py",
        "tests/fixtures/check_characterization/golden.json",
        "tests/fixtures/output_render/manifest.json",
    ],
)
def test_output_changes_select_characterization_consumers(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_check_characterization.py",
            "test_console_reconciliation.py",
            "test_output_render_characterization.py",
            "test_scan_characterization.py",
            "test_scan_verdict_completeness.py",
        )
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/api/current_graph.py",
        "src/agent_bom/api/stores.py",
        "src/agent_bom/api/storage/job_backends.py",
        "src/agent_bom/api/findings_current.py",
        "src/agent_bom/api/routes/scan.py",
        "src/agent_bom/api/finding_read_context.py",
        "src/agent_bom/finding_scope.py",
    ],
)
def test_current_evidence_edits_select_cross_view_contracts(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_findings_read_path_3641.py",
            "test_graph_api.py",
            "test_graph_backend_semantics.py",
            "test_graph_rollup_agent_grouping.py",
            "test_inventory_assets.py",
            "test_job_store_selection.py",
            "test_mcp_inventory.py",
            "test_neptune_unsupported_501.py",
            "test_demo_estate_bootstrap.py",
            "cloud/test_cloud_connections.py",
            "test_iac_findings_surface.py",
            "api/test_api_agent_population.py",
            "api/test_graph_scope_contract.py",
            "api/test_current_graph_estate.py",
            "api/test_current_remediation.py",
        )
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    ("source", "contracts"),
    [
        ("src/agent_bom/secret_scanner.py", ("test_sensitive_file_candidate_coverage.py", "test_secret_pruning_coverage.py")),
        (
            "src/agent_bom/iac/models.py",
            ("test_iac_iam_policy.py", "test_iac_scanner_golden.py", "test_iac_scanner_golden_cfn_docker_helm.py"),
        ),
        (
            "src/agent_bom/iac/__init__.py",
            ("test_iac_iam_policy.py", "test_iac_scanner_golden.py", "test_iac_scanner_golden_cfn_docker_helm.py"),
        ),
        ("src/agent_bom/reachability_cve.py", ("test_symbol_reachability_export.py",)),
        ("src/agent_bom/graph/blast_reach.py", ("test_symbol_reachability_export.py",)),
    ],
)
def test_scanner_contract_changes_select_cross_surface_regressions(tmp_path, source, contracts):
    expected = sorted(tmp_path / "tests" / name for name in contracts)
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source", ["src/agent_bom/api/middleware.py", "src/agent_bom/api/tenant_lifecycle.py", "src/agent_bom/api/storage_schema.py"]
)
def test_auth_storage_edits_select_trial_and_oidc_contracts(tmp_path, source):
    expected = sorted(
        tmp_path / "tests/api" / name
        for name in (
            "test_api_oidc.py",
            "test_managed_trial_invitations.py",
            "test_managed_trial_guardrails.py",
            "test_trial_completion_contract.py",
        )
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source", ["src/agent_bom/sbom.py", "src/agent_bom/sbom_formats/spdx_hierarchy.py", "src/agent_bom/parsers/spdx_context.py"]
)
def test_spdx_import_edits_select_all_spdx_and_sbom_contracts(tmp_path, source):
    expected = sorted(tmp_path / "tests" / name for name in ("test_sbom_application_inventory.py", "test_spdx_supplied_scope.py"))
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["src/agent_bom/domain/report_payloads.py", "src/agent_bom/api/read_models/scan.py"])
def test_report_contract_edits_select_producer_and_mounted_read_tests(tmp_path, source):
    expected = sorted(tmp_path / path for path in ("tests/test_report_payload_contracts.py", "tests/api/test_scan_read_contracts.py"))
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["README.md", "docs/GALLERY.md"])
def test_frontdoor_edits_select_product_explanation_contract(tmp_path, source):
    contract = tmp_path / "tests/test_product_explanations.py"
    _write(contract, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize(
    "source",
    ["README.md", "docs/README.md", "docs/NEW_GUIDE.md", "docs/perf/new-guide.md", "site-docs/new-guide.md"],
)
def test_documentation_edits_select_index_and_link_contracts(tmp_path, source):
    contract = tmp_path / "tests/test_docs_front_door.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    # New and deleted documents need the contract even without a current file.
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize("source", ["docs/image.png", "src/agent_bom/example.py"])
def test_non_documentation_edits_do_not_select_index_contract(tmp_path, source):
    _write(tmp_path / "tests/test_docs_front_door.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == []


@pytest.mark.parametrize("source", [".github/workflows/new.yml", ".github/workflows/removed.yaml"])
def test_workflow_changes_select_product_metrics_snapshot(tmp_path, source):
    contract = tmp_path / "tests/test_product_metrics_snapshot.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    # Select even when a newly added or deleted workflow is absent locally.
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


@pytest.mark.parametrize("source", [".github/workflows/README.md", ".github/ISSUE_TEMPLATE/bug.yml"])
def test_non_workflow_changes_do_not_select_product_metrics(tmp_path, source):
    _write(tmp_path / "tests/test_product_metrics_snapshot.py", 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == []


@pytest.mark.parametrize("source", ["README.md", "docs/FIRST_RUN.md", "docs/GALLERY.md"])
def test_frontdoor_edits_select_distribution_and_operator_contracts(tmp_path: Path, source: str) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_surface_freshness.py",
            "test_deploy_topology_docs.py",
            "test_consumer_precommit_hooks.py",
            "test_cli_exit_contract_docs.py",
            "test_readme_demo_excerpt.py",
            "test_published_counts_gate.py",
        )
    )
    for path in [*expected, tmp_path / "tests/test_unrelated.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_package_matching_selects_alias_severity_contract(tmp_path):
    from scripts.pytest_ci_plan import select_targeted_tests

    test = tmp_path / "tests" / "test_severity_alias_cluster_precedence.py"
    test.parent.mkdir()
    test.write_text("def test_alias(): pass\n")
    for source in ("src/agent_bom/scanners/package_scan.py", "src/agent_bom/scanners/package_versions.py"):
        assert test in select_targeted_tests(changed_files=[Path(source)], root=tmp_path)


@pytest.mark.parametrize("source", ["src/agent_bom/api/routes/discovery.py", "src/agent_bom/graph/lifecycle.py"])
def test_lifecycle_edits_select_cross_surface_credential_agreement(tmp_path, source):
    contract = tmp_path / "tests/test_credential_key_detector_agreement.py"
    _write(contract, 1)
    assert contract in select_targeted_tests(changed_files=[Path(source)], root=tmp_path)


@pytest.mark.parametrize("source", ["canonical_ids.py", "graph/edge.py", "graph/rekey.py"])
def test_identity_edits_select_persistence_and_export_consumers(tmp_path, source):
    names = [
        "graph/test_snowflake_account_staging.py",
        "graph/test_occurrence_applicability.py",
        "graph/test_asset_entity.py",
        "test_entrypoint_registries.py",
        "test_stable_ids.py",
        "test_snowflake_characterization.py",
        "test_agent_manifest.py",
        "test_agent_manifest_identity.py",
        "test_interop_schema_conformance.py",
        "test_mcp_server_scheme_aliases.py",
        "test_dependency_reach.py",
        "test_sarif_schema_2_1_0.py",
        "test_demo_inventory_accuracy.py",
    ]
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["path_evidence", "hop_evidence", "runtime_receipts", "attack_path_mitre", "technique_mapping"])
def test_hop_receipts_select_path_and_correlation_consumers(tmp_path, source):
    names = [
        "test_exposure_path_evidence_parity.py",
        "test_mcp_exposure_paths.py",
        "test_trace_graph_evidence.py",
        "test_graph_correlation_service.py",
        "api/test_graph_snapshot_path_routes.py",
    ]
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/graph/{source}.py")], root=tmp_path) == expected


@pytest.mark.parametrize("module", ["__init__", "multi_hop", "package_scan"])
def test_scanner_edits_select_public_import_contract(tmp_path: Path, module: str) -> None:
    contract = tmp_path / "tests/test_cli_scanners_init_exports.py"
    _write(contract, 1)
    assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/scanners/{module}.py")], root=tmp_path) == [contract]


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/evidence/package_remediation.py",
        "src/agent_bom/cli/_verify_remediation.py",
        "src/agent_bom/core/versions/osv.py",
    ],
)
def test_package_verification_sources_select_installed_receipt_contract(tmp_path, source):
    expected = tmp_path / "tests/test_package_remediation_verification.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [expected]


@pytest.mark.parametrize(
    "source",
    [
        "canonical_ids.py",
        "models.py",
        "agent_manifest.py",
        "evidence/occurrence_ids.py",
        "output/cyclonedx_fmt.py",
        "output/json_fmt.py",
        "parsers/sbom_topology.py",
    ],
)
def test_inventory_identity_edits_select_portable_round_trip_consumers(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_occurrence_ids.py",
            "test_evidence_portability.py",
            "test_aibom_e2e.py",
            "test_agent_manifest_identity.py",
        )
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["output/impact_brief.py", "output/impact_html.py", "cli/_impact.py", "cli/_report_group.py"])
def test_impact_reporting_selects_identity_and_receipt_contract(tmp_path, source):
    expected = tmp_path / "tests/test_impact_brief.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == [expected]


@pytest.mark.parametrize(
    "source",
    [
        "atlas.py",
        "atlas_fetch.py",
        "mitre_fetch.py",
        "framework_mapping.py",
        "evidence/finding_response_fields.py",
        "output/technique_evidence.py",
        "graph/blast_projection.py",
        "graph/edge.py",
    ],
)
def test_technique_receipt_edits_select_source_and_surface_contract(tmp_path, source):
    expected = [tmp_path / "tests" / name for name in ("test_atlas_mapping.py", "test_atlas_ui_labels.py", "test_constants.py")]
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


@pytest.mark.parametrize("changed", ["test_api_endpoints.py", "test_api_dashboard_deeplink_routes.py"])
def test_dashboard_mount_fixtures_select_scope_isolation_contracts(tmp_path, changed):
    expected = sorted(
        tmp_path / "tests/api" / name
        for name in ("test_api_endpoints.py", "test_api_dashboard_deeplink_routes.py", "test_operation_scope_coverage.py")
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("tests/api") / changed], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["output/json_fmt.py", "output/json_writer.py"])
def test_json_publication_selects_null_sink_and_low_disk_contracts(tmp_path, source):
    expected = sorted(tmp_path / "tests" / name for name in ("test_json_writer.py", "test_cli_scan.py", "test_graceful_low_disk.py"))
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom") / source], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source", ["docs/CLOUD_CONNECT.md", "docs/ARCHITECTURE.md", "docs/CLI_MAP.md", "docs/cloud/azure.md", "docs/cloud/gcp.md"]
)
def test_cloud_docs_select_provider_capability_contract(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_side_scan_capability_docs.py"
    _write(contract, 1)
    assert contract in select_targeted_tests(changed_files=[Path(source)], root=tmp_path)


def _timed_files(tmp_path: Path, seconds: dict[str, float], sizes: dict[str, int]) -> tuple[list[Path], dict[Path, float]]:
    files = []
    for name, lines in sizes.items():
        path = tmp_path / "tests" / name
        _write(path, lines)
        files.append(path)
    return files, {tmp_path / "tests" / name: value for name, value in seconds.items()}


def test_duration_plan_balances_measured_seconds_not_bytes(tmp_path: Path) -> None:
    # The slow module is tiny on disk; byte balancing stacks it with others.
    seconds = {"test_slow.py": 600.0, "test_a.py": 300.0, "test_b.py": 300.0, "test_c.py": 200.0, "test_d.py": 200.0}
    sizes = {"test_slow.py": 1, "test_a.py": 400, "test_b.py": 300, "test_c.py": 200, "test_d.py": 100}
    files, durations = _timed_files(tmp_path, seconds, sizes)

    shards = plan_shards(files, total=2, durations=durations)

    loads = sorted(sum(durations[path] for path in shard) for shard in shards)
    assert loads == [800.0, 800.0]
    assert sorted(path for shard in shards for path in shard) == sorted(files)
    assert shards == plan_shards(reversed(files), total=2, durations=durations)


def test_duration_plan_estimates_unknown_files_from_measured_bytes(tmp_path: Path) -> None:
    from scripts.pytest_ci_plan import estimate_seconds

    seconds = {"test_known.py": 10.0}
    sizes = {"test_known.py": 100, "test_new.py": 300}
    files, durations = _timed_files(tmp_path, seconds, sizes)
    known, new = files

    estimates = estimate_seconds(files, durations)

    assert estimates[known] == 10.0
    assert estimates[new] == pytest.approx(10.0 * new.stat().st_size / known.stat().st_size)


def test_duration_plan_without_any_measured_selection_keeps_byte_planning(tmp_path: Path) -> None:
    files, _ = _timed_files(tmp_path, {}, {"test_demo_estate_bootstrap.py": 1, "test_x.py": 50, "test_y.py": 40})
    unrelated = {tmp_path / "elsewhere/test_z.py": 99.0}

    assert plan_shards(files, total=2, durations=unrelated) == plan_shards(files, total=2)


@pytest.mark.parametrize("total", [2, 4])
def test_duration_plan_assigns_every_file_exactly_once(tmp_path: Path, total: int) -> None:
    sizes = {f"test_{index}.py": 10 + index for index in range(11)}
    seconds = {f"test_{index}.py": float(index % 4) for index in range(0, 11, 2)}
    files, durations = _timed_files(tmp_path, seconds, sizes)

    shards = plan_shards(files, total=total, durations=durations)

    selected = [path for shard in shards for path in shard]
    assert len(selected) == len(set(selected)) == len(files)
    assert set(selected) == set(files)


def test_load_durations_maps_repo_relative_names(tmp_path: Path) -> None:
    import json

    from scripts.pytest_ci_plan import load_durations

    timings = tmp_path / "tests/.ci-durations.json"
    timings.parent.mkdir(parents=True)
    timings.write_text(json.dumps({"files": {"tests/test_a.py": 1.5}}), encoding="utf-8")

    assert load_durations(timings) == {(tmp_path / "tests/test_a.py").resolve(): 1.5}
    assert load_durations(tmp_path / "missing.json") == {}


@pytest.mark.parametrize("payload", ["not json", '{"files": {"tests/test_a.py": -1}}', '{"files": []}'])
def test_load_durations_rejects_malformed_timings(tmp_path: Path, payload: str) -> None:
    from scripts.pytest_ci_plan import load_durations

    timings = tmp_path / "tests/.ci-durations.json"
    timings.parent.mkdir(parents=True)
    timings.write_text(payload, encoding="utf-8")

    with pytest.raises(SystemExit):
        load_durations(timings)


def test_committed_timings_cover_most_test_modules() -> None:
    from scripts.pytest_ci_plan import DURATIONS_FILE, discover_test_files, load_durations

    durations = load_durations(DURATIONS_FILE)
    modules = discover_test_files(DURATIONS_FILE.parent)
    assert sum(path.resolve() in durations for path in modules) >= 0.8 * len(modules)


@pytest.mark.parametrize(
    "source",
    [
        "integrations/agent-bom-guard/hooks/install_guard.py",
        "integrations/agent-bom-guard/hooks/hooks.json",
        "integrations/agent-bom-guard/.claude-plugin/plugin.json",
        "scripts/generate_guard_data.py",
        "src/agent_bom/malicious.py",
    ],
)
def test_guard_plugin_inputs_select_the_guard_contract(tmp_path, source):
    expected = tmp_path / "tests/test_agent_bom_guard.py"
    _write(expected, 1)
    assert expected in select_targeted_tests(changed_files=[Path(source)], root=tmp_path)
