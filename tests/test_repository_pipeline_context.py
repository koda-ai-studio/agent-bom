"""Static pipeline evidence must not execute code or retain secret values."""

import json

from agent_bom.parsers import summarize_project_inventory
from tests.test_repository_dbt_lineage import put


def test_gitlab_local_include_needs_and_reference_only_secrets(tmp_path):
    put(
        tmp_path,
        ".gitlab-ci.yml",
        """include:
  - local: /.ci/jobs.yml
  - remote: https://example.invalid/never-fetch.yml
deploy:
  needs: [build]
  environment: production
  variables:
    TOKEN: do-not-retain-value
  secrets:
    DEPLOY_TOKEN:
      vault: path/field@engine
  script: echo $DEPLOY_TOKEN
""",
    )
    put(tmp_path, ".ci/jobs.yml", "build:\n  script: echo safe\n")
    context = summarize_project_inventory(tmp_path, {})["repository_context"]
    pipelines = context.get("pipelines")
    assert pipelines is not None, "Local pipeline context is missing"
    jobs = {row["name"]: row for row in pipelines["nodes"]}
    assert set(jobs) == {"build", "deploy"}
    assert jobs["deploy"]["secret_references"] == ["DEPLOY_TOKEN"]
    assert jobs["deploy"]["deployment_target"] == "production"
    assert {tuple((edge["source"], edge["target"])) for edge in pipelines["edges"]} == {(jobs["deploy"]["key"], jobs["build"]["key"])}
    assert pipelines["status"] == "partial"
    assert "do-not-retain-value" not in json.dumps(context)
    assert "path/field" not in json.dumps(context)


def test_airflow_static_dag_tasks_dependencies_and_never_execute(tmp_path):
    put(
        tmp_path,
        "dags/shop.py",
        """from airflow import DAG as Workflow
from airflow.operators.empty import EmptyOperator as Task
raise RuntimeError('must never execute')
with Workflow(dag_id='shop') as flow:
    first = Task(task_id='extract')
    second = Task(task_id='load', conn_id='warehouse')
    first >> second
""",
    )
    result = summarize_project_inventory(tmp_path, {})["repository_context"].get("pipelines")
    assert result is not None, "Airflow source evidence is missing"
    by_name = {n["name"]: n for n in result["nodes"]}
    assert set(by_name) == {"shop", "extract", "load"}
    assert by_name["load"]["connection_references"] == ["warehouse"]
    assert {tuple((e["source"], e["target"])) for e in result["edges"]} == {(by_name["load"]["key"], by_name["extract"]["key"])}
    assert by_name["extract"]["parent"] == by_name["shop"]["key"]
    assert by_name["extract"]["line"] == 5


def test_dynamic_dag_and_unsafe_include_stay_unresolved(tmp_path):
    put(tmp_path, ".gitlab-ci.yml", "include: {local: ../outside.yml}\njob:\n  extends: .remote\n  script: echo safe\n")
    put(tmp_path, "dags/dynamic.py", "from airflow import DAG\nfor name in names:\n    dag = DAG(name)\n")
    value = summarize_project_inventory(tmp_path, {})["repository_context"].get("pipelines")
    assert value is not None
    assert value["status"] == "partial"
    reasons = {r["reason"] for r in value["unresolved"]}
    assert reasons >= {"include_unresolved", "job_inheritance_unresolved", "dynamic_airflow_structure"}


def test_pipeline_graph_is_scoped_static_and_does_not_assert_runtime(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report

    put(
        tmp_path,
        ".gitlab-ci.yml",
        "build:\n  script: echo safe\ndeploy:\n  needs: [build]\n  environment: production\n  script: echo safe\n",
    )
    graph = build_unified_graph_from_report({"project_inventory": summarize_project_inventory(tmp_path, {}), "agents": []})
    jobs = [n for n in graph.nodes.values() if n.attributes.get("subtype") == "gitlab_job"]
    assert len(jobs) == 2
    assert all(n.attributes["repository_scope"] for n in jobs)
    edges = [e for e in graph.edges if e.source in {n.id for n in jobs}]
    assert any(e.relationship.value == "depends_on" for e in edges)
    assert all(e.evidence["tier"] == "static_scan" and not e.traversable for e in edges)


def test_pipeline_cycles_and_symlink_include_are_partial(tmp_path):
    put(
        tmp_path,
        ".gitlab-ci.yml",
        "include: {local: linked.yml}\na:\n  needs: [b]\n  script: echo safe\nb:\n  needs: [a]\n  script: echo safe\n",
    )
    put(tmp_path, "local.yml", "hidden:\n  script: echo safe\n")
    (tmp_path / "linked.yml").symlink_to(tmp_path / "local.yml")
    result = summarize_project_inventory(tmp_path, {})["repository_context"]["pipelines"]
    assert result["status"] == "partial"
    assert {row["name"] for row in result["nodes"]} == {"a", "b"}
    assert {row["reason"] for row in result["unresolved"]} >= {"pipeline_dependency_cycle", "include_unavailable"}
