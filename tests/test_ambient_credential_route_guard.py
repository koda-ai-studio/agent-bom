"""Class guard: API code that spends the server's own credentials is opt-in and caller-checked.

The API process may hold credentials that belong to the operator, not to the
tenant sending a request: a cloud role or profile, ``SNOWFLAKE_*``, a
Kubernetes service account or kubeconfig, SaaS connector tokens, Okta/Entra
tokens, an ``HF_TOKEN`` or an Ollama host. Every route that reaches one must

* check an operator opt-in (or the tenant binding, for providers that gate on
  their own flag) in the same top-level function, and
* check the caller: an admin ``cloud_ambient`` dependency, an explicit caller
  check, or an admin-only route policy.

Scan jobs reach Kubernetes and connectors from the discovery stages rather than
from a route, so every scan entry point must decide ``ambient_caller``
explicitly and the queued job must recheck the opt-in before discovery.

Entry points imported into ``api/routes`` must be classified here, so a new
ambient read cannot land without a decision.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "api"
ROUTES_DIR = API_DIR / "routes"

# Names that, when used in route code, spend the server's own credentials.
AMBIENT_SINKS = frozenset(
    {
        # Snowflake governance / Cortex / activity
        "discover_governance",
        "discover_activity",
        "_get_connection",
        "_mine_cortex_agent_usage",
        "_mine_observability_events",
        "get_cortex_telemetry",
        # Cloud identity
        "_run_cis_benchmark",
        "_build_inventory_payload",
        # Kubernetes service account / kubeconfig
        "_collect_posture",
        "scan_live_cluster_posture_with_evidence",
        "select_k8s_transport",
        # SaaS connector tokens
        "check_connector_health",
        "discover_from_connector",
        # Okta / Entra tokens
        "discover_okta_non_human_identities",
        "discover_entra_non_human_identities",
        # HF_TOKEN / Ollama host
        "check_hf_models",
        "check_ollama_models",
    }
)

# Opt-in flags and tenant binding checks.
OPT_IN_GUARDS = frozenset(
    {
        "ambient_cis_enabled",
        "ambient_snowflake_governance_enabled",
        "_require_snowflake_governance",
        "_require_live_posture_allowed",
        "connector_health_refusal",
        "require_connector_health_caller",
        "api_model_hub_credentials_enabled",
        "discover_idp_subjects",
        "ambient_tenant_permitted",
    }
)

CALLER_CHECKS = frozenset({"caller_may_use_ambient", "connector_health_refusal", "require_connector_health_caller"})
AMBIENT_ROUTE_DEPENDENCIES = frozenset({"_AMBIENT_DEP", "_CIS_DEP"})

# Routes whose provider calls gate on their own operator flag inside discovery.
SELF_GATED: dict[tuple[str, str], str] = {
    ("identities.py", "discover_non_human_identities"): "Okta/Entra gate on AGENT_BOM_OKTA_DISCOVERY / AGENT_BOM_ENTRA_DISCOVERY",
}

# Reviewed ambient uses that are gated elsewhere.
REVIEWED_EXCEPTIONS: dict[tuple[str, str], str] = {
    ("cloud.py", "cloud_inventory"): "each provider checks its own AGENT_BOM_<PROVIDER>_INVENTORY opt-in inside discovery",
}

# Scan-pipeline entry points that must decide whether the caller may use ambient targets.
SCAN_ADMISSION_CALLS = frozenset({"_sanitize_scan_request_paths", "_request_for_source", "_validate_enabled_source_schedule"})
AMBIENT_SCAN_FIELDS = frozenset({"k8s", "connectors"})
PIPELINE_SINKS = frozenset({"select_k8s_transport", "discover_from_connector", "check_connector_health"})

_ENTRY_POINT = re.compile(
    r"^_?(discover\w*|run_benchmark\w*|_?get_connection|_mine_\w+|check_\w+_models|get_cortex_\w+"
    r"|check_\w+_health|select_\w+_transport|scan_live_\w+)$"
)
_SDK_NAMES = frozenset({"boto3", "DefaultAzureCredential", "snowflake", "google", "huggingface_hub", "kubernetes"})
_ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "api_route"})
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _route_modules() -> list[Path]:
    return sorted(ROUTES_DIR.rglob("*.py"))


def _api_modules() -> list[Path]:
    return sorted(API_DIR.rglob("*.py"))


def _names(node: ast.AST) -> set[str]:
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.alias):
            found.add(child.asname or child.name.rsplit(".", 1)[-1])
    return found


def _called(node: ast.AST) -> set[str]:
    called: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    return called


def _route_target(node: ast.AsyncFunctionDef | ast.FunctionDef) -> tuple[str, str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr in _ROUTE_DECORATORS and decorator.args and isinstance(decorator.args[0], ast.Constant):
            return decorator.func.attr.upper(), f"/v1{decorator.args[0].value}"
    return None


def _default_names(node: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
    return {d.id for d in defaults if isinstance(d, ast.Name)}


def _decorator_ambient_dependency(node: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    """``dependencies=[_dep("cloud_ambient")]`` on the route decorator."""
    for decorator in node.decorator_list:
        for child in ast.walk(decorator):
            if isinstance(child, ast.Constant) and child.value == "cloud_ambient":
                return True
    return False


def _caller_checked(node: ast.AsyncFunctionDef | ast.FunctionDef, route: tuple[str, str]) -> bool:
    from agent_bom.api.route_policy import required_role

    method, path = route
    return bool(
        _default_names(node) & AMBIENT_ROUTE_DEPENDENCIES
        or _decorator_ambient_dependency(node)
        or _called(node) & CALLER_CHECKS
        or required_role(method, path) == "admin"
    )


def unguarded_ambient_uses(module_name: str, source: str) -> list[str]:
    """Top-level functions that reach an ambient sink without an opt-in and caller check.

    A private helper may leave the check to its callers when every function in
    the module that references it performs one.
    """
    functions = [node for node in ast.parse(source).body if isinstance(node, _FUNCTIONS)]
    problems: list[str] = []
    for node in functions:
        sinks = _names(node) & AMBIENT_SINKS
        if not sinks or (module_name, node.name) in REVIEWED_EXCEPTIONS:
            continue
        route = _route_target(node)
        guarded = bool(_called(node) & OPT_IN_GUARDS) or (module_name, node.name) in SELF_GATED
        if not guarded and route is None:
            callers = [other for other in functions if other is not node and node.name in _names(other)]
            guarded = bool(callers) and all(_called(caller) & OPT_IN_GUARDS for caller in callers)
        if not guarded:
            problems.append(f"{module_name}:{node.lineno} {node.name} uses {sorted(sinks)} without an operator opt-in check")
        elif route is not None and not _caller_checked(node, route):
            problems.append(f"{module_name}:{node.lineno} {node.name} is not limited to the cloud_ambient permission")
    return problems


def unclassified_entry_points(module_name: str, source: str) -> list[str]:
    problems: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _SDK_NAMES:
                    problems.append(f"{module_name}:{node.lineno} imports SDK {alias.name} directly")
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.module.split(".")[0] in _SDK_NAMES:
            problems.append(f"{module_name}:{node.lineno} imports SDK {node.module} directly")
            continue
        if not node.module.startswith(
            ("agent_bom.cloud", "agent_bom.api.cloud_", "agent_bom.connectors", "agent_bom.k8s", "agent_bom.identity")
        ):
            continue
        for alias in node.names:
            if _ENTRY_POINT.match(alias.name) and alias.name not in AMBIENT_SINKS:
                problems.append(f"{module_name}:{node.lineno} imports {alias.name} from {node.module}; classify it in AMBIENT_SINKS")
    return problems


def scan_admissions_without_caller_decision(module_name: str, source: str) -> list[str]:
    problems: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if name in SCAN_ADMISSION_CALLS and not any(keyword.arg == "ambient_caller" for keyword in node.keywords):
            problems.append(f"{module_name}:{node.lineno} calls {name} without deciding ambient_caller")
    return problems


def test_every_ambient_route_use_checks_an_operator_opt_in() -> None:
    problems = [problem for path in _route_modules() for problem in unguarded_ambient_uses(path.name, path.read_text(encoding="utf-8"))]
    assert not problems, "\n".join(problems)


def test_route_code_has_no_unclassified_provider_entry_points() -> None:
    problems = [problem for path in _route_modules() for problem in unclassified_entry_points(path.name, path.read_text(encoding="utf-8"))]
    assert not problems, "\n".join(problems)


def test_every_scan_admission_decides_the_ambient_caller() -> None:
    problems = [
        problem
        for path in _api_modules()
        for problem in scan_admissions_without_caller_decision(path.name, path.read_text(encoding="utf-8"))
    ]
    assert not problems, "\n".join(problems)


def test_scan_discovery_of_ambient_targets_is_rechecked_before_it_runs() -> None:
    """Discovery stages that reach ambient credentials read only fields the admission gate knows."""
    stages = ast.parse((API_DIR / "scan_discovery_stages.py").read_text(encoding="utf-8"))
    functions = {node.name: node for node in stages.body if isinstance(node, _FUNCTIONS)}
    assert "ambient_scan_refusal" in _called(functions["prepare_request"])
    for node in functions.values():
        if _names(node) & PIPELINE_SINKS:
            read = {child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)}
            assert read & AMBIENT_SCAN_FIELDS, f"{node.name} reaches {sorted(_names(node) & PIPELINE_SINKS)} via an unclassified field"
    gate = (API_DIR / "ambient_access.py").read_text(encoding="utf-8")
    for field in AMBIENT_SCAN_FIELDS:
        assert f'"{field}"' in gate, f"ambient_access does not gate ScanRequest.{field}"


def test_reviewed_exceptions_still_exist() -> None:
    """A stale exception would silently widen the allowance."""
    for (module_name, function_name), _reason in {**REVIEWED_EXCEPTIONS, **SELF_GATED}.items():
        tree = ast.parse((ROUTES_DIR / module_name).read_text(encoding="utf-8"))
        names = {n.name for n in tree.body if isinstance(n, _FUNCTIONS)}
        assert function_name in names, f"{module_name}:{function_name} no longer exists; drop it from REVIEWED_EXCEPTIONS"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "@router.get('/x')\nasync def leak():\n    from agent_bom.cloud import discover_governance\n    return discover_governance()\n",
            "without an operator opt-in check",
        ),
        (
            "@router.get('/x')\nasync def half(_role=_READ_DEP):\n    _require_snowflake_governance()\n    return _get_connection()\n",
            "cloud_ambient permission",
        ),
        (
            "@router.get('/connectors/{name}/health')\nasync def probe(name):\n    return check_connector_health(name)\n",
            "without an operator opt-in check",
        ),
        (
            "def _helper():\n    return select_k8s_transport()\n\n@router.post('/x')\ndef route():\n    return _helper()\n",
            "without an operator opt-in check",
        ),
    ],
)
def test_guard_flags_unsafe_routes(source: str, expected: str) -> None:
    problems = unguarded_ambient_uses("synthetic.py", source)
    assert problems and expected in problems[0]


def test_guard_flags_new_unclassified_entry_point() -> None:
    assert unclassified_entry_points("synthetic.py", "from agent_bom.cloud.snowflake import discover_stages\n")
    assert unclassified_entry_points("synthetic.py", "from agent_bom.connectors import check_github_health\n")


def test_guard_flags_a_scan_admission_without_a_decision() -> None:
    assert scan_admissions_without_caller_decision("synthetic.py", "_request_for_source(source)\n")
    assert not scan_admissions_without_caller_decision("synthetic.py", "_request_for_source(source, ambient_caller=False)\n")


def test_guard_accepts_a_gated_admin_route() -> None:
    source = "@router.get('/x')\nasync def ok(_role=_AMBIENT_DEP):\n    _require_snowflake_governance()\n    return discover_governance()\n"
    assert unguarded_ambient_uses("synthetic.py", source) == []
