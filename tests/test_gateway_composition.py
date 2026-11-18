"""Gateway composition must fit the normal architecture budget."""

import ast
from pathlib import Path


def test_gateway_composition_has_no_function_size_allowance():
    source = Path(__file__).resolve().parents[1] / "src/agent_bom/gateway_server.py"
    tree = ast.parse(source.read_text())
    factory = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "create_gateway_app")
    assert factory.end_lineno - factory.lineno + 1 <= 80


def test_gateway_routes_keep_their_openapi_operation_ids():
    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamRegistry

    async def audit(_event):
        pass

    app = create_gateway_app(GatewaySettings(registry=UpstreamRegistry([]), policy={}, audit_sink=audit))
    paths = app.openapi()["paths"]
    assert {path: next(iter(methods.values()))["operationId"] for path, methods in paths.items()} == {
        "/healthz": "healthz_healthz_get",
        "/readyz": "readyz_readyz_get",
        "/v1/firewall/check": "firewall_check_v1_firewall_check_post",
        "/metrics": "metrics_metrics_get",
        "/mcp/{server_name}": "relay_mcp__server_name__post",
    }
