"""Qualified local fixtures: real gateway forwarding, target-side effect receipt.

The target and its receipts are controlled by this harness. They establish local
behavior, never independent AWS execution, customer activity or compromise.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key
from agent_bom.cloud.audit_trail_aws import aws_event_outcome
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


@pytest.mark.parametrize(
    "response,error,expected",
    [
        ({"statusCode": 202}, None, "accepted"),
        ({"statusCode": 200}, None, "unknown"),
        ({"statusCode": 204}, None, "unknown"),
        ({}, "AccessDeniedException", "failure"),
    ],
)
def test_lambda_attempt_receipt_cannot_prove_execution_or_effect(response, error, expected):
    document = {"responseElements": response}
    if error:
        document["errorCode"] = error
    assert aws_event_outcome({"CloudTrailEvent": json.dumps(document)}, "Invoke") == expected


def test_gateway_execution_effect_and_recollection_over_real_upstream_http(monkeypatch, tmp_path):
    """Revoke only the local policy; retained target receipts survive recreation."""
    receipts_path = tmp_path / "target-receipts.jsonl"
    effects_path = tmp_path / "target-effects.jsonl"
    orders_path = tmp_path / "synthetic-orders.json"
    orders_path.write_text(json.dumps({"ORDER-DEMO-1042": {"status": "shipped"}}))
    lock = threading.Lock()

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            tool = message["params"]["name"]
            result = "done"
            receipt = {"attempt_id": message["id"], "tool": tool, "basis": "local_fixture_target"}
            with lock:
                with receipts_path.open("a") as stream:
                    stream.write(json.dumps(receipt) + "\n")
                if tool == "lookup_order":
                    order = json.loads(orders_path.read_text())["ORDER-DEMO-1042"]
                    result = json.dumps(order, sort_keys=True)
                    digest = hashlib.sha256(result.encode()).hexdigest()
                    with effects_path.open("a") as stream:
                        stream.write(json.dumps({**receipt, "effect": "read_synthetic_order", "result_sha256": digest}) + "\n")
            data = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {"content": [{"type": "text", "text": result}]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    store = KeyStore()
    key, identity = create_api_key("orders-reader", Role.ANALYST, tenant_id="northstar-staging", scopes=["gateway:relay"])
    store.add(identity)
    other_key, other_identity = create_api_key("orders-reader", Role.ANALYST, tenant_id="northstar-production", scopes=["gateway:relay"])
    store.add(other_identity)
    monkeypatch.setattr("agent_bom.api.gateway_auth.get_key_store", lambda: store)
    registry = UpstreamRegistry(
        [
            UpstreamConfig(
                name="orders",
                url=f"http://127.0.0.1:{target.server_port}/mcp",
                tenant_id="northstar-staging",
                private_network_approved=True,
            )
        ]
    )
    audit = []

    async def sink(event):
        audit.append(event)

    def gateway(blocked):
        return TestClient(
            create_gateway_app(
                GatewaySettings(
                    registry=registry,
                    policy={"rules": [{"id": "scoped-tool-deny", "action": "block", "block_tools": blocked}]},
                    audit_sink=sink,
                )
            )
        )

    def call(client, attempt, tool, credential=key):
        return client.post(
            "/mcp/orders",
            headers={"X-API-Key": credential},
            json={"jsonrpc": "2.0", "id": attempt, "method": "tools/call", "params": {"name": tool, "arguments": {}}},
        )

    def read(path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    try:
        # Same display name in another tenant grants no access to this target.
        with gateway(["admin_action"]) as client:
            assert call(client, "wrong-tenant", "lookup_order", other_key).status_code in {403, 404}
            denied = call(client, "denied", "admin_action")
            assert denied.json()["error"]["code"] == -32001
            assert read(receipts_path) == read(effects_path) == []
            assert "result" in call(client, "completed-no-effect", "noop").json()
            assert read(effects_path) == []
            response = call(client, "completed-with-effect", "lookup_order").json()
            returned = response["result"]["content"][0]["text"]
            assert json.loads(returned) == {"status": "shipped"}
        before = read(receipts_path)
        assert [r["attempt_id"] for r in before] == ["completed-no-effect", "completed-with-effect"]
        assert [r["attempt_id"] for r in read(effects_path)] == ["completed-with-effect"]
        assert read(effects_path)[0]["result_sha256"] == hashlib.sha256(returned.encode()).hexdigest()
        # Apply an authorized task-local policy change and recreate the gateway.
        with gateway(["admin_action", "lookup_order"]) as client:
            assert call(client, "after-revoke", "lookup_order").json()["error"]["code"] == -32001
            assert "result" in call(client, "legitimate-noop", "noop").json()
        after = read(receipts_path)
        assert after[:2] == before
        assert [r["attempt_id"] for r in after] == ["completed-no-effect", "completed-with-effect", "legitimate-noop"]
        assert len(read(effects_path)) == 1
        assert len([event for event in audit if event["action"] == "gateway.policy_blocked"]) == 2
    finally:
        target.shutdown()
        target.server_close()
        thread.join(timeout=5)
