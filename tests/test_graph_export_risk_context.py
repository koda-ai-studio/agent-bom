"""Graph exports carry each node's risk context and its reasons."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from agent_bom.output.graph_export import build_graph_from_scan_data, to_graphml, to_json

_RDS = "cloud_resource:aws:rds:database:arn:aws:rds:us-east-1:111122223333:db:prod-db"


def _scan() -> dict:
    return {
        "agents": [],
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": "111122223333",
            "rds_instances": [
                {
                    "name": "prod-db",
                    "arn": "arn:aws:rds:us-east-1:111122223333:db:prod-db",
                    "engine": "postgres",
                    "publicly_accessible": True,
                }
            ],
        },
    }


def test_json_export_round_trips_the_risk_context() -> None:
    exported = json.loads(json.dumps(to_json(build_graph_from_scan_data(_scan()))))
    node = next(node for node in exported["nodes"] if node["id"] == _RDS)
    context = node["attributes"]["risk_context"]
    assert context["internet_exposed"] is True
    assert context["reasons"][0]["evidence"]["inputs"] == {"publicly_accessible": True}


def test_graphml_export_keeps_the_risk_context_in_node_attributes() -> None:
    root = ET.fromstring(to_graphml(build_graph_from_scan_data(_scan())))
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    keys = {key.get("attr.name"): key.get("id") for key in root.findall("g:key", ns)}
    node = next(node for node in root.iter("{http://graphml.graphdrawing.org/xmlns}node") if node.get("id") == _RDS)
    data = {item.get("key"): item.text for item in node.findall("g:data", ns)}
    attributes = json.loads(data[keys["attributes_json"]])
    assert attributes["risk_context"]["internet_exposed"] is True
