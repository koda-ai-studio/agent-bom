"""Access-key age findings retain useful evidence without exposing key identifiers."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from agent_bom.cloud.aws_cis_benchmark import _check_1_14
from agent_bom.security import sanitize_sensitive_payload


def test_stale_access_key_evidence_survives_export_redaction():
    client = Mock()
    user_arn = "arn:aws:iam::123456789012:user/fixture-user"
    client.get_paginator.return_value.paginate.return_value = [{"Users": [{"UserName": "fixture-user", "Arn": user_arn}]}]
    key_id = "AK" + "IA" + "X" * 16
    client.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": key_id, "Status": "Active", "CreateDate": datetime.now(timezone.utc) - timedelta(days=100)}]
    }
    result = _check_1_14(client)
    exported = sanitize_sensitive_payload({"evidence": result.evidence, "resource_ids": result.resource_ids})
    assert result.status.value == "fail"
    assert "1 access key(s) older than 90 days" in exported["evidence"]
    assert "100 days" in exported["evidence"]
    assert key_id not in str(exported)
    assert exported["resource_ids"] == [user_arn]
