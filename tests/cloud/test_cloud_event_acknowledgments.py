"""Queue drain summaries distinguish processing from confirmed acknowledgment."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.cloud import azure_event_ingest, event_ingest, gcp_event_ingest


@pytest.fixture(params=["aws", "azure", "gcp"])
def drain(request, monkeypatch):
    provider = request.param
    module, parser, consumer = {
        "aws": (event_ingest, "parse_cloudtrail_event", event_ingest.consume_aws_events),
        "azure": (azure_event_ingest, "parse_azure_event", azure_event_ingest.consume_azure_events),
        "gcp": (gcp_event_ingest, "parse_gcp_event", gcp_event_ingest.consume_gcp_events),
    }[provider]
    account = "123456789012"
    record = CloudConnectionRecord(
        id="connection",
        tenant_id="tenant",
        provider=provider,
        display_name="test",
        role_ref=f"arn:aws:iam::{account}:role/readonly",
        external_id_encrypted="cipher",
        auth_params={"subscription_id": account, "project_id": account},
    )
    event = event_ingest.CloudChangeEvent(provider, account, "region", "storage", "bucket", "change")
    parse = Mock(return_value=event)
    dispatch = Mock()
    monkeypatch.setattr(module, parser, parse)
    monkeypatch.setattr(module, "dispatch_change_event", dispatch)
    client = Mock()
    if provider == "aws":
        messages = [{"Body": "{}", "ReceiptHandle": str(i)} for i in range(2)]
        receive = client.receive_message
        receive.return_value = {"Messages": messages}
        ack = client.delete_message
        kwargs = {"queue_url": "https://queue.test", "sqs_client": client, "session": object()}
    elif provider == "azure":
        messages = [SimpleNamespace(content="{}") for _ in range(2)]
        receive = client.receive_messages
        receive.return_value = messages
        ack = client.delete_message
        kwargs = {"queue_url": "https://queue.test", "queue_client": client, "credential": object()}
    else:
        messages = [SimpleNamespace(ack_id=str(i), message=SimpleNamespace(data=b"{}")) for i in range(2)]
        receive = client.pull
        receive.return_value = SimpleNamespace(received_messages=messages)
        ack = client.acknowledge
        kwargs = {"subscription": "projects/p/subscriptions/q", "subscriber_client": client, "credentials": object()}
    return SimpleNamespace(
        provider=provider,
        run=lambda: consumer(record, max_batches=1, **kwargs),
        ack=ack,
        receive=receive,
        dispatch=dispatch,
        parse=parse,
        event=event,
        messages=messages,
        acknowledged="acked" if provider == "gcp" else "deleted",
    )


@pytest.mark.parametrize("kind", ["processed", "malformed", "foreign"])
def test_ack_failure_is_counted_and_later_messages_continue(drain, kind, caplog):
    if kind == "malformed":
        drain.parse.return_value = None
    elif kind == "foreign":
        drain.event.account = "foreign"
    drain.ack.side_effect = [RuntimeError("api_key=private-provider-value"), None]
    summary = drain.run()
    assert summary["errors"] == 1
    assert summary["status"] == "partial"
    assert summary["received"] == 2
    assert summary[drain.acknowledged] == 1
    assert summary["processed"] == (2 if kind == "processed" else 0)
    assert drain.ack.call_count == 2
    assert "private-provider-value" not in caplog.text
    assert "private-provider-value" not in str(summary)


def test_dispatch_failure_remains_unacknowledged_and_is_partial(drain):
    drain.dispatch.side_effect = [RuntimeError("temporary"), None]
    summary = drain.run()
    assert summary["status"] == "partial"
    assert summary["errors"] == 1
    assert summary["processed"] == 1
    assert summary[drain.acknowledged] == 1
    assert drain.ack.call_count == 1


def test_receive_failure_is_partial(drain):
    drain.receive.side_effect = RuntimeError("temporary")
    summary = drain.run()
    assert summary["status"] == "partial"
    assert summary["errors"] == 1
    assert summary["received"] == 0
    drain.ack.assert_not_called()


def test_successful_drain_is_ok(drain):
    summary = drain.run()
    assert summary["status"] == "ok"
    assert summary["errors"] == 0
    assert summary["processed"] == summary[drain.acknowledged] == 2


def test_missing_ack_handle_is_counted(drain):
    if drain.provider == "azure":
        pytest.skip("Azure validates receipt handles in its SDK delete call")
    if drain.provider == "aws":
        drain.messages[0].pop("ReceiptHandle")
    else:
        drain.messages[0].ack_id = None
    summary = drain.run()
    assert summary["status"] == "partial"
    assert summary["errors"] == 1
    assert summary["processed"] == 2
    assert summary[drain.acknowledged] == 1
