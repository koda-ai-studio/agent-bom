"""Retry policy is durable, bounded, and never retries authorization failures."""

from agent_bom.api.trace_collection.retry import provider_retry_after, retry_delay


def test_exponential_backoff_and_jitter_have_a_ceiling():
    assert retry_delay(1, jitter=0) == 60
    assert retry_delay(3, jitter=0) == 240
    assert retry_delay(100, jitter=1) == 3600
    assert retry_delay(2, retry_after=900, jitter=0) == 900


def test_retry_after_parses_delta_and_http_date():
    assert provider_retry_after("120", now=100) == 120
    assert provider_retry_after("Thu, 01 Jan 1970 00:03:20 GMT", now=100) == 100
    assert provider_retry_after("bad", now=100) == 0
    assert provider_retry_after("999999999", now=100) == 86400
