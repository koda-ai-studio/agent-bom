"""Provider timing must be bounded without retaining untrusted header text."""

import pytest

from agent_bom.core.http_retry import provider_retry_after


@pytest.mark.parametrize(
    "header,expected",
    [
        (None, 0),
        (" 120 ", 120),
        ("Thu, 01 Jan 1970 00:03:20 GMT", 100),
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ("999999999999999999999999", 86400),
        ("-1", 0),
        ("NaN", 0),
        ("Infinity", 0),
        ("²", 0),
        ("api_key=private-value", 0),
    ],
)
def test_retry_after_is_bounded_and_invalid_headers_are_ignored(header, expected):
    assert provider_retry_after(header, now=100) == expected
