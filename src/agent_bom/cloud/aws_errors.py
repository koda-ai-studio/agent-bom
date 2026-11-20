"""Fixed, secret-free AWS collection diagnostics.

AWS exception messages carry ARNs, account ids and request ids. Classify only
the structured ``Error.Code`` / HTTP status and never copy message text.
"""

from __future__ import annotations

from .collection_errors import CollectionError, CollectionStatus, collection_status, collection_warning

# Credential and authorization failures (botocore ClientError codes).
AWS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthFailure",
        "AuthorizationError",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "InvalidSignatureException",
        "MissingAuthenticationToken",
        "SignatureDoesNotMatch",
        "UnauthorizedAccess",
        "UnauthorizedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }
)

# Superset of botocore 1.43 ``retries.standard`` throttled error codes.
AWS_THROTTLED_CODES = frozenset(
    {
        "BandwidthLimitExceeded",
        "EC2ThrottledException",
        "LimitExceededException",
        "PriorRequestNotComplete",
        "ProvisionedThroughputExceededException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "RequestThrottledException",
        "SlowDown",
        "ThrottledException",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "TransactionInProgressException",
    }
)

_CREDENTIAL_ERRORS = ("NoCredentialsError", "PartialCredentialsError", "NoRegionError", "TokenRetrievalError", "SSOTokenLoadError")


def aws_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    code = error.get("Code") if isinstance(error, dict) else None
    return code if isinstance(code, str) else ""


def aws_read_status(exc: Exception) -> CollectionStatus:
    """Classify a boto3/botocore failure from structured fields only."""
    if isinstance(exc, CollectionError):
        return exc.status
    code = aws_error_code(exc)
    if code in AWS_DENIED_CODES:
        return CollectionStatus.DENIED
    if code in AWS_THROTTLED_CODES:
        return CollectionStatus.THROTTLED
    if type(exc).__name__ in _CREDENTIAL_ERRORS:
        return CollectionStatus.DENIED
    response = getattr(exc, "response", None)
    metadata = response.get("ResponseMetadata") if isinstance(response, dict) else None
    http_status = metadata.get("HTTPStatusCode") if isinstance(metadata, dict) else None
    if isinstance(http_status, int):
        return {401: CollectionStatus.DENIED, 403: CollectionStatus.DENIED, 429: CollectionStatus.THROTTLED}.get(
            http_status, CollectionStatus.UNAVAILABLE
        )
    return collection_status(exc)


def aws_read_warning(resource: str, exc: Exception) -> str:
    """``aws:<resource>:<status>: <guidance> Assessment incomplete.`` — no provider text."""
    return collection_warning("aws", resource, CollectionError(aws_read_status(exc)))
