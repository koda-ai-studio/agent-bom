"""Read-only OCI distribution API client: manifests, blobs and referrers.

Every request is a GET. Manifests and blobs are verified against their digest
before use, blobs stream to a temporary file under a hard byte cap, and
redirects (registries hand blobs to a CDN) are followed by hand: HTTPS only,
and the ``Authorization`` header is dropped as soon as the host changes.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO, Any
from urllib.parse import urlencode, urljoin, urlparse

import httpcore
import httpx

from agent_bom.http_client import check_offline
from agent_bom.oci_registry.auth import (
    ANONYMOUS,
    RegistryAuthError,
    RegistryCredential,
    basic_header,
    parse_challenge,
    validate_realm,
)
from agent_bom.oci_registry.media_types import MANIFEST_ACCEPT, OCI_INDEX
from agent_bom.oci_registry.policy import LOCAL_POLICY, RegistryPolicy
from agent_bom.oci_registry.reference import ImageReference
from agent_bom.runtime.egress_transport import PinnedDNSSyncTransport, UnsafeDestinationError

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
_MAX_REDIRECTS = 5
_CHUNK = 1024 * 1024
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_USER_AGENT = "agent-bom-registry-client"
_TRANSPORT_ERRORS = (
    httpx.HTTPError,
    httpcore.TimeoutException,
    httpcore.NetworkError,
    httpcore.ProtocolError,
    httpcore.UnsupportedProtocol,
)


class RegistryError(Exception):
    """A registry request failed; ``status`` is the HTTP status when there was one."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RegistryPolicyError(RegistryError):
    """The registry egress policy refused a destination (server-side scans)."""


class RegistryLimitError(RegistryError):
    """A supply-chain lookup exceeded a finite resource budget."""


@dataclass
class EvidenceBudget:
    deadline: float
    max_requests: int = 64
    max_bytes: int = 16 * 1024 * 1024
    requests: int = 0
    bytes_read: int = 0

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RegistryLimitError("Supply-chain lookup time limit reached")
        return remaining

    def request(self) -> httpx.Timeout:
        remaining = self.remaining()
        if self.requests >= self.max_requests:
            raise RegistryLimitError("Supply-chain lookup request limit reached")
        self.requests += 1
        return httpx.Timeout(min(30.0, remaining), connect=min(10.0, remaining))

    def consume(self, size: int) -> None:
        self.remaining()
        self.bytes_read += size
        if self.bytes_read > self.max_bytes:
            raise RegistryLimitError("Supply-chain lookup aggregate byte limit reached")


@dataclass(frozen=True)
class FetchedManifest:
    media_type: str
    digest: str
    raw: bytes
    document: dict[str, Any]


def _default_transport() -> httpx.BaseTransport | None:
    """Transport for new clients; the test suite swaps this for an in-memory registry."""
    return None


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_hasher(digest: str) -> Any:
    algorithm = digest.split(":", 1)[0]
    if algorithm not in {"sha256", "sha512"}:
        raise RegistryError(f"Unsupported digest algorithm: {algorithm}")
    return hashlib.new(algorithm)


def _matches_digest(data: bytes, digest: str) -> bool:
    """Whether ``data`` hashes to ``digest`` (``sha256``/``sha512``; any other algorithm is rejected)."""
    hasher = _digest_hasher(digest)
    hasher.update(data)
    return f"{digest.split(':', 1)[0]}:{hasher.hexdigest()}" == digest


def _read_bounded(response: httpx.Response, limit: int, what: str, on_chunk: Callable[[int], None] | None = None) -> bytes:
    """Read a streamed body into memory, aborting as soon as it passes ``limit`` bytes."""
    buffer = bytearray()
    try:
        for chunk in response.iter_bytes():
            if on_chunk is not None:
                on_chunk(len(chunk))
            buffer += chunk
            if len(buffer) > limit:
                raise RegistryError(f"{what} exceeds the size limit")
    except _TRANSPORT_ERRORS as exc:
        raise RegistryError(f"{what} download failed: {type(exc).__name__}") from exc
    finally:
        response.close()
    return bytes(buffer)


@dataclass
class RegistryClient:
    """Client for one repository on one registry."""

    ref: ImageReference
    credential_resolver: Callable[[], RegistryCredential] = field(default=lambda: ANONYMOUS)
    transport: httpx.BaseTransport | None = None
    policy: RegistryPolicy = LOCAL_POLICY
    _token: str | None = None
    _basic: str | None = None
    _credential: RegistryCredential | None = None
    _client: httpx.Client | None = None
    _evidence_budget: EvidenceBudget | None = None

    def __post_init__(self) -> None:
        check_offline()
        reason = self.policy.refusal(self.ref)
        if reason is not None:
            raise RegistryPolicyError(f"Registry refused by server-side egress policy: {reason}")
        transport = self.transport if self.transport is not None else _default_transport()
        if transport is None and self.policy.server:
            transport = PinnedDNSSyncTransport(allow_private_networks=False)
        self._client = httpx.Client(
            timeout=_TIMEOUT, transport=transport, follow_redirects=False, verify=True, trust_env=not self.policy.server
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def bounded_evidence(self, *, seconds: float = 30.0, max_requests: int = 64, max_bytes: int = 16 * 1024 * 1024):
        previous = self._evidence_budget
        self._evidence_budget = previous or EvidenceBudget(time.monotonic() + seconds, max_requests, max_bytes)
        try:
            yield self._evidence_budget
        finally:
            self._evidence_budget = previous

    def _consume_evidence(self, size: int) -> None:
        if self._evidence_budget is not None:
            self._evidence_budget.consume(size)

    @property
    def credential_source(self) -> str:
        return self._credential.source if self._credential is not None else "anonymous"

    @property
    def base_url(self) -> str:
        scheme = "http" if self.policy.allows_plain_http(self.ref) else "https"
        return f"{scheme}://{self.ref.registry}/v2/{self.ref.repository}"

    def _status(self, status: int) -> str:
        """`` (HTTP n)`` for the local CLI; server-side scans withhold upstream status."""
        return "" if self.policy.server else f" (HTTP {status})"

    def _auth_headers(self) -> dict[str, str]:
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        if self._basic:
            return {"Authorization": self._basic}
        return {}

    def _authenticate(self, response: httpx.Response) -> None:
        challenge = parse_challenge(response.headers.get("www-authenticate"))
        if challenge is None:
            raise RegistryError("Registry requires authentication but sent no usable challenge", 401)
        if self._credential is None:
            self._credential = self.credential_resolver()
        if challenge.scheme == "basic":
            self._basic = basic_header(self._credential)
            if self._basic is None:
                raise RegistryError("Registry requires credentials (none found for this registry)", 401)
            return
        self._token = self._fetch_token(challenge.params)

    def _fetch_token(self, params: dict[str, str]) -> str:
        realm = validate_realm(params.get("realm", ""), allow_plain_http=self.policy.allows_plain_http(self.ref))
        query = {k: v for k, v in params.items() if k in {"service", "scope"} and v}
        query.setdefault("scope", f"repository:{self.ref.repository}:pull")
        credential = self._credential or ANONYMOUS
        assert self._client is not None
        if credential.identity_token:
            form = {"grant_type": "refresh_token", "refresh_token": credential.identity_token, "client_id": "agent-bom", **query}
            response = self._send_request("POST", realm, {"User-Agent": _USER_AGENT}, data=form)
        else:
            headers = {"User-Agent": _USER_AGENT}
            if (basic := basic_header(credential)) is not None:
                headers["Authorization"] = basic
            response = self._send_request("GET", f"{realm}?{urlencode(query)}", headers)
        if response.status_code != 200:
            response.close()
            raise RegistryError(f"Registry token request was refused{self._status(response.status_code)}", response.status_code)
        try:
            payload = json.loads(_read_bounded(response, MAX_TOKEN_BYTES, "Registry token response", self._consume_evidence))
        except ValueError as exc:
            raise RegistryError("Registry token response was not JSON") from exc
        if not isinstance(payload, dict):
            raise RegistryError("Registry token response was not a JSON object")
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RegistryError("Registry token response carried no token")
        return token

    def _send_request(self, method: str, url: str, headers: dict[str, str], *, stream: bool = True, data: Any = None) -> httpx.Response:
        assert self._client is not None
        timeout = self._evidence_budget.request() if self._evidence_budget is not None else _TIMEOUT
        request = self._client.build_request(method, url, headers=headers, data=data, timeout=timeout)
        try:
            return self._client.send(request, stream=stream)
        except UnsafeDestinationError as exc:
            raise RegistryPolicyError("Registry refused by server-side egress policy: destination address is not public") from exc
        except _TRANSPORT_ERRORS as exc:
            raise RegistryError(f"Registry request failed: {type(exc).__name__}") from exc

    def _send(self, url: str, headers: dict[str, str], *, stream: bool) -> httpx.Response:
        assert self._client is not None
        origin = urlparse(url).netloc
        current = url
        for _ in range(_MAX_REDIRECTS + 1):
            same_origin = urlparse(current).netloc == origin
            request_headers = {"User-Agent": _USER_AGENT, **headers, **(self._auth_headers() if same_origin else {})}
            response = self._send_request("GET", current, request_headers, stream=stream)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location", "")
            response.close()
            target = urljoin(current, location)
            if urlparse(target).scheme != "https" and not (self.policy.allows_plain_http(self.ref) and urlparse(target).netloc == origin):
                raise RegistryError("Registry redirected to a non-HTTPS location")
            current = target
        raise RegistryError("Registry redirected too many times")

    def get(self, path: str, headers: dict[str, str] | None = None, *, stream: bool = False) -> httpx.Response:
        """GET ``path`` under the repository, answering one auth challenge."""
        url = f"{self.base_url}/{path}"
        response = self._send(url, headers or {}, stream=stream)
        if response.status_code == 401 and not self._token and not self._basic:
            response.close()
            if urlparse(str(response.request.url)).netloc != urlparse(url).netloc:
                raise RegistryError("A registry redirect target asked for credentials; they are only sent to the registry itself", 401)
            try:
                self._authenticate(response)
            except RegistryAuthError as exc:
                raise RegistryError(str(exc), 401) from exc
            response = self._send(url, headers or {}, stream=stream)
        return response

    def get_manifest(self, reference: str, *, missing_ok: bool = False) -> FetchedManifest | None:
        response = self.get(f"manifests/{reference}", {"Accept": MANIFEST_ACCEPT}, stream=True)
        if response.status_code != 200:
            response.close()
            if response.status_code == 404 and missing_ok:
                return None
            raise RegistryError(f"Manifest {reference} could not be fetched{self._status(response.status_code)}", response.status_code)
        raw = _read_bounded(response, MAX_MANIFEST_BYTES, "Manifest", self._consume_evidence)
        header_digest = response.headers.get("docker-content-digest")
        if header_digest and not _matches_digest(raw, header_digest):
            raise RegistryError("Manifest digest does not match the registry's Docker-Content-Digest")
        if ":" in reference and not _matches_digest(raw, reference):
            raise RegistryError("Manifest content does not match the requested digest")
        digest = reference if ":" in reference else header_digest or sha256_digest(raw)
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise RegistryError("Manifest is not valid JSON") from exc
        if not isinstance(document, dict):
            raise RegistryError("Manifest is not a JSON object")
        media_type = str(document.get("mediaType") or response.headers.get("content-type", "").split(";")[0].strip())
        return FetchedManifest(media_type=media_type, digest=digest, raw=raw, document=document)

    def fetch_blob(self, digest: str, sink: IO[bytes], max_bytes: int, on_chunk: Callable[[int], None] | None = None) -> int:
        """Stream blob ``digest`` into ``sink``; verify the digest; never exceed ``max_bytes``."""
        hasher = _digest_hasher(digest)
        written = 0
        response = self.get(f"blobs/{digest}", stream=True)
        try:
            if response.status_code != 200:
                raise RegistryError(f"Blob {digest[:19]} could not be fetched{self._status(response.status_code)}", response.status_code)
            for chunk in response.iter_bytes(_CHUNK):
                self._consume_evidence(len(chunk))
                written += len(chunk)
                if written > max_bytes:
                    raise RegistryError("Blob exceeds the size limit")
                hasher.update(chunk)
                sink.write(chunk)
                if on_chunk is not None:
                    on_chunk(written)
        except _TRANSPORT_ERRORS as exc:
            raise RegistryError(f"Blob download failed: {type(exc).__name__}") from exc
        finally:
            response.close()
        if f"{digest.split(':', 1)[0]}:{hasher.hexdigest()}" != digest:
            raise RegistryError("Blob content does not match its digest")
        return written

    def fetch_json_blob(self, digest: str, max_bytes: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
        buffer = io.BytesIO()
        self.fetch_blob(digest, buffer, max_bytes)
        try:
            document = json.loads(buffer.getvalue())
        except ValueError as exc:
            raise RegistryError("Blob is not valid JSON") from exc
        if not isinstance(document, dict):
            raise RegistryError("Blob is not a JSON object")
        return document

    def referrers(self, digest: str) -> list[dict[str, Any]] | None:
        """OCI 1.1 referrers for ``digest``; ``None`` when the registry has no referrers API."""
        response = self.get(f"referrers/{digest}", {"Accept": OCI_INDEX}, stream=True)
        if response.status_code != 200:
            response.close()
            if response.status_code in {404, 405, 400}:
                return None
            raise RegistryError(f"Referrers query failed{self._status(response.status_code)}", response.status_code)
        try:
            document = json.loads(_read_bounded(response, MAX_MANIFEST_BYTES, "Referrers index", self._consume_evidence))
        except ValueError:
            return None
        manifests = document.get("manifests") if isinstance(document, dict) else None
        return [m for m in manifests if isinstance(m, dict)] if isinstance(manifests, list) else []
