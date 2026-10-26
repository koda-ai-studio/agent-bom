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
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO, Any
from urllib.parse import urlencode, urljoin, urlparse

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
from agent_bom.oci_registry.reference import ImageReference

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_REDIRECTS = 5
_CHUNK = 1024 * 1024
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_USER_AGENT = "agent-bom-registry-client"


class RegistryError(Exception):
    """A registry request failed; ``status`` is the HTTP status when there was one."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


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


@dataclass
class RegistryClient:
    """Client for one repository on one registry."""

    ref: ImageReference
    credential_resolver: Callable[[], RegistryCredential] = field(default=lambda: ANONYMOUS)
    transport: httpx.BaseTransport | None = None
    _token: str | None = None
    _basic: str | None = None
    _credential: RegistryCredential | None = None
    _client: httpx.Client | None = None

    def __post_init__(self) -> None:
        check_offline()
        transport = self.transport if self.transport is not None else _default_transport()
        self._client = httpx.Client(timeout=_TIMEOUT, transport=transport, follow_redirects=False, verify=True)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def credential_source(self) -> str:
        return self._credential.source if self._credential is not None else "anonymous"

    @property
    def base_url(self) -> str:
        scheme = "http" if self.ref.allows_plain_http else "https"
        return f"{scheme}://{self.ref.registry}/v2/{self.ref.repository}"

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
        realm = validate_realm(params.get("realm", ""), self.ref)
        query = {k: v for k, v in params.items() if k in {"service", "scope"} and v}
        query.setdefault("scope", f"repository:{self.ref.repository}:pull")
        credential = self._credential or ANONYMOUS
        assert self._client is not None
        if credential.identity_token:
            form = {"grant_type": "refresh_token", "refresh_token": credential.identity_token, "client_id": "agent-bom", **query}
            response = self._client.post(realm, data=form, headers={"User-Agent": _USER_AGENT})
        else:
            headers = {"User-Agent": _USER_AGENT}
            if (basic := basic_header(credential)) is not None:
                headers["Authorization"] = basic
            response = self._client.get(f"{realm}?{urlencode(query)}", headers=headers)
        if response.status_code != 200:
            raise RegistryError(f"Registry token request was refused (HTTP {response.status_code})", response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise RegistryError("Registry token response was not JSON") from exc
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RegistryError("Registry token response carried no token")
        return token

    def _send(self, url: str, headers: dict[str, str], *, stream: bool) -> httpx.Response:
        assert self._client is not None
        origin = urlparse(url).netloc
        current = url
        for _ in range(_MAX_REDIRECTS + 1):
            same_origin = urlparse(current).netloc == origin
            request_headers = {"User-Agent": _USER_AGENT, **headers, **(self._auth_headers() if same_origin else {})}
            request = self._client.build_request("GET", current, headers=request_headers)
            try:
                response = self._client.send(request, stream=stream)
            except httpx.HTTPError as exc:
                raise RegistryError(f"Registry request failed: {type(exc).__name__}") from exc
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location", "")
            response.close()
            target = urljoin(current, location)
            if urlparse(target).scheme != "https" and not (self.ref.allows_plain_http and urlparse(target).netloc == origin):
                raise RegistryError("Registry redirected to a non-HTTPS location")
            current = target
        raise RegistryError("Registry redirected too many times")

    def get(self, path: str, headers: dict[str, str] | None = None, *, stream: bool = False) -> httpx.Response:
        """GET ``path`` under the repository, answering one auth challenge."""
        url = f"{self.base_url}/{path}"
        response = self._send(url, headers or {}, stream=stream)
        if response.status_code == 401 and not self._token and not self._basic:
            response.close()
            try:
                self._authenticate(response)
            except RegistryAuthError as exc:
                raise RegistryError(str(exc), 401) from exc
            response = self._send(url, headers or {}, stream=stream)
        return response

    def get_manifest(self, reference: str, *, missing_ok: bool = False) -> FetchedManifest | None:
        response = self.get(f"manifests/{reference}", {"Accept": MANIFEST_ACCEPT})
        if response.status_code == 404 and missing_ok:
            return None
        if response.status_code != 200:
            raise RegistryError(f"Manifest {reference} could not be fetched (HTTP {response.status_code})", response.status_code)
        raw = response.content
        if len(raw) > MAX_MANIFEST_BYTES:
            raise RegistryError("Manifest exceeds the size limit")
        digest = sha256_digest(raw)
        header_digest = response.headers.get("docker-content-digest")
        if header_digest and header_digest.startswith("sha256:") and header_digest != digest:
            raise RegistryError("Manifest digest does not match the registry's Docker-Content-Digest")
        if reference.startswith("sha256:") and reference != digest:
            raise RegistryError("Manifest content does not match the requested digest")
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
                raise RegistryError(f"Blob {digest[:19]} could not be fetched (HTTP {response.status_code})", response.status_code)
            for chunk in response.iter_bytes(_CHUNK):
                written += len(chunk)
                if written > max_bytes:
                    raise RegistryError("Blob exceeds the size limit")
                hasher.update(chunk)
                sink.write(chunk)
                if on_chunk is not None:
                    on_chunk(written)
        except httpx.HTTPError as exc:
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
        response = self.get(f"referrers/{digest}", {"Accept": OCI_INDEX})
        if response.status_code in {404, 405, 400}:
            return None
        if response.status_code != 200:
            raise RegistryError(f"Referrers query failed (HTTP {response.status_code})", response.status_code)
        try:
            document = response.json()
        except ValueError:
            return None
        manifests = document.get("manifests") if isinstance(document, dict) else None
        return [m for m in manifests if isinstance(m, dict)] if isinstance(manifests, list) else []
