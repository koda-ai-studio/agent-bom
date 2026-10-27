"""An in-memory OCI distribution registry served through ``httpx.MockTransport``.

Implements just enough of the distribution spec for read-only pulls: the
``/v2/`` token challenge (anonymous or Basic-authenticated token endpoint, or
plain Basic auth), manifests by tag/digest, blobs (optionally redirected to a
"CDN" host), and the OCI 1.1 referrers API. Every request is recorded so tests
can assert on what was sent.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

import httpx

from tests._oci_image_builder import OCI_INDEX, BuiltImage, digest_of

REGISTRY = "registry.example.test"
AUTH_HOST = "auth.example.test"
CDN_HOST = "cdn.example.test"


@dataclass
class FakeRegistry:
    host: str = REGISTRY
    auth: str = "anonymous"  # anonymous | token-basic | basic
    username: str = "reader"
    password: str = "reader-pass"
    redirect_blobs: bool = False
    referrers_api: bool = True
    manifests: dict[tuple[str, str], tuple[bytes, str]] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)
    referrers: dict[tuple[str, str], list[dict]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    corrupt_blob: str | None = None

    def push_image(self, repository: str, image: BuiltImage, *tags: str) -> None:
        self.blobs.update(image.blobs)
        self.add_manifest(repository, image.manifest_bytes, image.manifest["mediaType"], *tags)

    def add_manifest(self, repository: str, raw: bytes, media_type: str, *tags: str) -> str:
        digest = digest_of(raw)
        for key in (digest, *tags):
            self.manifests[(repository, key)] = (raw, media_type)
        return digest

    def add_blob(self, data: bytes) -> str:
        digest = digest_of(data)
        self.blobs[digest] = data
        return digest

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _expected_basic(self) -> str:
        return "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode()).decode()

    def _authorized(self, request: httpx.Request) -> bool:
        header = request.headers.get("authorization", "")
        if self.auth == "anonymous":
            return header == "Bearer anon-token"
        if self.auth == "token-basic":
            return header == "Bearer user-token"
        return header == self._expected_basic()

    def _challenge(self, repository: str) -> httpx.Response:
        if self.auth == "basic":
            return httpx.Response(401, headers={"WWW-Authenticate": f'Basic realm="{self.host}"'})
        realm = f"https://{AUTH_HOST}/token"
        scope = f"repository:{repository}:pull"
        value = f'Bearer realm="{realm}",service="{self.host}",scope="{scope}"'
        return httpx.Response(401, headers={"WWW-Authenticate": value}, json={"errors": [{"code": "UNAUTHORIZED"}]})

    def _token(self, request: httpx.Request) -> httpx.Response:
        query = parse_qs(urlparse(str(request.url)).query)
        if query.get("service") != [self.host] or not query.get("scope"):
            return httpx.Response(400)
        if self.auth == "token-basic":
            if request.headers.get("authorization") != self._expected_basic():
                return httpx.Response(401)
            return httpx.Response(200, json={"token": "user-token"})
        return httpx.Response(200, json={"token": "anon-token"})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = urlparse(str(request.url))
        if url.netloc == AUTH_HOST:
            return self._token(request)
        if url.netloc == CDN_HOST:
            if "authorization" in request.headers:
                return httpx.Response(400, text="credentials leaked to CDN")
            digest = url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, content=self.blobs[digest])
        if url.netloc != self.host or not url.path.startswith("/v2/"):
            return httpx.Response(404)
        path = url.path[len("/v2/") :]
        for marker in ("/manifests/", "/blobs/", "/referrers/"):
            if marker in path:
                repository, ref = path.split(marker, 1)
                break
        else:
            return httpx.Response(404)
        if not self._authorized(request):
            return self._challenge(repository)
        if marker == "/manifests/":
            entry = self.manifests.get((repository, ref))
            if entry is None:
                return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})
            raw, media_type = entry
            return httpx.Response(200, content=raw, headers={"Content-Type": media_type, "Docker-Content-Digest": digest_of(raw)})
        if marker == "/referrers/":
            if not self.referrers_api:
                return httpx.Response(404)
            body = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": self.referrers.get((repository, ref), [])}
            return httpx.Response(200, content=json.dumps(body).encode(), headers={"Content-Type": OCI_INDEX})
        if ref not in self.blobs:
            return httpx.Response(404)
        if self.redirect_blobs:
            return httpx.Response(307, headers={"Location": f"https://{CDN_HOST}/blobs/{ref}"})
        data = self.blobs[ref]
        if self.corrupt_blob == ref:
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
        return httpx.Response(200, content=data)
