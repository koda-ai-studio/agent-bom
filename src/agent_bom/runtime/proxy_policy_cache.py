"""Signed gateway policy cache and policy retrieval."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from agent_bom.security import sanitize_text
from agent_bom.storage import state_home

if TYPE_CHECKING:
    from agent_bom.api.policy_store import GatewayPolicy
import logging

from agent_bom.core.settings import env_raw
from agent_bom.proxy_policy import resolve_rate_limit_threshold as resolve_rate_limit_threshold
from agent_bom.runtime.proxy_tracing import _control_plane_headers, proxy_span

logger = logging.getLogger("agent_bom.proxy")

_PROXY_POLICY_CACHE_SIGNING_ENV_VAR = "AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM"


def _proxy_policy_cache_signing_pem() -> str:
    """Resolve the cache-signing PEM file-first without retaining it in process env."""
    from agent_bom.api.secret_source import resolve_secret

    return resolve_secret(_PROXY_POLICY_CACHE_SIGNING_ENV_VAR).strip()


def _gateway_policy_cache_path() -> Path:
    configured = env_raw("AGENT_BOM_PROXY_POLICY_CACHE_PATH")
    if configured:
        return Path(configured).expanduser()
    return state_home.state_path("cache", "gateway-policies.json")


def _gateway_policy_cache_signature_path(cache_path: Path) -> Path:
    return cache_path.with_name(f"{cache_path.name}.sig")


class _GatewayPolicyCacheSigner:
    def __init__(self, pem: str) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        loaded = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"{_PROXY_POLICY_CACHE_SIGNING_ENV_VAR} is not an Ed25519 key")
        self._private_key = loaded
        public_bytes: bytes = loaded.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = hashlib.sha256(public_bytes).hexdigest()[:16]

    def sign(self, payload: bytes) -> str:
        return self._private_key.sign(payload).hex()

    def verify(self, payload: bytes, signature_hex: str) -> None:
        self._private_key.public_key().verify(bytes.fromhex(signature_hex), payload)


_gateway_policy_cache_signer: _GatewayPolicyCacheSigner | None = None


_gateway_policy_cache_signer_error: str | None = None


def _load_gateway_policy_cache_signer() -> _GatewayPolicyCacheSigner | None:
    global _gateway_policy_cache_signer, _gateway_policy_cache_signer_error
    if _gateway_policy_cache_signer is not None:
        return _gateway_policy_cache_signer
    pem = _proxy_policy_cache_signing_pem()
    if not pem:
        return None
    if _gateway_policy_cache_signer_error is not None:
        return None
    try:
        _gateway_policy_cache_signer = _GatewayPolicyCacheSigner(pem)
        logger.info(
            "proxy gateway policy cache signing enabled (key_id=%s)",
            _gateway_policy_cache_signer.key_id,
        )
        return _gateway_policy_cache_signer
    except Exception as exc:  # noqa: BLE001
        _gateway_policy_cache_signer_error = str(exc)
        logger.error("%s could not be parsed: %s", _PROXY_POLICY_CACHE_SIGNING_ENV_VAR, sanitize_text(exc))
        return None


def _reset_gateway_policy_cache_signer_for_tests() -> None:
    global _gateway_policy_cache_signer, _gateway_policy_cache_signer_error
    _gateway_policy_cache_signer = None
    _gateway_policy_cache_signer_error = None


def _canonicalize_gateway_policy_cache(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_cached_gateway_policies(
    cache_path: Path,
    max_age_seconds: int,
) -> tuple[list["GatewayPolicy"] | None, str | None]:
    from agent_bom.api.policy_store import GatewayPolicy

    try:
        payload = json.loads(cache_path.read_text())
    except FileNotFoundError:
        return None, None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Ignoring unreadable gateway policy cache %s: %s", cache_path, sanitize_text(exc))
        return None, None

    fetched_at = payload.get("fetched_at")
    if not isinstance(fetched_at, (int, float)):
        logger.warning("Ignoring gateway policy cache %s with missing fetched_at", cache_path)
        return None, None
    age_seconds = time.time() - float(fetched_at)
    if age_seconds > max(max_age_seconds, 0):
        logger.warning(
            "Ignoring stale gateway policy cache %s (age=%ss, max=%ss)",
            cache_path,
            int(age_seconds),
            max(max_age_seconds, 0),
        )
        return None, None

    signer = _load_gateway_policy_cache_signer()
    if _proxy_policy_cache_signing_pem():
        if signer is None:
            logger.warning("Ignoring gateway policy cache %s because cache signing is misconfigured", cache_path)
            return None, None
        signature_path = _gateway_policy_cache_signature_path(cache_path)
        try:
            signature_payload = json.loads(signature_path.read_text())
            signature_hex = str(signature_payload["signature_hex"])
            key_id = str(signature_payload["key_id"])
        except FileNotFoundError:
            logger.warning("Ignoring unsigned gateway policy cache %s because signing is required", cache_path)
            return None, None
        except (KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
            logger.warning("Ignoring unreadable gateway policy cache signature %s: %s", signature_path, sanitize_text(exc))
            return None, None
        if key_id != signer.key_id:
            logger.warning(
                "Ignoring gateway policy cache %s signed with unexpected key_id=%s (expected %s)",
                cache_path,
                key_id,
                signer.key_id,
            )
            return None, None
        try:
            signer.verify(_canonicalize_gateway_policy_cache(payload), signature_hex)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ignoring gateway policy cache %s with invalid signature: %s", cache_path, sanitize_text(exc))
            return None, None

    try:
        policies = [GatewayPolicy(**item) for item in payload.get("policies", [])]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Ignoring invalid gateway policy cache %s: %s", cache_path, sanitize_text(exc))
        return None, None
    return policies, payload.get("etag")


def _persist_gateway_policies_cache(
    cache_path: Path,
    policies: list["GatewayPolicy"],
    etag: str | None,
) -> None:
    payload = {
        "fetched_at": time.time(),
        "etag": etag,
        "policies": [policy.model_dump(mode="json") for policy in policies],
    }
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        signature_path = _gateway_policy_cache_signature_path(cache_path)
        signer = _load_gateway_policy_cache_signer()
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(cache_path.parent),
            prefix=f"{cache_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        temp_path.replace(cache_path)
        if signer is not None:
            signature_payload = {
                "algorithm": "Ed25519",
                "key_id": signer.key_id,
                "signature_hex": signer.sign(_canonicalize_gateway_policy_cache(payload)),
            }
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(signature_path.parent),
                prefix=f"{signature_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                json.dump(signature_payload, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
                temp_sig_path = Path(handle.name)
            temp_sig_path.replace(signature_path)
    except OSError as exc:
        logger.warning("Failed to persist gateway policy cache %s: %s", cache_path, sanitize_text(exc))


async def _fetch_enabled_gateway_policies(
    base_url: str,
    token: str | None,
    etag: str | None = None,
) -> tuple[list["GatewayPolicy"] | None, str | None]:
    from agent_bom.api.policy_store import GatewayPolicy
    from agent_bom.http_client import create_client

    url = base_url.rstrip("/") + "/v1/gateway/policies?enabled=true"
    span_cm = proxy_span("proxy.fetch_gateway_policies")
    with span_cm as span:
        if span is not None:
            span.set_attribute("agent_bom.proxy.control_plane_url", base_url.rstrip("/"))
            span.set_attribute("agent_bom.proxy.gateway_policy_etag_present", bool(etag))
        async with create_client(timeout=15.0) as client:
            response = await client.get(url, headers=_control_plane_headers(token, etag))
    if response.status_code == 304:
        return None, response.headers.get("ETag", etag)
    response.raise_for_status()
    payload = response.json()
    policies = [GatewayPolicy(**item) for item in payload.get("policies", [])]
    if span is not None:
        span.set_attribute("agent_bom.proxy.gateway_policy_count", len(policies))
    return policies, response.headers.get("ETag")


def _resolve_control_plane_rate_limit_threshold(policies: list["GatewayPolicy"], agent_name: str | None = None) -> int | None:
    from agent_bom.gateway import gateway_policy_to_proxy_format

    limits: list[int] = []
    for policy in policies:
        if not getattr(policy, "enabled", False):
            continue
        if agent_name and getattr(policy, "bound_agents", None) and agent_name not in getattr(policy, "bound_agents", []):
            continue
        proxy_fmt = gateway_policy_to_proxy_format(policy)
        limit = resolve_rate_limit_threshold(proxy_fmt)
        if limit is not None:
            limits.append(limit)
    return min(limits) if limits else None
