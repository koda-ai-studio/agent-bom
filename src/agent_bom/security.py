"""Security validation and hardening utilities."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import logging
import os
import re
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from agent_bom.core.security_validation import (
    _CLOUD_METADATA_HOSTS as _CLOUD_METADATA_HOSTS,
)
from agent_bom.core.security_validation import (
    _IMAGE_REF_RE as _IMAGE_REF_RE,
)
from agent_bom.core.security_validation import (
    DANGEROUS_ENV_VARS as DANGEROUS_ENV_VARS,
)
from agent_bom.core.security_validation import (
    KNOWN_MCP_LAUNCHERS as KNOWN_MCP_LAUNCHERS,
)
from agent_bom.core.security_validation import (
    SHELL_METACHARACTERS as SHELL_METACHARACTERS,
)
from agent_bom.core.security_validation import (
    SecurityError as SecurityError,
)
from agent_bom.core.security_validation import (
    _is_non_public_ip as _is_non_public_ip,
)
from agent_bom.core.security_validation import (
    _unwrap_ip as _unwrap_ip,
)
from agent_bom.core.security_validation import (
    create_safe_subprocess_env as create_safe_subprocess_env,
)
from agent_bom.core.security_validation import (
    require_recognized_launcher as require_recognized_launcher,
)
from agent_bom.core.security_validation import (
    validate_arguments as validate_arguments,
)
from agent_bom.core.security_validation import (
    validate_environment as validate_environment,
)
from agent_bom.core.security_validation import (
    validate_file_size as validate_file_size,
)
from agent_bom.core.security_validation import (
    validate_image_ref as validate_image_ref,
)
from agent_bom.core.security_validation import (
    validate_json_file as validate_json_file,
)
from agent_bom.core.security_validation import (
    validate_package_name as validate_package_name,
)
from agent_bom.core.security_validation import (
    validate_path as validate_path,
)
from agent_bom.redaction.emails import _contains_email, mask_email
from agent_bom.redaction.entropy import shannon_entropy as _shannon_entropy
from agent_bom.redaction.env_values import container_has_secret
from agent_bom.redaction.field_policy import _REPORT_AUTH_MODES, _REPORT_COORDINATE_KEYS
from agent_bom.redaction.text_memo import memoized_text
from agent_bom.redaction.text_memo import sanitize_text_memo as sanitize_text_memo

logger = logging.getLogger(__name__)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Patterns for sensitive data (for redaction)
SENSITIVE_PATTERNS = [
    r"token",
    r"password",
    r"secret",
    r"api[_-]?key",
    r"auth",
    r"credential",
    r"bearer",
    r"jwt",
]
_SENSITIVE_KEY_RE = re.compile("|".join(f"(?:{pattern})" for pattern in SENSITIVE_PATTERNS))

# CR/LF/TAB become spaces; every other C0 control and DEL is dropped.
_LOG_LABEL_CONTROL_TABLE: dict[int, str | None] = {code_point: None for code_point in range(0x20)}
_LOG_LABEL_CONTROL_TABLE.update({0x09: " ", 0x0A: " ", 0x0D: " ", 0x7F: None})
_MULTI_SPACE_RE = re.compile(r" {2,}")


def sanitize_log_label(value: object, max_len: int = 500) -> str:
    """Return a single-line, ANSI-free label for logs and terminal output."""
    text = str(value)
    # ``isprintable`` is False for ESC, every C0 control and DEL, so a printable
    # string has no ANSI sequence or control character to remove.
    if not text.isprintable():
        text = ANSI_ESCAPE_RE.sub("", text).translate(_LOG_LABEL_CONTROL_TABLE)
    if "  " in text:
        text = _MULTI_SPACE_RE.sub(" ", text)
    return text.strip()[:max_len]


_VALUE_CREDENTIAL_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9_-])abom_[A-Za-z0-9_-]{43,}(?![A-Za-z0-9_-])"),  # Generated control-plane API keys
    re.compile(r"(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}", re.I),  # Stripe/service keys
    # Require a token boundary so ordinary identifiers containing ``risk-``
    # are not truncated from the embedded ``sk-`` onward.
    re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{20,}"),  # OpenAI/Anthropic-style keys
    re.compile(r"hf_[A-Za-z0-9]{20,}"),  # Hugging Face tokens
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),  # Google API keys
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}"),  # GitHub tokens
    re.compile(r"(?:glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}"),  # GitLab tokens
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),  # AWS access key IDs
    # Any PEM private-key label (`OPENSSH`, `ENCRYPTED`, `PGP … BLOCK` once leaked verbatim). Requiring
    # the literal `PRIVATE KEY` keeps public material (`-----BEGIN CERTIFICATE-----`, `PUBLIC KEY`) out.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"),  # Private keys
    # RFC 6750 bearer values; only the scheme's own vocabulary ("bearer token") is prose.
    re.compile(r"(?i:\bbearer[ \t]+)(?!(?i:tokens?|auth(?:entication|orization)?|schemes?|credentials?)(?![\w.~+/=-]))[\w.~+/-]+=*"),
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*)?"),  # JWTs, including short claims
    re.compile(r"xox[bpsar]-[A-Za-z0-9-]{10,}"),  # Slack tokens
]

# Keep credential-bearing connection URLs on a literal-prefixed fast path.
# Putting an unbounded scheme expression in ``_VALUE_CREDENTIAL_PATTERNS``
# makes regex search backtrack from every character of a non-URL model payload,
# turning a linear redaction pass into minutes of CPU time.
_CONNECTION_CREDENTIAL_RE = re.compile(r"://[^:\s/@]+:[^@\s/]+@")
_REFERENCE_SAFE_PREFIXES = (
    "arn:",
    "vault://",
    "keyvault://",
    "aws-secretsmanager://",
    "gcp-secretmanager://",
    "secret-manager://",
    "workload-identity/",
)
_REFERENCE_ENCODED_OCTET_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _contains_value_credential(value: str) -> bool:
    return any(pattern.search(value) for pattern in _VALUE_CREDENTIAL_PATTERNS) or (
        "://" in value and _CONNECTION_CREDENTIAL_RE.search(value) is not None
    )


def _decode_reference_component(value: str) -> str:
    """Decode bounded nested percent-encoding before classifying a reference."""
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def value_looks_like_secret(value: object) -> bool:
    """Return whether an external reference is actually credential material.

    Credential-reference APIs accept names, role ARNs, and secret-manager
    *paths*, never their values. Known credential patterns are authoritative;
    a bounded entropy fallback catches opaque pasted tokens while allowlisting
    the explicit reference shapes the product documents.
    """

    text = str(value or "").strip()
    if not text:
        return False
    if _contains_value_credential(text):
        return True
    lowered = text.lower()
    if "://" in text:
        try:
            parsed = urlsplit(text)
        except ValueError:
            return True
        # Query strings and fragments frequently carry bearer material. A
        # credential reference has no reason to preserve either.
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return True
        # A reference-shaped URL can still carry an opaque credential in its
        # host or path (for example ``vault://team/<pasted token>``). Apply the
        # same bounded entropy classifier to individual decoded components;
        # checking the whole URL would skip entropy because it contains ``://``.
        components = [_decode_reference_component(parsed.hostname or "")]
        decoded_path = _decode_reference_component(parsed.path)
        components.extend(part for part in decoded_path.split("/") if part)
        # Decoding is intentionally capped. If a syntactically valid encoded
        # octet remains after that budget, accepting it would let another
        # consumer reveal a credential through one more decode pass. Reject
        # the ambiguous reference instead of making decoding unbounded.
        if any(_REFERENCE_ENCODED_OCTET_RE.search(component) for component in components):
            return True
        return any(_looks_sensitive_value(component) for component in components)
    if lowered.startswith(_REFERENCE_SAFE_PREFIXES):
        # Non-URL reference forms (ARNs and workload-identity names) receive
        # the same segment-level check instead of bypassing entropy wholesale.
        decoded_reference = _decode_reference_component(text)
        if _REFERENCE_ENCODED_OCTET_RE.search(decoded_reference):
            return True
        components = [part for part in re.split(r"[/:]", decoded_reference) if part]
        return any(_looks_sensitive_value(component) for component in components)
    return _looks_sensitive_value(text)


# Base64 alphabet (standard + URL-safe)
_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+=*$")

# Minimum length to bother trying base64 decode (encodes ≥20 bytes)
_B64_MIN_LEN = 28

# Shannon entropy threshold — secrets typically score >3.8 bits/char;
# readable English scores ~4.0 but with spaces; env var values without
# spaces that score >4.5 over a long string are almost certainly secrets.
# Shorter strings (24-39 chars) require higher entropy to reduce false positives.
_HIGH_ENTROPY_THRESHOLD = 4.5
_HIGH_ENTROPY_MIN_LEN = 24
_HIGH_ENTROPY_SHORT_THRESHOLD = 5.0  # stricter for shorter strings (24-39 chars)

_STRUCTURED_EDGE_ID_RE = re.compile(r"^[^\s>]+->[A-Za-z][A-Za-z0-9_.:-]*->[^\s>]+$")
# Directory-traversal coverage receipt (``traversal.py``): a root digest and a reason code.
_COVERAGE_RECEIPT_RE = re.compile(r"^filesystem-discovery:[0-9a-f]{16}:[a-z_]{1,64}$")


def _is_structured_coordinate(key_text: str, value: str) -> bool:
    """A deterministic identifier whose punctuation and length would trip the entropy detector.

    Deliberately narrow: a coverage receipt in ``release``, or an ``id`` /
    ``canonical_id`` in the canonical ``source->relation->target`` edge shape
    whose endpoints match no credential pattern.
    """
    if key_text == "release":
        return _COVERAGE_RECEIPT_RE.fullmatch(value) is not None
    edge_parts = value.split("->")
    return (
        key_text in {"id", "canonical_id"}
        and _STRUCTURED_EDGE_ID_RE.fullmatch(value) is not None
        and len(edge_parts) == 3
        and not _looks_sensitive_value(edge_parts[0])
        and not _looks_sensitive_value(edge_parts[2])
    )


def _is_obfuscated_credential(value: str) -> bool:
    """Return True if value looks like a base64-encoded or high-entropy secret.

    Two detection strategies:
    1. Base64 decode: if the value decodes to valid UTF-8 text that itself
       matches a key name or value credential pattern, flag it.
    2. High-entropy: strings (≥24 chars) with no whitespace and high Shannon
       entropy are extremely likely to be opaque secrets (keys, tokens,
       passwords).  Short strings (24-39 chars) require entropy >5.0 to reduce
       false positives; longer strings (≥40 chars) use the standard 4.5
       threshold.  Pure random bytes score ~6.0; base64-encoded secrets
       score ~5.8; UUIDs score ~3.8.
    """
    stripped = value.strip()

    # Strategy 1: base64 decode and re-check
    if len(stripped) >= _B64_MIN_LEN and _B64_RE.match(stripped):
        try:
            decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="strict")
            decoded_lower = decoded.lower()
            # Decoded text contains a sensitive keyword
            if _SENSITIVE_KEY_RE.search(decoded_lower):
                return True
            # Decoded text matches a known credential value pattern
            if _contains_value_credential(decoded):
                return True
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass  # Not valid base64 — fall through to entropy check

    # Strategy 2: high Shannon entropy on a compact, non-URL string
    # Short strings (24-39 chars) use a stricter threshold to avoid false positives
    str_len = len(stripped)
    if str_len >= _HIGH_ENTROPY_MIN_LEN and " " not in stripped and "://" not in stripped:
        entropy = _shannon_entropy(stripped)
        threshold = _HIGH_ENTROPY_SHORT_THRESHOLD if str_len < 40 else _HIGH_ENTROPY_THRESHOLD
        if entropy > threshold:
            return True

    return False


def env_key_is_credential(key: str) -> bool:
    """Whether an environment-variable *name* denotes a credential.

    Environment variable names are classified product-wide by
    ``constants.is_credential_key`` — it backs ``MCPServer.credential_names``
    and therefore every surface that reports an exposed credential.  Redaction
    has to cover at least those names, or a report can list a variable as an
    exposed credential in one field while publishing its value in another.
    ``SENSITIVE_PATTERNS`` adds forms that are not env-var-shaped (``api-key``,
    ``jwt``); it stays regex-based and is not widened, because
    :func:`_key_looks_sensitive` applies it to arbitrary payload keys where
    over-matching collapses distinct graph nodes.
    """
    from agent_bom.constants import is_credential_key

    return _SENSITIVE_KEY_RE.search(key.lower()) is not None or is_credential_key(key)


def sanitize_env_vars(env: dict[str, Any]) -> dict[str, str]:
    """
    Sanitize environment variables by redacting sensitive values.

    Checks both key names (via :func:`env_key_is_credential`) and values (via
    _VALUE_CREDENTIAL_PATTERNS) to catch hardcoded credentials in
    custom-named variables.

    Args:
        env: Dictionary of environment variables

    Returns:
        Dictionary with sensitive values redacted
    """
    sanitized = {}
    for key, value in env.items():
        if env_key_is_credential(key):
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict | list | tuple | set):
            secret = container_has_secret(value, _looks_sensitive_value, env_key_is_credential)
            sanitized[key] = "***REDACTED***" if secret else str(value)
        else:
            # Plaintext credential patterns, then base64 / high-entropy values.
            sanitized[key] = "***REDACTED***" if _looks_sensitive_value(str(value)) else str(value)

    return sanitized


# Field names whose values are email addresses and must always be masked in
# operational records (audit metadata, connector identity fields, evidence).
_EMAIL_KEYS = {
    "email",
    "email_address",
    "user_email",
    "actor_email",
    "owner_email",
    "contact_email",
    "notify_email",
    "reporter_email",
    "assignee_email",
    "mail",
}


def _key_looks_like_email(key: object) -> bool:
    key_text = str(key or "").strip().lower().replace("-", "_")
    return key_text in _EMAIL_KEYS or key_text.endswith("_email")


def sanitize_url(value: str | None) -> str | None:
    """Strip credentials, query strings, and fragments from display/export URLs."""
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-url>"
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    try:
        port = parsed.port
    except ValueError:
        # A non-numeric or out-of-range port only raises on access; free text
        # such as ``http://host:PORT/`` must not abort a whole report export.
        return "<redacted-url>"
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def redact_secret_url(value: str | None) -> str:
    """Redact a secret-bearing URL down to scheme+host plus a short fingerprint.

    Unlike :func:`sanitize_url`, this also drops the *path*: for incoming
    webhooks (Slack-style) the URL path segments carry the secret token, so the
    URL itself is credential material. The returned form keeps just enough
    (scheme, host, and a stable 8-char fingerprint of the full URL) for an
    operator to correlate failures without exposing the secret in logs or an
    audit export.
    """
    if not value:
        return "<none>"
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    try:
        parsed = urlsplit(value)
    except ValueError:
        return f"<redacted-url>#{fingerprint}"
    if not parsed.scheme or not parsed.netloc:
        return f"<redacted-url>#{fingerprint}"
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}/…#{fingerprint}"


# `KEY = "value"` in the shapes free text actually uses: bare, quoted, spaced,
# JSON (`"api_key": "…"`), YAML (`api_key: …`). The previous scanner took a run
# of non-space characters and `rpartition`-ed it, so it found the key only in
# the single unquoted `KEY=value` form — and on a base64 value it split at the
# `=` *padding*, leaving an empty candidate. Everything else printed verbatim.
#
# Widening happens on the key side only. `[^\s"',;<>]` is the value: a plain run,
# never entropy-tested on its own, because free text is full of legitimate
# high-entropy tokens (digests, ARNs, request ids) and a redactor that eats them
# is one people switch off.
#
# A bare `:` with nothing around it is *not* an assignment — it is the delimiter
# in the graph's own structured identifiers
# (`credential_ref:credential_ref:credential_reference:redacted`) and in ARNs and
# digests. Reading one as `key: value` redacts the tail of a node id, and the
# graph exporter then collapses distinct nodes into one phantom. So a colon has
# to look like an assignment: quoted as in JSON, or followed by whitespace as
# YAML requires. `=` needs no such proof; structured ids do not use it.
_TEXT_KEY_VALUE_RE = re.compile(
    r"""(?P<key>[A-Za-z][A-Za-z0-9_.\-]{1,63})   # key name
        (?P<sep>["']?[ \t]*=[ \t]*               # `KEY=v`, `KEY = v`, `"KEY"=v`
             |["'][ \t]*:[ \t]*                  # `"key": v`
             |[ \t]*:[ \t]*(?=["'])              # `key:"v"`
             |[ \t]*:[ \t]+)                     # `key: v`
        (?P<quote>["']?)                         # optional opening quote on the value
        (?P<value>[^\s"',;<>]+)                  # the value
    """,
    re.VERBOSE,
)

# Values that are plainly not credential material. The key name cannot tell a
# secret from a count or a placeholder, and redacting these makes logs
# unreadable without making anything safer.
_NON_SECRET_VALUE_RE = re.compile(
    r"^(?:\d+(?:\.\d+)*|true|false|yes|on|off|none|null|nil|unset|unknown|missing|empty|n/?a|redacted|\*+redacted\*+|\*+|-+)$",
    re.I,
)

# An env-var *name* is an identifier, not a secret. Reports carry
# `credential_names=OPENAI_API_KEY` as evidence; redacting the name loses the
# finding and protects nothing — only the value of a credential is sensitive.
_CREDENTIAL_IDENTIFIER_VALUE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")

# Below this a value is an enum or a flag, not authentication material.
_MIN_SECRET_VALUE_LEN = 4

# A key that *describes* a credential rather than holding one: `secret_type`,
# `token_type`, `secret_name`. Its value is a category or a reference name, and
# redacting it makes findings unreadable while protecting nothing.
_CREDENTIAL_METADATA_KEY_WORDS = frozenset({"type", "kind", "name", "label", "category", "class", "title", "pattern", "rule", "format"})

# `Hardcoded credential: Stripe Key` is a finding title, not `key: value`. A bare
# `: ` followed by a run of capitalised words is prose; anything with digits or
# symbols, or written with `=` or quotes, is still treated as an assignment.
_TITLE_CASE_WORD_RE = re.compile(r"^[A-Z][A-Za-z]+$")
_TITLE_CASE_CONTINUATION_RE = re.compile(r"[ \t]{1,8}[A-Z][A-Za-z]{0,64}\b")


_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def sanitize_text(value: object, max_len: int = 1000) -> str:
    """Redact credential-shaped substrings, credential-bearing URLs, and emails in text."""
    return memoized_text(value, max_len, _sanitize_text)


def _sanitize_text(value: object, max_len: int = 1000) -> str:
    text = sanitize_log_label(value, max_len=max_len)
    # A substitution is skipped only when its pattern cannot match: URLs need
    # ``://``, a keyed value needs ``=`` or ``:``, an email needs ``@``.
    if "://" in text:
        text = _HTTP_URL_RE.sub(lambda match: str(sanitize_url(match.group(0)) or ""), text)
    for pattern in _VALUE_CREDENTIAL_PATTERNS:
        text = pattern.sub("<redacted>", text)
    if "://" in text:
        text = _CONNECTION_CREDENTIAL_RE.sub("://<redacted>@", text)
    # The pattern list carries AWS access key *ids* but nothing for the 40-char
    # secret access key, so the harmless half was redacted while the dangerous
    # half was printed verbatim. Anything the shapes above miss is caught by the
    # variable *name* it is written under, using the product-wide predicate.
    if "=" in text or ":" in text:
        text = _TEXT_KEY_VALUE_RE.sub(_redact_keyed_value, text)
    # Email is sensitive PII — mask any addresses left in free text.
    if "@" in text:
        text = mask_email(text)
    return text[:max_len]


def _redact_keyed_value(match: re.Match[str]) -> str:
    """Redact the value of a `key: value` pair when the *key* names a credential.

    Requiring the key is what keeps this usable. The entropy fallback that
    `sanitize_env_vars` applies is safe there, because a high-entropy env var
    value is almost certainly a secret — but free text is full of high-entropy
    tokens that are not: content hashes, ARNs, request ids, digests. Applying it
    to bare tokens redacted a `hash_ref` and a GuardDuty ARN in the runtime
    taxonomy. So the two paths share the *predicate for names* and deliberately
    do not share the bare-value heuristic.

    A named credential's value is redacted on the strength of the name alone —
    a 64-char hex API key scores below every value threshold there is, and
    waiting for the value to look secret is what let it through.
    """
    value = match.group("value")
    if not _keyed_value_is_secret(match):
        return match.group(0)
    prefix = f"{match.group('key')}{match.group('sep')}{match.group('quote')}"
    # A connection URL is evidence: the host says which system was reached. Keep
    # that and drop the credential, rather than blanking the whole line.
    if "://" in value:
        return f"{prefix}{sanitize_url(value) or '<redacted>'}"
    return f"{prefix}<redacted>"


def _keyed_value_is_secret(match: re.Match[str]) -> bool:
    key = match.group("key")
    if not env_key_is_credential(key) or not _is_credential_material(match.group("value")):
        return False
    return not (_is_credential_metadata_key(key) or _is_title_prose(match))


def _is_credential_metadata_key(key: str) -> bool:
    tokens = re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).casefold())
    return any(token in _CREDENTIAL_METADATA_KEY_WORDS for token in tokens)


def _is_title_prose(match: re.Match[str]) -> bool:
    if match.group("quote") or "=" in match.group("sep") or not match.group("sep").strip().startswith(":"):
        return False
    if match.group("sep").lstrip().startswith(("'", '"')) or not _TITLE_CASE_WORD_RE.match(match.group("value")):
        return False
    return bool(_TITLE_CASE_CONTINUATION_RE.match(match.string, match.end()))


def _is_credential_material(value: str) -> bool:
    """Whether a value under a credential-named key could be the credential (prose punctuation aside)."""
    value = value.rstrip(".,;:!?)")
    if len(value) < _MIN_SECRET_VALUE_LEN or _NON_SECRET_VALUE_RE.match(value):
        return False
    return not (_CREDENTIAL_IDENTIFIER_VALUE_RE.match(value) and env_key_is_credential(value))


def text_requires_redaction(value: object) -> bool:
    """Return whether canonical free-text redaction would alter sensitive data.

    Renderers use this exact predicate for their fast path. It intentionally
    shares the central patterns and credential-key classifier so a duplicated
    heuristic cannot drift into a redaction bypass.
    """
    text = str(value)
    if "http://" in text.lower() or "https://" in text.lower():
        return True
    if _contains_email(text) or _contains_value_credential(text):
        return True
    # The keyed-value grammar cannot match without an assignment delimiter.
    # Avoid starting its bounded-key regex at every character of large plain
    # model/output strings.
    if "=" not in text and ":" not in text:
        return False
    return any(_keyed_value_is_secret(match) for match in _TEXT_KEY_VALUE_RE.finditer(text))


def _looks_sensitive_value(value: str) -> bool:
    """Whether ``sanitize_env_vars`` would redact ``value`` under a neutral name.

    The placeholder name ``ARG`` is not credential-named, so only the value
    checks apply; calling them directly skips re-classifying a constant name.
    """
    text = str(value)
    return _contains_value_credential(text) or _is_obfuscated_credential(text)


def sanitize_command_args(args: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact secret-bearing command arguments while preserving launch shape."""
    sanitized: list[str] = []
    redact_next = False
    for raw_arg in args:
        arg = str(raw_arg)
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue

        if "=" in arg:
            key, _sep, raw_value = arg.partition("=")
            if any(re.search(pattern, key.lower()) for pattern in SENSITIVE_PATTERNS):
                sanitized.append(f"{key}=<redacted>")
                continue
            if "://" in raw_value:
                sanitized.append(f"{key}={sanitize_url(raw_value)}")
                continue
            if _looks_sensitive_value(raw_value):
                sanitized.append(f"{key}=<redacted>")
                continue

        if "://" in arg:
            sanitized.append(str(sanitize_url(arg) or ""))
            continue

        if _looks_sensitive_value(arg):
            sanitized.append("<redacted>")
            continue

        if arg.startswith("-") and any(re.search(pattern, arg.lower()) for pattern in SENSITIVE_PATTERNS):
            sanitized.append(arg)
            redact_next = True
            continue

        sanitized.append(arg)
    return sanitized


def sanitize_launch_command(command: object, args: list[Any] | tuple[Any, ...] | None = None, *, max_args: int | None = None) -> str:
    """Return a safe command label for display/export surfaces."""
    safe_command = sanitize_text(command, max_len=200)
    raw_args = list(args or [])
    if max_args is not None:
        raw_args = raw_args[:max_args]
    safe_args = sanitize_command_args(raw_args)
    return " ".join([part for part in [safe_command, *safe_args] if part]).strip()


def sanitize_security_warnings(values: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact warning text before persistence or UI/API export."""
    return [sanitize_text(value) for value in values if str(value or "").strip()]


def _key_looks_sensitive(key: object) -> bool:
    return _SENSITIVE_KEY_RE.search(str(key).lower()) is not None


# Fields whose string members are credential *env-var names* — identifiers such
# as ``OPENAI_API_KEY`` — not secret values.  The key text ("credential…")
# matches SENSITIVE_PATTERNS, so without this exception every name would redact
# to ``***REDACTED***``; downstream the graph exporter mints node IDs from these
# labels and set-dedups them, collapsing distinct credentials into one phantom
# node and inventing cross-agent ``reaches_tool``/``exposes_cred`` edges.  Only
# the VALUE of a credential is sensitive, and values are never carried here.
_CREDENTIAL_IDENTIFIER_KEYS = frozenset(
    {
        "credential_env_vars",
        "credential_env_var",
        "credential_names",
        "credential_refs",
        "credentials_exposed",
        "exposed_credentials",
        "exposed_credential_names",
    }
)


def _key_is_credential_identifier(key: object) -> bool:
    return str(key or "").strip().lower().replace("-", "_") in _CREDENTIAL_IDENTIFIER_KEYS


def _key_looks_like_url(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in {"url", "uri", "endpoint", "webhook"} or key_text.endswith(("_url", "_uri", "_endpoint", "_webhook"))


def _key_looks_like_path(key: object) -> bool:
    key_text = str(key).lower()
    path_terms = ("path", "file", "dir", "directory", "cwd", "workspace", "config_path", "source_path")
    return any(term in key_text for term in path_terms)


def _looks_like_path_value(value: str) -> bool:
    if not value or "://" in value:
        return False
    return value.startswith("/") or value.startswith("~/") or bool(re.match(r"^[A-Za-z]:[\\/]", value))


_CLOUD_IDENTITY_KEYS = {
    "account_id",
    "arn",
    "cloud_principal",
    "endpoint_id",
    "location",
    "principal_arn",
    "project_id",
    "region",
    "resource_group",
    "resource_id",
    "resource_name",
    "service",
    "subscription_id",
    "tenant_id",
}


def _key_looks_like_cloud_identity(key: object) -> bool:
    key_text = str(key or "").strip().lower().replace("-", "_")
    return key_text in _CLOUD_IDENTITY_KEYS or key_text.endswith("_arn") or key_text.endswith("_resource_id")


def sanitize_path_label(value: object) -> str:
    """Return a non-revealing label for local filesystem paths."""
    text = sanitize_log_label(value, max_len=1000)
    if re.fullmatch(r"<path:[^<>]+>", text):
        return text
    basename = re.split(r"[\\/]+", text.rstrip("/\\"))[-1] if text else ""
    if "(" not in basename:
        basename = basename.rstrip(")")
    basename = sanitize_text(basename or "path", max_len=80)
    if not basename or _key_looks_sensitive(basename) or _looks_sensitive_value(basename):
        basename = "path"
    return f"<path:{basename}>"


# ``\s`` on a str pattern is the same predicate as ``str.isspace``.
_WHITESPACE_RE = re.compile(r"\s")
_WHITESPACE_OR_C0_RE = re.compile(r"[\s\x00-\x1f]")


def _safe_report_coordinate(value: str) -> bool:
    """Check coordinate components, not the entropy of combined namespaces.

    Preserve coordinates while checking credential patterns and component entropy;
    a field named node_id is not permission to export an embedded token.
    """
    if ":" not in value or "://" in value or _looks_like_path_value(value) or _WHITESPACE_OR_C0_RE.search(value):
        return False
    if text_requires_redaction(value):
        return False
    components = [_decode_reference_component(part) for part in re.split(r"[/:@|?&#><]", value) if part]
    return bool(components) and all(
        not _REFERENCE_ENCODED_OCTET_RE.search(part) and not _looks_sensitive_value(part) for part in components
    )


def _sanitize_sensitive_string(value: str, *, key: object | None, max_str_len: int) -> object:
    """Redact one string while preserving the caller's field-sensitive rules."""
    key_text = str(key or "").strip().lower().replace("-", "_")
    if key_text == "auth_mode" and value in _REPORT_AUTH_MODES:
        return value
    if key_text in _REPORT_COORDINATE_KEYS and _safe_report_coordinate(value):
        return sanitize_text(value, max_len=max_str_len)
    # A credential env-var NAME is an identifier, not a secret value.  Keep
    # it intact so distinct credentials stay distinct graph nodes; still
    # redact defensively if the string itself looks like a leaked secret.
    if _key_is_credential_identifier(key) and not _looks_sensitive_value(value):
        return sanitize_text(value, max_len=max_str_len)
    if key is not None and _key_looks_sensitive(key):
        return "***REDACTED***"
    if key is not None and _key_looks_like_email(key):
        return mask_email(value)
    if key is not None and _key_looks_like_url(key):
        return sanitize_url(value)
    if key is not None and _key_looks_like_cloud_identity(key):
        if _looks_sensitive_value(value):
            return "***REDACTED***"
        return sanitize_text(value, max_len=max_str_len)
    # Graph edge ids and coverage receipts are coordinates, not opaque credentials.
    if _is_structured_coordinate(key_text, value):
        return sanitize_text(value, max_len=max_str_len)
    if "://" in value:
        return sanitize_text(value, max_len=max_str_len)
    if key is not None and _key_looks_like_path(key) and _looks_like_path_value(value):
        return sanitize_path_label(value)
    if _looks_like_path_value(value):
        return sanitize_path_label(value)
    if not text_requires_redaction(value) and (len(value.strip()) < _HIGH_ENTROPY_MIN_LEN or _WHITESPACE_RE.search(value)):
        return sanitize_log_label(value, max_len=max_str_len)
    if _looks_sensitive_value(value):
        return "***REDACTED***"
    return sanitize_text(value, max_len=max_str_len)


def sanitize_sensitive_payload(
    value: object,
    *,
    key: object | None = None,
    max_str_len: int = 1000,
    depth: int = 0,
    _string_cache: dict[tuple[str | None, str, int], object] | None = None,
    _key_cache: dict[str, str] | None = None,
) -> object:
    """Recursively redact sensitive runtime/audit payloads before persistence/export.

    Caches are bounded and live for a single traversal, so repeated package
    fields are redacted once without retaining sensitive strings globally.
    """
    from agent_bom.redaction.payload import redact_payload

    string_cache = {} if _string_cache is None else _string_cache
    return redact_payload(value, key, max_str_len, depth, string_cache, {} if _key_cache is None else _key_cache)


def validate_url(url: str, *, allowed_schemes: tuple[str, ...] = ("https",), allow_private: bool = False) -> None:
    """
    Validate a URL for safety, including DNS rebinding protection.

    Resolves hostnames to IPs and validates the resolved addresses against
    private/loopback/reserved/link-local ranges to prevent DNS rebinding
    attacks where a hostname initially resolves to a public IP but later
    resolves to an internal one.

    Args:
        url: URL to validate

    Raises:
        SecurityError: If URL is invalid or uses insecure protocol
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL '{url}': {e}")

    allow_private = allow_private or os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    http_private_override = allow_private and parsed.scheme == "http" and allowed_schemes == ("https",)

    if parsed.scheme not in allowed_schemes and not http_private_override:
        if allowed_schemes == ("https",):
            raise SecurityError(f"URL must use HTTPS; got: {parsed.scheme}")
        expected = ", ".join(f"{scheme}://" for scheme in allowed_schemes)
        raise SecurityError(f"URL must use one of {expected}; got: {parsed.scheme}")

    # Validate domain is not localhost or internal IP
    hostname = parsed.hostname or ""
    if not hostname:
        raise SecurityError("URL must include a hostname")
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # nosec B104 - checking FOR these values to reject them, not binding to them
        if not allow_private:
            raise SecurityError(f"Cannot connect to localhost/internal IPs: {hostname}")
        logger.warning("Private egress URL allowed by operator override")
        return

    # Block cloud metadata endpoints (AWS/GCP/Azure/Alibaba)
    if hostname in _CLOUD_METADATA_HOSTS:
        raise SecurityError(f"Cannot connect to cloud metadata endpoint: {hostname}")

    # Check if hostname is already an IP literal
    try:
        addr = _unwrap_ip(ipaddress.ip_address(hostname))
        if str(addr) in _CLOUD_METADATA_HOSTS:
            raise SecurityError(f"Cannot connect to cloud metadata endpoint: {hostname}")
        if _is_non_public_ip(addr):
            if not allow_private:
                raise SecurityError(f"Cannot connect to private/reserved IP: {hostname}")
            logger.warning("Private egress URL allowed by operator override")
            return
    except ValueError:
        pass  # hostname is a domain name — resolve below

    # DNS rebinding protection: resolve hostname and validate all resolved IPs
    from agent_bom.core.egress_resolution import resolve_egress_hostname

    addrinfos = resolve_egress_hostname(hostname, SecurityError)

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        resolved_ip = sockaddr[0]
        try:
            addr = _unwrap_ip(ipaddress.ip_address(resolved_ip))
            if str(addr) in _CLOUD_METADATA_HOSTS:
                raise SecurityError(f"Hostname '{hostname}' resolves to cloud metadata endpoint: {resolved_ip}")
            if _is_non_public_ip(addr):
                if not allow_private:
                    raise SecurityError(f"Hostname '{hostname}' resolves to private/reserved IP: {resolved_ip}")
                logger.warning("Private egress URL allowed by operator override")
                return
        except ValueError:
            continue

    if http_private_override:
        raise SecurityError("HTTP URLs are only allowed for private egress targets when AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS is enabled")

    # Static log — no user-controlled values to prevent both cleartext
    # credential logging and log injection (CodeQL py/clear-text-logging,
    # py/log-injection).
    logger.debug("URL validated successfully")


def validate_mcp_server_config(server_config: dict) -> None:
    """
    Validate an MCP server configuration for hygiene issues before launch.

    Checks launcher recognition, argument shape, and dangerous environment
    variables. These are misconfiguration guards, not isolation — a config
    that passes still runs with full host privileges unless container
    isolation (``agent_bom.proxy_sandbox``, ``--isolate``) is enabled.

    Args:
        server_config: MCP server configuration dictionary

    Raises:
        SecurityError: If configuration fails a hygiene check
    """
    # Check the launcher (remote/URL-based servers don't require a local command)
    command = server_config.get("command", "")
    has_url = bool(server_config.get("url") or server_config.get("uri"))
    if not has_url:
        require_recognized_launcher(command)

    # Validate arguments
    args = server_config.get("args", [])
    if not isinstance(args, list):
        raise SecurityError("Server args must be a list")
    validate_arguments(args)

    # Validate environment variables
    env = server_config.get("env", {})
    if not isinstance(env, dict):
        raise SecurityError("Server env must be a dictionary")
    validate_environment(env)

    logger.info("MCP server config validated: %s", sanitize_text(command or server_config.get("url", "unknown")))


def sanitize_error(exc: Exception | str, generic: bool = False, *, max_length: int = 200) -> str:
    """Redact credentials, PII, paths and URLs from API error messages.

    ``generic=True`` returns a fixed non-diagnostic message. ``max_length``
    bounds the response; callers with authored remediation text may raise
    this cap without disabling redaction.
    """
    if generic:
        return "An internal error occurred. Please contact support."

    msg = str(exc)
    # Strip URLs first (before path regex matches the path portion)
    msg = re.sub(r"https?://[^\s\"']+", "<url>", msg)
    # Apply the same recognizable credential rules used for logs before the
    # path scrubber can split a bearer token containing a slash.
    msg = sanitize_text(msg, max_len=len(msg))
    # Strip inline credential assignments commonly included in SDK error strings.
    msg = re.sub(
        r"(?i)\b(token|secret|password|passwd|api[_-]?key|access[_-]?key|session[_-]?token)\s*=\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=<redacted>",
        msg,
    )
    # Strip absolute file paths
    msg = re.sub(r"(/[^\s:\"']+)+", "<path>", msg)
    return msg[:max_length] if len(msg) > max_length else msg


# Export all validation functions
__all__ = [
    "SecurityError",
    "require_recognized_launcher",
    "validate_arguments",
    "validate_environment",
    "validate_path",
    "sanitize_env_vars",
    "sanitize_command_args",
    "sanitize_launch_command",
    "sanitize_security_warnings",
    "sanitize_sensitive_payload",
    "sanitize_path_label",
    "sanitize_text",
    "sanitize_url",
    "mask_email",
    "validate_file_size",
    "validate_json_file",
    "validate_url",
    "validate_package_name",
    "create_safe_subprocess_env",
    "validate_mcp_server_config",
    "validate_image_ref",
    "sanitize_error",
]
