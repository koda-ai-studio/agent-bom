"""TF-SEC-051: literal secrets in Terraform resource arguments."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource, line_number

_SECRET_ARGS = frozenset(
    {
        "password",
        "master_password",
        "admin_password",
        "root_password",
        "secret",
        "secret_key",
        "client_secret",
        "token",
        "access_token",
        "auth_token",
        "access_key",
        "private_key",
    }
)
_ARG_RE = re.compile(r'^[ \t]*([a-z][a-z0-9_]*)[ \t]*=[ \t]*"((?:[^"\\\n]|\\.)*)"', re.MULTILINE)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:|changeme|change[-_]?me|replace[-_]?me|todo|tbd|placeholder|example|dummy|redacted|"
    r"x+|\*+|<[^>]*>|your[-_].*|.*[-_]here)$"
)
_SSH_KEY_PREFIXES = ("ssh-rsa ", "ssh-ed25519 ", "-----BEGIN")
# Lambda environment variables are TF-SEC-046.
_SKIP_TYPES = frozenset({"aws_lambda_function"})


def _is_literal_secret(arg: str, value: str) -> bool:
    if "${" in value or _PLACEHOLDER_RE.match(value.strip()):
        return False
    # Inline SSH keys are TF-SEC-007.
    return not (arg == "private_key" and value.startswith(_SSH_KEY_PREFIXES))


def tf_sec_051(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-051: hardcoded password, secret, token or key in a resource argument."""
    if res.rtype in _SKIP_TYPES:
        return []
    findings: list[IaCFinding] = []
    for m in _ARG_RE.finditer(res.block):
        arg, value = m.group(1), m.group(2)
        if arg not in _SECRET_ARGS or not _is_literal_secret(arg, value):
            continue
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-051",
                severity="critical",
                title="Hardcoded secret in Terraform resource",
                message=(
                    f"Resource '{res.rname}' ({res.rtype}) sets '{arg}' to a literal value. "
                    "The value lands in version control and Terraform state. Pass it from a "
                    "sensitive variable, random_password, or a secrets manager reference."
                ),
                file_path=res.rel_path,
                line_number=line_number(res.content, res.block_offset + m.start(1)),
                category="terraform",
                compliance=["CIS-AWS-1.14", "NIST-IA-5", "NIST-SC-28"],
            )
        )
    return findings
