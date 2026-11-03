"""Write-time security policy validation without constraining legacy reads."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from agent_bom.api.suppression_policy import expiry_window_error
from agent_bom.core.iac_exceptions import IAC_RULE_ID, parse_resource_selector
from agent_bom.core.timestamps import parse_identity_timestamp
from agent_bom.runtime.policy_validation import validate_policy_rules


class PolicyRuleValidation(BaseModel):
    @field_validator("rules", check_fields=False)
    @classmethod
    def validate_patterns(cls, rules: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        return validate_policy_rules(rules)


class ExceptionExpiryValidation(BaseModel):
    @field_validator("expires_at", check_fields=False)
    @classmethod
    def validate_expiry(cls, value: str | None) -> str | None:
        # An omitted expiry can remain pending, but never authorizes suppression.
        if not value:
            return value
        expiry = parse_identity_timestamp(value, require_timezone=True)
        if expiry is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be a future timestamp with an explicit timezone")
        if error := expiry_window_error(value):
            raise ValueError(error)
        return value


class IaCExceptionScopeValidation(BaseModel):
    """An exception is either about a vulnerability or about an IaC rule, never both; IaC ones need a reason."""

    @model_validator(mode="after")
    def validate_scope(self) -> Any:
        rule = str(getattr(self, "iac_rule_id", "") or "").strip()
        iac_scoped = bool(rule or getattr(self, "iac_path", "") or getattr(self, "iac_resource", None))
        vuln_scoped = bool(str(getattr(self, "vuln_id", "")).strip() or str(getattr(self, "package_name", "")).strip())
        if not iac_scoped:
            if not (str(getattr(self, "vuln_id", "")).strip() and str(getattr(self, "package_name", "")).strip()):
                raise ValueError("vuln_id and package_name are required (or iac_rule_id for an IaC exception)")
            return self
        if vuln_scoped:
            raise ValueError("an exception covers a vulnerability or an IaC rule, not both")
        if not IAC_RULE_ID.match(rule):
            raise ValueError("iac_rule_id must be an IaC rule id such as K8S-001")
        if not str(getattr(self, "reason", "")).strip():
            raise ValueError("reason is required for an IaC exception")
        resource = getattr(self, "iac_resource", None)
        if resource:
            parse_resource_selector(resource)
        elif not str(getattr(self, "iac_path", "") or "").strip():
            raise ValueError("an IaC exception needs iac_path or iac_resource to scope it")
        return self
