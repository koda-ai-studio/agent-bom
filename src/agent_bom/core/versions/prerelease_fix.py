"""Whether an advisory's only published fix is a pre-release build."""

from __future__ import annotations

from agent_bom.core.versions.validation import is_prerelease_version


def fix_is_prerelease(fixed_version: str | None, ecosystem: str | None) -> bool:
    """True when ``fixed_version`` is an upstream pre-release for ``ecosystem``.

    Distro package versions are builds the distro already shipped, so they are
    never pre-releases (``is_prerelease_version`` handles that family).
    """
    if not isinstance(fixed_version, str) or not fixed_version.strip():
        return False
    return is_prerelease_version(fixed_version.strip(), (ecosystem or "").strip())


def upgrade_remediation(package_name: str, fixed_version: str, ecosystem: str | None, flagged: bool = False) -> str:
    """Remediation line for a forward fix; a pre-release-only fix says so."""
    if flagged or fix_is_prerelease(fixed_version, ecosystem):
        return f"Upgrade {package_name} to {fixed_version} (pre-release; no stable fix published yet)."
    return f"Upgrade {package_name} to {fixed_version}."
