"""Which VEX assertions may suppress a finding, and how the overlay is recorded."""

from __future__ import annotations

from typing import Any

from agent_bom.core.suppression_score import mark_blast_radius_suppressed

VEX_SOURCE_OPERATOR = "operator"
VEX_SOURCE_DISCOVERED = "discovered"
_SUPPRESSING_VEX_STATUSES = frozenset({"not_affected", "fixed"})


def is_vex_suppressed(vuln) -> bool:
    """True only for an operator-supplied ``not_affected``/``fixed`` assertion.

    VEX discovered inside scanned artifacts is attacker-influenced supply-chain
    content, so it stays evidence and never lowers totals or gates.
    """
    return getattr(vuln, "vex_source", None) == VEX_SOURCE_OPERATOR and getattr(vuln, "vex_status", None) in _SUPPRESSING_VEX_STATUSES


def active_blast_radii(blast_radii):
    """Return findings active after approved-exception and operator-VEX overlays."""

    return [br for br in blast_radii if not br.suppressed and not is_vex_suppressed(br.vulnerability)]


def _normalize_purl(value: str) -> str:
    return value.split("?", 1)[0].split("#", 1)[0].strip().lower()


def product_matches(products: list[str], package: Any) -> bool:
    """A statement without products applies to every package carrying the vulnerability."""
    if not products or package is None:
        return True
    purl = _normalize_purl(str(getattr(package, "purl", "") or ""))
    name = str(getattr(package, "name", "") or "").lower()
    version = str(getattr(package, "version", "") or "").lower()
    for raw in products:
        product = _normalize_purl(str(raw))
        if not product:
            continue
        if purl and (product == purl or ("@" not in product.rsplit("/", 1)[-1] and purl.split("@", 1)[0] == product)):
            return True
        if product in {f"{name}@{version}", name}:
            return True
        if product.startswith("pkg:"):
            tail = product.rsplit("/", 1)[-1]
            p_name, _, p_version = tail.partition("@")
            if p_name == name and (not p_version or p_version == version):
                return True
    return False


def vex_suppression_reason(vuln) -> str:
    detail = getattr(vuln, "vex_justification", None) or getattr(vuln, "vex_status", None) or "not_affected"
    statement = getattr(vuln, "vex_statement_id", None)
    return f"vex: {detail}" + (f" ({statement})" if statement else "")


def apply_vex_suppression(br) -> bool:
    """Overlay operator-VEX suppression on a blast radius, preserving evidence."""
    if br.suppressed or not is_vex_suppressed(br.vulnerability):
        return False
    mark_blast_radius_suppressed(br, suppression_id=None, state="vex", reason=vex_suppression_reason(br.vulnerability))
    return True
