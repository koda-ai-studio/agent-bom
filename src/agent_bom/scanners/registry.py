"""Scanner driver registry.

This registry makes scanner families discoverable before every implementation
is migrated behind one executor. It is the shared contract for CLI, API, UI,
and future plugin drivers.
"""

from __future__ import annotations

from typing import Any

from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
from agent_bom.scanners.base import (
    ScannerExecutionState,
    ScannerFailureMode,
    ScannerPhase,
    ScannerRegistration,
)
from agent_bom.scanners.builtin_registrations import builtin_scanner_registrations

_ENTRY_POINT_GROUP = "agent_bom.scanner_drivers"

_SCANNER_REGISTRY: dict[str, ScannerRegistration] = {}
_SCANNER_REGISTRY_WARNINGS: list[str] = []
_SCANNER_REGISTRY_LOADED = False


def _coerce_scanner_registration(value: Any, entry_point_name: str) -> ScannerRegistration:
    if isinstance(value, ScannerRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("scanner registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    phase = getattr(value, "phase", ScannerPhase.SCANNING)
    if not isinstance(phase, ScannerPhase):
        phase = ScannerPhase(str(phase))
    execution_state = getattr(value, "execution_state", ScannerExecutionState.ACTIVE)
    if not isinstance(execution_state, ScannerExecutionState):
        execution_state = ScannerExecutionState(str(execution_state))
    failure_mode = getattr(value, "failure_mode", ScannerFailureMode.WARN_AND_CONTINUE)
    if not isinstance(failure_mode, ScannerFailureMode):
        failure_mode = ScannerFailureMode(str(failure_mode))
    return ScannerRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=str(getattr(value, "source", "entry_point")),
        phase=phase,
        execution_state=execution_state,
        failure_mode=failure_mode,
        enabled_by_default=bool(getattr(value, "enabled_by_default", True)),
        run_attr=str(getattr(value, "run_attr", "run")),
        input_types=tuple(str(item) for item in getattr(value, "input_types", ())),
        output_types=tuple(str(item) for item in getattr(value, "output_types", ())),
        finding_types=tuple(str(item) for item in getattr(value, "finding_types", ())),
        skip_when=tuple(str(item) for item in getattr(value, "skip_when", ())),
        telemetry_keys=tuple(str(item) for item in getattr(value, "telemetry_keys", ())),
        standards=tuple(str(item) for item in getattr(value, "standards", ())),
        summary=str(getattr(value, "summary", "")),
    )


def register_scanner(registration: ScannerRegistration) -> None:
    """Register a scanner driver with capability and execution metadata."""

    if not registration.name:
        raise ValueError("scanner registration must declare a name")
    if registration.name in _SCANNER_REGISTRY:
        raise ValueError(f"duplicate scanner registration: {registration.name}")
    _SCANNER_REGISTRY[registration.name] = registration


def _ensure_scanner_registry_loaded() -> None:
    global _SCANNER_REGISTRY_LOADED
    if _SCANNER_REGISTRY_LOADED:
        return
    for registration in builtin_scanner_registrations():
        register_scanner(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_scanner_registration,
        warnings=_SCANNER_REGISTRY_WARNINGS,
    ):
        register_scanner(registration)
    _SCANNER_REGISTRY_LOADED = True


def list_registered_scanners(*, include_planned: bool = True) -> list[ScannerRegistration]:
    """Return registered scanner drivers sorted by name."""

    _ensure_scanner_registry_loaded()
    registrations = [_SCANNER_REGISTRY[name] for name in sorted(_SCANNER_REGISTRY)]
    if include_planned:
        return registrations
    return [registration for registration in registrations if registration.execution_state != ScannerExecutionState.PLANNED]


def get_scanner_registration(name: str) -> ScannerRegistration:
    """Return one scanner registration or raise ``KeyError``."""

    _ensure_scanner_registry_loaded()
    return _SCANNER_REGISTRY[name]


def scanner_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_scanner_registry_loaded()
    return list(_SCANNER_REGISTRY_WARNINGS)


def scanner_registry_summary() -> dict[str, object]:
    """Return a compact scanner registry summary for API/UI surfaces."""

    registrations = list_registered_scanners(include_planned=True)
    by_phase: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for registration in registrations:
        by_phase[registration.phase.value] = by_phase.get(registration.phase.value, 0) + 1
        by_state[registration.execution_state.value] = by_state.get(registration.execution_state.value, 0) + 1
    return {
        "total": len(registrations),
        "active": by_state.get(ScannerExecutionState.ACTIVE.value, 0),
        "passive": by_state.get(ScannerExecutionState.PASSIVE.value, 0),
        "planned": by_state.get(ScannerExecutionState.PLANNED.value, 0),
        "by_phase": by_phase,
        "by_state": by_state,
    }


def _reset_scanner_registry_for_tests() -> None:
    _SCANNER_REGISTRY.clear()
    _SCANNER_REGISTRY_WARNINGS.clear()
    global _SCANNER_REGISTRY_LOADED
    _SCANNER_REGISTRY_LOADED = False


__all__ = [
    "ScannerExecutionState",
    "ScannerFailureMode",
    "ScannerPhase",
    "ScannerRegistration",
    "builtin_scanner_registrations",
    "get_scanner_registration",
    "list_registered_scanners",
    "register_scanner",
    "scanner_registry_summary",
    "scanner_registry_warnings",
]
