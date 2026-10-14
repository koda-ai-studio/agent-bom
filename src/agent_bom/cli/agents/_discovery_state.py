"""Shared state threaded through the local-discovery stages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
from typing import Any

from agent_bom.cli.agents._context import ScanContext


@dataclass
class DiscoveryRun:
    """One ``run_local_discovery`` call: its inputs plus what earlier stages produced.

    ``images``, ``filesystem_paths`` and ``iac_paths`` are rebound by the k8s and
    auto-detect stages, and later stages read the rebound values.
    """

    ctx: ScanContext
    con: Any
    discover: Callable[..., Any]
    extra: dict[str, Any]
    project: Any
    config_dir: Any
    inventory: Any
    skill_only: bool
    no_discover: bool
    follow_symlinks: bool
    dynamic_discovery: bool
    dynamic_max_depth: int
    include_processes: bool
    include_containers: bool
    k8s_mcp: bool
    k8s_namespace: str
    k8s_all_namespaces: bool
    k8s_mcp_context: Any
    no_skill: bool
    skill_paths: tuple
    sbom_file: Any
    sbom_name: Any
    external_scan_path: Any
    k8s: bool
    namespace: str
    all_namespaces: bool
    k8s_context: Any
    registry_user: Any
    registry_pass: Any
    image_platform: Any
    images: tuple
    image_tars: tuple
    filesystem_paths: tuple
    code_paths: tuple
    sast_config: str
    offline: bool
    tf_dirs: tuple
    gha_path: Any
    agent_projects: tuple
    scan_prompts: bool
    browser_extensions: bool
    jupyter_dirs: tuple
    iac_paths: tuple
    verbose: bool
    os_packages: bool
    workstation_sweep: bool
    extra_projects: tuple = ()
    extra_config_dirs: tuple = ()
    extra_inventories: tuple = ()
    extra_sbom_files: tuple = ()
    extra_sbom_names: tuple = ()
    extra_external_scan_paths: tuple = ()
    preloaded_inventory: dict[str, Any] | None = None
    preloaded_extra_inventories: list[dict[str, Any]] = field(default_factory=list)
    inventory_label: str | None = None
    skill_result: Any = None
    skill_audit: Any = None

    @staticmethod
    def _all(primary: Any, extra: tuple) -> tuple:
        return ((primary,) if primary else ()) + tuple(extra)

    @property
    def all_projects(self) -> tuple:
        return self._all(self.project, self.extra_projects)

    @property
    def all_config_dirs(self) -> tuple:
        return self._all(self.config_dir, self.extra_config_dirs)

    @property
    def all_external_scan_paths(self) -> tuple:
        return self._all(self.external_scan_path, self.extra_external_scan_paths)

    @property
    def sbom_inputs(self) -> list[tuple[Any, Any]]:
        """``(sbom_file, sbom_name)`` pairs; names pair positionally when given."""
        files = self._all(self.sbom_file, self.extra_sbom_files)
        names = self._all(self.sbom_name, self.extra_sbom_names)
        return [(path, names[index] if index < len(names) else None) for index, path in enumerate(files)]

    @classmethod
    def from_params(cls, params: dict[str, Any], discover: Callable[..., Any]) -> DiscoveryRun:
        """Build the run from ``run_local_discovery``'s bound parameters."""
        names = {f.name for f in fields(cls) if f.init} - {"con", "discover", "extra"}
        values = {name: params[name] for name in names if name in params}
        return cls(con=params["ctx"].con, discover=discover, extra=params["kwargs"], **values)


DiscoveryStage = Callable[[DiscoveryRun], None]
