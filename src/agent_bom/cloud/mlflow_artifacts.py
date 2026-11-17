"""Bounded reads and fixed diagnostics for MLflow artifact plugins."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, TypeVar

from agent_bom.models import Package

from .collection_errors import CollectionError, CollectionStatus, collection_status, collection_warning

MAX_ARTIFACT_BYTES = 1024 * 1024
_T = TypeVar("_T")


def mlflow_warning(resource: str, exc: Exception) -> str:
    """Use structured SDK codes, never provider exception text."""
    code = getattr(exc, "error_code", None)
    statuses = {
        "PERMISSION_DENIED": CollectionStatus.DENIED,
        "UNAUTHENTICATED": CollectionStatus.DENIED,
        "CUSTOMER_UNAUTHORIZED": CollectionStatus.DENIED,
        "REQUEST_LIMIT_EXCEEDED": CollectionStatus.THROTTLED,
        "RESOURCE_EXHAUSTED": CollectionStatus.THROTTLED,
    }
    status = statuses.get(code, collection_status(exc)) if isinstance(code, str) else collection_status(exc)
    return collection_warning("mlflow", resource, CollectionError(status)).replace(": ", ": Could not collect inventory. ", 1)


def attempt(operation: Callable[[], _T], warnings: list[str], resource: str = "artifacts") -> _T | None:
    """Isolate SDK/plugin failures while retaining independent inventory."""
    try:
        return operation()
    except Exception as exc:  # broad-except: MLflow plugins expose arbitrary exceptions; emit fixed diagnostics only.
        warnings.append(mlflow_warning(resource, exc))
        return None


def _read_download(client: Any, run_id: str, artifact: Any) -> str:
    size = getattr(artifact, "file_size", None)
    if isinstance(size, int) and size > MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact exceeds metadata limit")
    with TemporaryDirectory(prefix="agent-bom-mlflow-") as destination:
        root = Path(destination).resolve()
        downloaded = Path(client.download_artifacts(run_id, artifact.path, dst_path=str(root)))
        if downloaded.is_symlink() or not downloaded.resolve().is_relative_to(root):
            raise ValueError("Artifact outside download directory")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(downloaded, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
                raise ValueError("Invalid artifact file")
            content = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(content) > MAX_ARTIFACT_BYTES:
            raise ValueError("Artifact exceeds content limit")
        return content.decode("utf-8")


def collect_run_packages(
    client: Any, run_id: str, warnings: list[str], parsers: dict[str, Callable[[str], list[Package]]]
) -> list[Package]:
    """Download only listed manifests; absent optional files are valid empty."""
    packages: list[Package] = []

    def collect() -> None:
        for directory in client.list_artifacts(run_id):
            if directory.path not in ("model", "models") or not directory.is_dir:
                continue
            children = attempt(lambda: client.list_artifacts(run_id, directory.path), warnings)
            if children is None:
                continue
            for artifact in children:
                parser = next((parse for name, parse in parsers.items() if artifact.path == f"{directory.path}/{name}"), None)
                if parser is None or artifact.is_dir:
                    continue
                result = attempt(lambda: parser(_read_download(client, run_id, artifact)), warnings)
                if result is not None:
                    packages.extend(result)

    attempt(collect, warnings)
    return packages
