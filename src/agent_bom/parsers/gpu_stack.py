"""NVIDIA GPU stack components: kernel driver, CUDA toolkit and Container Toolkit.

Distro package databases miss most of this stack: drivers are often installed
from NVIDIA's ``.run`` installer, the CUDA toolkit from a tarball, and the
running kernel module can differ from the package on disk until a reboot. The
versions are read passively from files NVIDIA documents:

- ``/proc/driver/nvidia/version``: "Lists the installed driver revision" of the
  loaded kernel module (NVIDIA Linux driver README, chapter "Using the /proc
  File System Interface",
  https://download.nvidia.com/XFree86/Linux-x86_64/550.127.05/README/procinterface.html).
- ``libcuda.so.<driver version>``: the driver's user-space library is named
  after the driver release. ``/usr/local/cuda*/compat`` copies belong to the
  forward-compatibility package and are not the host driver, so they are skipped.
- ``/usr/local/cuda*/version.json`` (``cuda.version``) and, for toolkits up to
  11.0, ``version.txt`` ("contain the version and build number of the installed
  toolkit", CUDA 11.1 release notes).
- ``nvidia-container-toolkit``, ``nvidia-container-toolkit-base``,
  ``libnvidia-container-tools`` and ``libnvidia-container1`` are installed at
  one shared version (Container Toolkit install guide,
  https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html);
  ``libnvidia-container.so.<version>`` covers unpackaged installs.

Components carry the NVD CPE dictionary identity (``nvidia:gpu_display_driver``
with ``target_sw=linux``, ``nvidia:cuda_toolkit``,
``nvidia:nvidia_container_toolkit``). When a distro package already
inventories the same release, that package carries the CPE instead of a second
component, so one install is counted once.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bom.models import Package
from agent_bom.parsers.image_runtimes import _upstream_version
from agent_bom.parsers.rootfs_files import list_names, read_bounded

_DISTRO_ECOSYSTEMS = frozenset({"deb", "rpm", "apk"})
_MAX_VERSION_FILE = 65_536
_LIB_DIRS = ("usr/lib/x86_64-linux-gnu", "usr/lib/aarch64-linux-gnu", "usr/lib64", "usr/lib", "usr/local/nvidia/lib64")
_LIB_DIR_RE = r"(?:usr/lib/(?:x86_64|aarch64)-linux-gnu|usr/lib64|usr/lib|usr/local/nvidia/lib64)"
PROC_VERSION_PATH = "proc/driver/nvidia/version"
_PROC_RE = re.compile(
    rb"^NVRM version: NVIDIA UNIX (?:[A-Za-z0-9_]+ )?(?:Open )?Kernel Module(?: for [A-Za-z0-9_]+)?[ \t]+(\S+)", re.MULTILINE
)
_CUDA_FILE_RE = re.compile(r"usr/local/cuda(?:-[0-9]{1,2}(?:\.[0-9]{1,2})?)?/version\.(json|txt)")
_LIBCUDA_RE = re.compile(_LIB_DIR_RE + r"/libcuda\.so\.([0-9][0-9.]*)")
_LIBNVC_RE = re.compile(_LIB_DIR_RE + r"/libnvidia-container\.so\.([0-9][0-9.]*)")


@dataclass(frozen=True)
class GpuProduct:
    name: str
    cpe_product: str
    target_sw: str
    version_re: re.Pattern[str]
    anchors: tuple[re.Pattern[str], ...]

    def cpe(self, version: str) -> str | None:
        if not self.version_re.fullmatch(version):
            return None
        return f"cpe:2.3:a:nvidia:{self.cpe_product}:{version}:*:*:*:*:{self.target_sw}:*:*"

    def purl(self, version: str) -> str:
        return f"pkg:generic/nvidia/{self.name}@{version}"


def _anchors(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)


DRIVER = GpuProduct(
    "nvidia-gpu-display-driver",
    "gpu_display_driver",
    "linux",
    re.compile(r"[0-9]{2,4}\.[0-9]{1,4}(?:\.[0-9]{1,4})?"),
    _anchors(
        r"nvidia-driver(?:-[0-9]+)?(?:-server)?(?:-open)?",
        r"cuda-drivers(?:-[0-9]+)?",
        r"nvidia-open(?:-[0-9]+)?",
        r"nvidia-headless(?:-no-dkms)?-[0-9]+(?:-server)?(?:-open)?",
        r"kmod-nvidia(?:-[a-z0-9]+)*",
        r"libnvidia-compute-[0-9]+(?:-server)?",
    ),
)
CUDA_TOOLKIT = GpuProduct(
    "nvidia-cuda-toolkit",
    "cuda_toolkit",
    "*",
    re.compile(r"[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,4})?"),
    _anchors(r"cuda-toolkit(?:-[0-9]+-[0-9]+)?", r"nvidia-cuda-toolkit"),
)
CONTAINER_TOOLKIT = GpuProduct(
    "nvidia-container-toolkit",
    "nvidia_container_toolkit",
    "*",
    re.compile(r"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}"),
    _anchors(r"nvidia-container-toolkit", r"nvidia-container-toolkit-base", r"libnvidia-container1", r"libnvidia-container-tools"),
)
GPU_PRODUCTS: tuple[GpuProduct, ...] = (DRIVER, CUDA_TOOLKIT, CONTAINER_TOOLKIT)
_PRODUCT_BY_NAME = {product.name: product for product in GPU_PRODUCTS}

_PROVENANCE = {
    "loaded_kernel_module": ("loaded-kernel-module", "high"),
    "version_file": ("version-file", "high"),
    "library_filename": ("library-filename", "medium"),
}


@dataclass(frozen=True)
class GpuObservation:
    product: GpuProduct
    version: str
    evidence_type: str
    path: str


def parse_proc_version(content: bytes) -> str | None:
    match = _PROC_RE.search(content)
    if match is None:
        return None
    version = match[1].decode("ascii", "replace")
    return version if DRIVER.version_re.fullmatch(version) else None


def parse_cuda_version_file(rel: str, content: bytes) -> str | None:
    if rel.endswith(".json"):
        try:
            data = json.loads(content)
        except (ValueError, UnicodeDecodeError):
            return None
        cuda = data.get("cuda") if isinstance(data, dict) else None
        version = cuda.get("version") if isinstance(cuda, dict) else None
    else:
        match = re.match(rb"CUDA Version ([0-9][0-9.]{0,15})\s*$", content.strip())
        version = match[1].decode("ascii") if match else None
    return version if isinstance(version, str) and CUDA_TOOLKIT.version_re.fullmatch(version) else None


def observe_path(rel: str, read: Callable[[str], bytes | None]) -> GpuObservation | None:
    """One GPU stack observation from a root-relative path, reading its content only when needed."""
    rel = rel.removeprefix("./")
    if rel == PROC_VERSION_PATH:
        content = read(rel)
        version = parse_proc_version(content) if content is not None else None
        return GpuObservation(DRIVER, version, "loaded_kernel_module", rel) if version else None
    if _CUDA_FILE_RE.fullmatch(rel):
        content = read(rel)
        version = parse_cuda_version_file(rel, content) if content is not None else None
        return GpuObservation(CUDA_TOOLKIT, version, "version_file", rel) if version else None
    for pattern, product in ((_LIBCUDA_RE, DRIVER), (_LIBNVC_RE, CONTAINER_TOOLKIT)):
        match = pattern.fullmatch(rel)
        if match and product.version_re.fullmatch(match[1]):
            return GpuObservation(product, match[1], "library_filename", rel)
    return None


def candidate_paths(root: Path) -> list[str]:
    """Root-relative paths worth observing on a mounted host or snapshot."""
    paths = [PROC_VERSION_PATH]
    for name in list_names(root, "usr/local"):
        if re.fullmatch(r"cuda(?:-[0-9]{1,2}(?:\.[0-9]{1,2})?)?", name):
            paths.extend((f"usr/local/{name}/version.json", f"usr/local/{name}/version.txt"))
    for lib_dir in _LIB_DIRS:
        names = list_names(root, lib_dir)
        paths.extend(f"{lib_dir}/{name}" for name in names if name.startswith(("libcuda.so.", "libnvidia-container.so.")))
    return paths


def _observation_package(observations: list[GpuObservation]) -> Package:
    first = observations[0]
    return Package(
        name=first.product.name,
        version=first.version,
        ecosystem="generic",
        purl=first.product.purl(first.version),
        is_direct=False,
        resolved_from_registry=False,
        version_evidence=[{"type": obs.evidence_type, "source_file": obs.path} for obs in observations],
    )


def detect_gpu_stack(root: Path) -> list[Package]:
    """GPU stack observations under a mounted root, before distro de-duplication."""
    observations = [
        obs for rel in candidate_paths(root) if (obs := observe_path(rel, lambda path: read_bounded(root, path, _MAX_VERSION_FILE)))
    ]
    loaded = {obs.version for obs in observations if obs.evidence_type == "loaded_kernel_module"}
    grouped: dict[tuple[str, str], list[GpuObservation]] = {}
    for obs in observations:
        if obs.product is DRIVER and loaded and obs.version not in loaded:
            continue  # a stale user-space library does not override the loaded module
        grouped.setdefault((obs.product.name, obs.version), []).append(obs)
    return [_observation_package(group) for group in grouped.values()]


def _provenance(package: Package, source_type: str) -> dict[str, Any]:
    kinds = [str(item.get("type")) for item in package.version_evidence]
    best = next((kind for kind in _PROVENANCE if kind in kinds), "library_filename")
    source, confidence = _PROVENANCE[best]
    paths = [str(item["source_file"]) for item in package.version_evidence if item.get("source_file")]
    return {"source_type": source_type, "source": source, "observed_via": paths, "confidence": confidence}


def _anchor(product: GpuProduct, distro: Iterable[Package]) -> Package | None:
    candidates = list(distro)
    for pattern in product.anchors:
        for package in candidates:
            if pattern.fullmatch(package.name.lower()) and product.cpe(_upstream_version(package.version)):
                return package
    return None


def gpu_product(package: Package) -> GpuProduct | None:
    return _PRODUCT_BY_NAME.get(package.name) if package.ecosystem == "generic" else None


def finalize_gpu_stack(packages: list[Package], source_type: str = "filesystem_scan") -> list[Package]:
    """Attach NVIDIA CPE identities; fold observations into a distro package of the same release."""
    distro = [pkg for pkg in packages if pkg.ecosystem in _DISTRO_ECOSYSTEMS]
    anchored: dict[tuple[str, str], Package] = {}
    for product in GPU_PRODUCTS:
        anchor = _anchor(product, distro)
        if anchor is not None:
            version = _upstream_version(anchor.version)
            anchor.cpe = product.cpe(version)
            anchored[(product.name, version)] = anchor
    kept: list[Package] = []
    for package in packages:
        observed = gpu_product(package)
        if observed is None:
            kept.append(package)
            continue
        anchor = anchored.get((observed.name, package.version))
        if anchor is not None:
            anchor.version_evidence = [*anchor.version_evidence, *package.version_evidence]
            continue
        cpe = observed.cpe(package.version)
        if cpe is None:
            continue
        package.cpe = cpe
        package.purl = observed.purl(package.version)
        package.discovery_provenance = _provenance(package, source_type)
        kept.append(package)
    return kept


def extract_gpu_stack_layer(scan: Any, read_member: Callable[[Any, str], Any]) -> None:
    """Record GPU stack observations from one image layer (``oci_parser._LayerScan``)."""
    for path in sorted(name for name in scan.names if "cuda" in name or "nvidia" in name):
        if scan.is_deleted(path):
            continue

        def _read(_rel: str, member: str = path) -> bytes | None:
            stream = read_member(scan.layer_tf, member)
            content = stream.read(_MAX_VERSION_FILE + 1) if stream is not None else None
            return content if content is not None and len(content) <= _MAX_VERSION_FILE else None

        obs = observe_path(path, _read)
        if obs is None:
            continue
        previous = scan.packages_by_key.get((obs.product.name, "generic"))
        evidence = previous.version_evidence if previous is not None and previous.version == obs.version else []
        scan.add(path, obs.product.name, obs.version, "generic", obs.product.purl(obs.version))
        package = scan.packages_by_key[(obs.product.name, "generic")]
        package.version_evidence = [item for item in evidence if item.get("source_file") != obs.path] + [
            {"type": obs.evidence_type, "source_file": obs.path}
        ]
