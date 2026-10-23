"""NVIDIA driver, CUDA toolkit and Container Toolkit inventory from passive file reads."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.oci_parser import parse_oci_tarball
from agent_bom.parsers.gpu_stack import finalize_gpu_stack

DRIVER_CPE = "cpe:2.3:a:nvidia:gpu_display_driver:550.54.15:*:*:*:*:linux:*:*"
CUDA_CPE = "cpe:2.3:a:nvidia:cuda_toolkit:12.4.1:*:*:*:*:*:*:*"
CTK_CPE = "cpe:2.3:a:nvidia:nvidia_container_toolkit:1.16.1:*:*:*:*:*:*:*"

PROC_VERSION = (
    "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.15  Tue Mar  5 22:23:56 UTC 2024\n"
    "GCC version:  gcc version 12.2.0 (Debian 12.2.0-14)\n"
)
OPEN_PROC_VERSION = (
    "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  560.35.03  Release Build  (dvs-builder@U16-I3-B03-4-3)\n"
    "GCC version:  gcc version 13.2.0 (Ubuntu 13.2.0-23ubuntu4)\n"
)
CUDA_VERSION_JSON = json.dumps(
    {"cuda": {"name": "CUDA SDK", "version": "12.4.1"}, "cuda_cudart": {"name": "CUDA Runtime (cudart)", "version": "12.4.127"}}
)


def _stanza(name: str, version: str) -> str:
    return f"Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\n\n"


CTK_DPKG = "".join(
    _stanza(name, "1.16.1-1")
    for name in ("nvidia-container-toolkit", "nvidia-container-toolkit-base", "libnvidia-container1", "libnvidia-container-tools")
)


def _write(root: Path, rel: str, content: str | bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)


def _gpu_rootfs(root: Path, *, dpkg: str = CTK_DPKG, proc: str | None = PROC_VERSION) -> Path:
    if proc is not None:
        _write(root, "proc/driver/nvidia/version", proc)
    _write(root, "usr/lib/x86_64-linux-gnu/libcuda.so.550.54.15", b"\x7fELF")
    (root / "usr/lib/x86_64-linux-gnu/libcuda.so.1").symlink_to("libcuda.so.550.54.15")
    _write(root, "usr/local/cuda-12.4/version.json", CUDA_VERSION_JSON)
    (root / "usr/local/cuda").symlink_to("cuda-12.4")
    _write(root, "var/lib/dpkg/status", dpkg)
    return root


def _nvidia(packages: list[Package]) -> dict[str, Package]:
    out = {pkg.cpe.split(":")[4]: pkg for pkg in packages if (pkg.cpe or "").startswith("cpe:2.3:a:nvidia:")}
    assert len(out) == sum(1 for pkg in packages if (pkg.cpe or "").startswith("cpe:2.3:a:nvidia:")), "one component per product"
    return out


def test_live_host_rootfs_inventories_each_gpu_component_once(tmp_path: Path) -> None:
    packages = scan_disk_path_native(_gpu_rootfs(tmp_path))
    components = _nvidia(packages)

    assert set(components) == {"gpu_display_driver", "cuda_toolkit", "nvidia_container_toolkit"}
    driver = components["gpu_display_driver"]
    assert (driver.name, driver.version, driver.ecosystem, driver.cpe) == ("nvidia-gpu-display-driver", "550.54.15", "generic", DRIVER_CPE)
    assert driver.purl == "pkg:generic/nvidia/nvidia-gpu-display-driver@550.54.15"
    assert {item["type"] for item in driver.version_evidence} == {"loaded_kernel_module", "library_filename"}
    assert driver.discovery_provenance["source"] == "loaded-kernel-module"

    cuda = components["cuda_toolkit"]
    assert (cuda.name, cuda.version, cuda.cpe) == ("nvidia-cuda-toolkit", "12.4.1", CUDA_CPE)
    assert [item["source_file"] for item in cuda.version_evidence] == ["usr/local/cuda-12.4/version.json"]

    toolkit = components["nvidia_container_toolkit"]
    assert (toolkit.name, toolkit.ecosystem, toolkit.version, toolkit.cpe) == ("nvidia-container-toolkit", "deb", "1.16.1-1", CTK_CPE)
    assert not [pkg for pkg in packages if pkg.ecosystem == "generic" and pkg.name == "nvidia-container-toolkit"]
    siblings = [
        pkg for pkg in packages if pkg.name in {"nvidia-container-toolkit-base", "libnvidia-container1", "libnvidia-container-tools"}
    ]
    assert len(siblings) == 3 and all(pkg.cpe is None for pkg in siblings)


def test_open_kernel_module_version_is_read(tmp_path: Path) -> None:
    _write(tmp_path, "proc/driver/nvidia/version", OPEN_PROC_VERSION)
    (driver,) = [pkg for pkg in scan_disk_path_native(tmp_path) if pkg.name == "nvidia-gpu-display-driver"]
    assert driver.version == "560.35.03"


def test_distro_driver_package_anchors_identity_without_a_duplicate(tmp_path: Path) -> None:
    dpkg = _stanza("nvidia-driver-550", "550.54.15-0ubuntu1") + _stanza("libnvidia-compute-550", "550.54.15-0ubuntu1")
    packages = scan_disk_path_native(_gpu_rootfs(tmp_path, dpkg=dpkg))
    driver = _nvidia(packages)["gpu_display_driver"]
    assert (driver.name, driver.ecosystem, driver.cpe) == ("nvidia-driver-550", "deb", DRIVER_CPE)
    assert not [pkg for pkg in packages if pkg.name == "nvidia-gpu-display-driver"]


def test_loaded_module_newer_than_package_is_reported_separately() -> None:
    loaded = Package(name="nvidia-gpu-display-driver", version="550.127.05", ecosystem="generic")
    loaded.version_evidence = [{"type": "loaded_kernel_module", "source_file": "proc/driver/nvidia/version"}]
    installed = Package(name="nvidia-driver", version="550.54.15-1.el9", ecosystem="rpm")
    packages = finalize_gpu_stack([installed, loaded])
    assert installed.cpe == DRIVER_CPE
    assert [pkg.cpe for pkg in packages if pkg.ecosystem == "generic"] == [
        "cpe:2.3:a:nvidia:gpu_display_driver:550.127.05:*:*:*:*:linux:*:*"
    ]


def test_without_proc_the_driver_comes_from_the_libcuda_filename(tmp_path: Path) -> None:
    driver = _nvidia(scan_disk_path_native(_gpu_rootfs(tmp_path, dpkg="", proc=None)))["gpu_display_driver"]
    assert driver.version == "550.54.15"
    assert driver.version_evidence == [{"type": "library_filename", "source_file": "usr/lib/x86_64-linux-gnu/libcuda.so.550.54.15"}]
    assert driver.discovery_provenance["source"] == "library-filename"


def test_cuda_compat_libcuda_is_not_the_host_driver(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/cuda-12.4/compat/libcuda.so.550.54.15", b"\x7fELF")
    assert not [pkg for pkg in scan_disk_path_native(tmp_path) if pkg.name == "nvidia-gpu-display-driver"]


def test_legacy_cuda_version_txt(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/cuda-10.2/version.txt", "CUDA Version 10.2.89\n")
    (cuda,) = [pkg for pkg in scan_disk_path_native(tmp_path) if pkg.name == "nvidia-cuda-toolkit"]
    assert cuda.cpe == "cpe:2.3:a:nvidia:cuda_toolkit:10.2.89:*:*:*:*:*:*:*"


def test_unpackaged_container_toolkit_from_library_filename(tmp_path: Path) -> None:
    _write(tmp_path, "usr/lib/x86_64-linux-gnu/libnvidia-container.so.1.16.1", b"\x7fELF")
    (toolkit,) = [pkg for pkg in scan_disk_path_native(tmp_path) if pkg.name == "nvidia-container-toolkit"]
    assert (toolkit.ecosystem, toolkit.version, toolkit.cpe) == ("generic", "1.16.1", CTK_CPE)


@pytest.mark.parametrize(
    ("rel", "content"),
    [
        ("proc/driver/nvidia/version", "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.15;rm -rf  x\n"),
        ("proc/driver/nvidia/version", "garbage"),
        ("usr/local/cuda-12.4/version.json", "{not json"),
        ("usr/local/cuda-12.4/version.json", json.dumps({"cuda": {"version": "12.4.1:*:*"}})),
        ("usr/local/cuda-12.4/version.json", json.dumps({"cuda": {"version": "1" * 5000}})),
    ],
)
def test_malformed_gpu_metadata_emits_nothing(tmp_path: Path, rel: str, content: str) -> None:
    _write(tmp_path, rel, content)
    assert not [pkg for pkg in scan_disk_path_native(tmp_path) if (pkg.cpe or "").startswith("cpe:2.3:a:nvidia:")]


def test_symlinked_version_file_outside_root_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside-version"
    outside.write_text(PROC_VERSION)
    root = tmp_path / "root"
    (root / "proc/driver/nvidia").mkdir(parents=True)
    (root / "proc/driver/nvidia/version").symlink_to(outside)
    assert not [pkg for pkg in scan_disk_path_native(root) if pkg.name == "nvidia-gpu-display-driver"]


def test_detection_never_executes_binaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("GPU detection must not run subprocesses")

    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert len(_nvidia(scan_disk_path_native(_gpu_rootfs(tmp_path)))) == 3


def _image(tmp_path: Path, layers: list[dict[str, bytes]]) -> Path:
    out = tmp_path / "image.tar"
    with tarfile.open(out, mode="w:") as outer:
        layer_paths = []
        for index, files in enumerate(layers):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:") as tf:
                for path, content in files.items():
                    info = tarfile.TarInfo(name=path)
                    info.size = len(content)
                    tf.addfile(info, io.BytesIO(content))
            name = f"{index:040x}/layer.tar"
            layer_paths.append(name)
            info = tarfile.TarInfo(name=name)
            info.size = len(buf.getvalue())
            outer.addfile(info, io.BytesIO(buf.getvalue()))
        config = {"config": {"Env": ["CUDA_VERSION=12.4.1"]}, "history": []}
        for name, payload in (
            ("config.json", json.dumps(config).encode()),
            ("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": ["cuda:12.4"], "Layers": layer_paths}]).encode()),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))
    return out


def test_image_layers_inventory_cuda_and_container_toolkit(tmp_path: Path) -> None:
    image = _image(
        tmp_path,
        [
            {"var/lib/dpkg/status": CTK_DPKG.encode(), "usr/local/cuda-12.4/version.json": CUDA_VERSION_JSON.encode()},
            {"usr/lib/x86_64-linux-gnu/libcuda.so.550.54.15": b"\x7fELF"},
        ],
    )
    components = _nvidia(parse_oci_tarball(image).packages)
    assert set(components) == {"gpu_display_driver", "cuda_toolkit", "nvidia_container_toolkit"}
    assert components["cuda_toolkit"].cpe == CUDA_CPE
    assert components["cuda_toolkit"].occurrences[0].package_path == "usr/local/cuda-12.4/version.json"
    assert components["nvidia_container_toolkit"].ecosystem == "deb"
    assert components["gpu_display_driver"].occurrences[0].layer_index == components["cuda_toolkit"].occurrences[0].layer_index + 1


def test_image_whiteout_removes_cuda_toolkit(tmp_path: Path) -> None:
    image = _image(
        tmp_path,
        [{"usr/local/cuda-12.4/version.json": CUDA_VERSION_JSON.encode()}, {"usr/local/cuda-12.4/.wh.version.json": b""}],
    )
    assert "cuda_toolkit" not in _nvidia(parse_oci_tarball(image).packages)
