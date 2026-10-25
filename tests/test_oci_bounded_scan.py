"""Image scans stay bounded in memory and wall time, and say so when they stop early."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import tarfile
import time
import tracemalloc
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom import oci_parser
from agent_bom.cli import main
from agent_bom.oci_parser import parse_oci_layout_dir, parse_oci_tarball, scan_oci
from agent_bom.parsers.oci_stream import LayerLimitError, ScanBudget, spool_layer
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

_MIB = 1024 * 1024
_FILLER_BYTES = 24 * _MIB
_PEAK_LIMIT_BYTES = 12 * _MIB


class _Stream:
    """File-like source of ``size`` bytes generated chunk by chunk."""

    def __init__(self, size: int, *, random: bool) -> None:
        self.left = size
        self.random = random

    def read(self, n: int = -1) -> bytes:
        n = self.left if n < 0 else min(n, self.left)
        self.left -= n
        return os.urandom(n) if self.random else bytes(n)


def _status(*names: str) -> bytes:
    return "".join(f"Package: {name}\nStatus: install ok installed\nVersion: 1.0\n\n" for name in names).encode()


def _write_layer(path: Path, *, gz: bool, status: bytes | None, filler: int = 0, random: bool = True, extra_files: int = 0) -> None:
    opener = gzip.open(path, "wb", compresslevel=1) if gz else open(path, "wb")
    with opener as raw, tarfile.open(fileobj=raw, mode="w|") as layer:
        if status is not None:
            info = tarfile.TarInfo("var/lib/dpkg/status")
            info.size = len(status)
            layer.addfile(info, io.BytesIO(status))
        if filler:
            info = tarfile.TarInfo("opt/model/weights.bin")
            info.size = filler
            layer.addfile(info, _Stream(filler, random=random))
        for index in range(extra_files):
            info = tarfile.TarInfo(f"srv/data/file-{index}.txt")
            info.size = 1
            layer.addfile(info, io.BytesIO(b"x"))


def _docker_save(tmp_path: Path, layers: list[Path], *, gzip_outer: bool = False) -> Path:
    names = [f"{index:040d}/layer.tar" for index in range(len(layers))]
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["bounded:test"], "Layers": names}]).encode()
    image = tmp_path / ("image.tar.gz" if gzip_outer else "image.tar")
    options = {"compresslevel": 1} if gzip_outer else {}
    with tarfile.open(image, "w:gz" if gzip_outer else "w", **options) as tf:
        for name, layer in zip(names, layers, strict=True):
            tf.add(layer, name)
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        tf.addfile(info, io.BytesIO(manifest))
    return image


def _oci_layout(tmp_path: Path, layers: list[Path]) -> Path:
    root = tmp_path / "layout"
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    descriptors = []
    for index, layer in enumerate(layers):
        digest = f"{index:064x}"
        layer.rename(blobs / digest)
        descriptors.append({"digest": f"sha256:{digest}"})
    manifest = json.dumps({"layers": descriptors}).encode()
    (blobs / ("f" * 64)).write_bytes(manifest)
    (root / "index.json").write_text(json.dumps({"manifests": [{"digest": "sha256:" + "f" * 64}]}))
    return root


@pytest.fixture(autouse=True)
def _reset_coverage_state():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def _measure(fn):
    tracemalloc.start()
    try:
        result = fn()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


def _names(packages) -> set[str]:
    return {package.name for package in packages}


@pytest.mark.parametrize("gz", [False, True], ids=["uncompressed-layer", "gzip-layer"])
def test_docker_save_layer_is_streamed_not_buffered(tmp_path: Path, gz: bool) -> None:
    layer = tmp_path / "layer.tar"
    _write_layer(layer, gz=gz, status=_status("openssl"), filler=_FILLER_BYTES)
    image = _docker_save(tmp_path, [layer])

    result, peak = _measure(lambda: parse_oci_tarball(image))

    assert _names(result.packages) == {"openssl"}
    assert result.coverage_warnings == []
    assert peak < _PEAK_LIMIT_BYTES, f"peak {peak / _MIB:.1f} MiB for a {_FILLER_BYTES / _MIB:.0f} MiB layer"


def test_gzip_outer_tarball_is_streamed_not_buffered(tmp_path: Path) -> None:
    layer = tmp_path / "layer.tar"
    _write_layer(layer, gz=False, status=_status("zlib1g"), filler=_FILLER_BYTES)
    image = _docker_save(tmp_path, [layer], gzip_outer=True)

    result, peak = _measure(lambda: parse_oci_tarball(image))

    assert _names(result.packages) == {"zlib1g"}
    assert peak < _PEAK_LIMIT_BYTES


def test_oci_layout_gzip_blob_is_streamed_not_buffered(tmp_path: Path) -> None:
    layer = tmp_path / "layer.tar.gz"
    _write_layer(layer, gz=True, status=_status("libc6"), filler=_FILLER_BYTES)
    root = _oci_layout(tmp_path, [layer])

    result, peak = _measure(lambda: parse_oci_layout_dir(root))

    assert _names(result.packages) == {"libc6"}
    assert result.coverage_warnings == []
    assert peak < _PEAK_LIMIT_BYTES


def test_spool_stops_decompressing_a_bomb_at_the_ratio_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO", "10")
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1) as gz:
        for _ in range(64):
            gz.write(bytes(_MIB))
    compressed = raw.getvalue()
    raw.seek(0)

    with pytest.raises(LayerLimitError) as excinfo:
        spool_layer(raw, len(compressed), ScanBudget.from_env())

    assert excinfo.value.reason == "oci_layer_decompression_limit"
    assert excinfo.value.bytes_written <= len(compressed) * 10 + _MIB


def test_spool_stops_at_the_uncompressed_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES", str(4 * _MIB))
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1) as gz:
        gz.write(os.urandom(16 * _MIB))
    raw.seek(0)

    with pytest.raises(LayerLimitError) as excinfo:
        spool_layer(raw, len(raw.getvalue()), ScanBudget.from_env())

    assert excinfo.value.reason == "oci_layer_size_limit"
    assert excinfo.value.bytes_written <= 5 * _MIB


def test_decompression_bomb_layer_is_skipped_with_coverage_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO", "10")
    bomb = tmp_path / "bomb.tar"
    _write_layer(bomb, gz=True, status=None, filler=64 * _MIB, random=False)
    good = tmp_path / "good.tar"
    _write_layer(good, gz=False, status=_status("bash"))
    image = _docker_save(tmp_path, [good, bomb])

    result, peak = _measure(lambda: parse_oci_tarball(image))

    assert _names(result.packages) == {"bash"}
    assert [warning.reason for warning in result.coverage_warnings] == ["oci_layer_decompression_limit"]
    assert peak < _PEAK_LIMIT_BYTES


def test_layer_member_count_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_MEMBERS", "50")
    wide = tmp_path / "wide.tar"
    _write_layer(wide, gz=False, status=_status("ignored"), extra_files=200)
    good = tmp_path / "good.tar"
    _write_layer(good, gz=False, status=_status("bash"))
    image = _docker_save(tmp_path, [good, wide])

    result = parse_oci_tarball(image)

    assert _names(result.packages) == {"bash"}
    assert [(warning.path, warning.reason) for warning in result.coverage_warnings] == [
        (f"{1:040d}/layer.tar", "oci_layer_member_limit"),
    ]


def _slow_layers(monkeypatch: pytest.MonkeyPatch, delay: float) -> None:
    original = oci_parser._read_os_release_from_layer

    def _slow(*args, **kwargs):
        time.sleep(delay)
        return original(*args, **kwargs)

    monkeypatch.setattr(oci_parser, "_read_os_release_from_layer", _slow)


def _three_layer_image(tmp_path: Path) -> Path:
    layers = []
    for index, name in enumerate(("base-pkg", "mid-pkg", "top-pkg")):
        layer = tmp_path / f"l{index}.tar"
        _write_layer(layer, gz=False, status=_status(name))
        layers.append(layer)
    return _docker_save(tmp_path, layers)


def test_time_budget_returns_partial_inventory_naming_skipped_layers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS", "0.5")
    _slow_layers(monkeypatch, 0.3)
    image = _three_layer_image(tmp_path)

    packages, _strategy = scan_oci(image)

    assert _names(packages) == {"base-pkg"}
    warnings = consume_coverage_warnings()
    assert [(warning["release"], warning["reason"]) for warning in warnings] == [
        (f"oci:{1:040d}/layer.tar", "oci_scan_time_budget"),
        (f"oci:{2:040d}/layer.tar", "oci_scan_time_budget"),
    ]
    assert all("time budget" in warning["detail"] for warning in warnings)


def test_time_budget_zero_disables_the_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS", "0")
    _slow_layers(monkeypatch, 0.05)
    image = _three_layer_image(tmp_path)

    packages, _strategy = scan_oci(image)

    assert _names(packages) == {"base-pkg", "mid-pkg", "top-pkg"}
    assert consume_coverage_warnings() == []


def test_time_budget_exhaustion_makes_the_scan_run_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS", "0.5")
    _slow_layers(monkeypatch, 0.3)
    image = _three_layer_image(tmp_path)
    output = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        ["scan", "--image-tar", str(image), "--offline", "--no-auto-update-db", "--format", "json", "--output", str(output)],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_run"]["outcome"] == "partial", result.output
    reasons = {warning["reason"] for warning in payload["coverage_warnings"] if warning.get("ecosystem") == "oci"}
    assert reasons == {"oci_scan_time_budget"}


def test_image_scan_limits_are_documented() -> None:
    from agent_bom.parsers import oci_io

    source = Path(oci_io.__file__).read_text(encoding="utf-8")
    documented = (Path(__file__).resolve().parents[1] / "site-docs" / "features" / "scanning.md").read_text(encoding="utf-8")
    names = set(re.findall(r'"(AGENT_BOM_OCI_[A-Z_]+)"', source))
    assert names >= {"AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS", "AGENT_BOM_OCI_MAX_LAYER_MEMBERS", "AGENT_BOM_OCI_MAX_LAYER_COMPRESSED_BYTES"}
    assert {name for name in names if f"`{name}`" not in documented} == set()


@pytest.mark.parametrize("mode", ["w:xz", "w:bz2"])
def test_xz_and_bzip2_layers_are_spooled_and_parsed(tmp_path: Path, mode: str) -> None:
    layer = tmp_path / "layer.tar"
    status = _status("coreutils")
    with tarfile.open(layer, mode) as tf:
        info = tarfile.TarInfo("var/lib/dpkg/status")
        info.size = len(status)
        tf.addfile(info, io.BytesIO(status))
    root = _oci_layout(tmp_path, [layer])

    result = parse_oci_layout_dir(root)

    assert _names(result.packages) == {"coreutils"}
    assert result.coverage_warnings == []


def test_truncated_gzip_layer_is_a_parse_error_gap(tmp_path: Path) -> None:
    layer = tmp_path / "layer.tar.gz"
    _write_layer(layer, gz=True, status=_status("ignored"), filler=_MIB)
    layer.write_bytes(layer.read_bytes()[: layer.stat().st_size // 2])
    good = tmp_path / "good.tar"
    _write_layer(good, gz=False, status=_status("bash"))
    image = _docker_save(tmp_path, [good, layer])

    result = parse_oci_tarball(image)

    assert _names(result.packages) == {"bash"}
    assert [warning.reason for warning in result.coverage_warnings] == ["oci_layer_parse_error"]
