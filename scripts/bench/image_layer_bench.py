#!/usr/bin/env python3
"""Native image-parser memory and wall-time bench on synthetic images.

Builds a ``docker save`` tarball per size with two layers (an uncompressed
layer carrying a 2,000-package dpkg status plus an incompressible filler file,
and a gzip layer with the same filler), optionally gzips the whole tarball,
and runs ``agent_bom.oci_parser.scan_oci`` in a fresh interpreter per run. It
reports the tracemalloc peak (Python allocations), the process max RSS and the
wall time. Images are generated chunk by chunk in a temporary directory; no
network or Docker is used.

Examples:
  uv run python scripts/bench/image_layer_bench.py --sizes 128,512 --gzip-outer
  uv run python scripts/bench/image_layer_bench.py --sizes 512 --src /path/to/other/src
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_MIB = 1024 * 1024
_MEASURE = """
import json, resource, sys, time, tracemalloc
from pathlib import Path
from agent_bom.oci_parser import scan_oci
tracemalloc.start()
started = time.perf_counter()
packages, strategy = scan_oci(Path(sys.argv[1]))
wall = time.perf_counter() - started
peak = tracemalloc.get_traced_memory()[1]
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rss_mib = rss / 2**20 if sys.platform == "darwin" else rss / 1024
print(json.dumps({"packages": len(packages), "wall_s": round(wall, 2),
                  "tracemalloc_peak_mib": round(peak / 2**20, 1), "max_rss_mib": round(rss_mib, 1)}))
"""


class _Random:
    def __init__(self, size: int) -> None:
        self.left = size

    def read(self, n: int = -1) -> bytes:
        n = self.left if n < 0 else min(n, self.left)
        self.left -= n
        return os.urandom(n)


def _layer(path: Path, filler: int, *, gz: bool, status: bool) -> None:
    opener = gzip.open(path, "wb", compresslevel=1) if gz else open(path, "wb")
    with opener as raw, tarfile.open(fileobj=raw, mode="w|") as tf:
        if status:
            data = "".join(f"Package: pkg{i}\nStatus: install ok installed\nVersion: 1.{i}\n\n" for i in range(2000)).encode()
            info = tarfile.TarInfo("var/lib/dpkg/status")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("opt/model/weights.bin")
        info.size = filler
        tf.addfile(info, _Random(filler))


def build_image(workdir: Path, layer_mib: int, *, gzip_outer: bool) -> Path:
    first, second = workdir / "l1.tar", workdir / "l2.tar.gz"
    _layer(first, layer_mib * _MIB, gz=False, status=True)
    _layer(second, layer_mib * _MIB, gz=True, status=False)
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["bench:1"], "Layers": ["a/layer.tar", "b/layer.tar"]}]).encode()
    image = workdir / ("image.tar.gz" if gzip_outer else "image.tar")
    options = {"compresslevel": 1} if gzip_outer else {}
    with tarfile.open(image, "w:gz" if gzip_outer else "w", **options) as tf:
        tf.add(first, "a/layer.tar")
        tf.add(second, "b/layer.tar")
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        tf.addfile(info, io.BytesIO(manifest))
    first.unlink()
    second.unlink()
    return image


def measure(image: Path, src: str | None) -> dict:
    env = dict(os.environ)
    if src:
        env["PYTHONPATH"] = src
    out = subprocess.run([sys.executable, "-c", _MEASURE, str(image)], check=True, capture_output=True, text=True, env=env)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", default="128,512", help="comma-separated per-layer filler sizes in MiB")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--gzip-outer", action="store_true", help="also measure a gzip-compressed docker-save tarball")
    parser.add_argument("--src", help="PYTHONPATH for an alternate agent_bom source tree (baseline comparison)")
    parser.add_argument("--output", type=Path, help="write the JSON result here")
    args = parser.parse_args()

    results = []
    variants = [False, True] if args.gzip_outer else [False]
    for size in [int(value) for value in args.sizes.split(",") if value]:
        for gzip_outer in variants:
            workdir = Path(tempfile.mkdtemp(prefix="agent-bom-image-bench-"))
            try:
                image = build_image(workdir, size, gzip_outer=gzip_outer)
                for run in range(args.runs):
                    row = {
                        "layer_mib": size,
                        "image_mib": round(image.stat().st_size / _MIB, 1),
                        "gzip_outer": gzip_outer,
                        "run": run + 1,
                    }
                    row.update(measure(image, args.src))
                    results.append(row)
                    print(json.dumps(row), flush=True)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

    payload = {
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "load_avg": [round(value, 2) for value in os.getloadavg()],
        },
        "results": results,
    }
    if args.output:
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
