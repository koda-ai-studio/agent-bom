#!/usr/bin/env python3
"""Serving lane: ``--serving-endpoint`` and ``--ollama`` against real runtimes in containers.

Starts each runtime from its vendor's image with a tiny model, records which
status the runtime answers with and without a token, then runs ``agent-bom
agents --no-discover --offline`` against it and checks the outcome the docs
promise: ``success`` with exit 0 and the runtime identity confirmed when the
listing is readable, ``denied`` with exit 1 and no inventory when it is not.

    python scripts/qualification/serving.py --runtime llamacpp --runtime vllm --runtime ollama
    python scripts/qualification/serving.py --runtime tgi --runtime triton

Models (downloaded on first use, removed with ``--clean``):
llama.cpp serves Qwen/Qwen2.5-0.5B-Instruct-GGUF ``q4_k_m`` (~470 MiB); vLLM's
CPU image serves ``facebook/opt-125m`` (~250 MiB); Ollama pulls
``qwen2.5:0.5b`` (~380 MiB); TGI's Intel CPU image (linux/amd64 only)
serves ``HuggingFaceTB/SmolLM2-135M-Instruct`` (~270 MiB); Triton serves a
generated two-version Python-backend identity model on CPU. API keys are generated per run and reach the
runtime and agent-bom only through files and ``--serving-token-env``.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LaneResult, agent_bom_command, run_measured, secret_env, tail  # noqa: E402

IMAGES = {
    "llamacpp": "ghcr.io/ggml-org/llama.cpp:server",
    "vllm": "vllm/vllm-openai-cpu:latest",
    "ollama": "ollama/ollama:latest",
    # TGI publishes its CPU build (Intel IPEX) for linux/amd64 only; it runs emulated on Apple silicon.
    "tgi": "ghcr.io/huggingface/text-generation-inference:3.3.7-intel-cpu"
    "@sha256:89b4cc8d6e4f7c184c63485a63094760ac9454be658a90f68bc8ecc3cde228bc",
    "triton": "nvcr.io/nvidia/tritonserver:26.10-py3@sha256:b404f7de5dbeeefe0b17d7d149745a50d0989a25d0d831433b5ba63c716c2fcd",
}
PLATFORMS = {"tgi": "linux/amd64"}
TGI_MODEL = "HuggingFaceTB/SmolLM2-135M-Instruct"
TRITON_MODEL = "abq_identity"
GGUF_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
TOKEN_ENV = "AGENT_BOM_SERVING_TOKEN_QUALIFICATION"
# The inventory and metadata reads agent-bom sends, plus /health, per runtime.
READS = {
    "llamacpp": ["/v1/models", "/props", "/health"],
    "vllm": ["/v1/models", "/version", "/health", "/metrics"],
    "tgi": ["/info", "/health", "/v1/models", "/metrics"],
    "triton": ["POST /v2/repository/index", "/v2", "/v2/health/ready", f"/v2/models/{TRITON_MODEL}"],
}
READY = {"llamacpp": "/health", "vllm": "/health", "tgi": "/health", "triton": "/v2/health/ready"}
# TGI's --api-key guards only the generation routes (router/src/server.rs, v3.3.7); /info stays public.
LISTING_OPEN_WITH_KEY = {"tgi"}
LISTING = {"llamacpp": "/v1/models", "vllm": "/v1/models", "tgi": "/info", "triton": "POST /v2/repository/index"}


def docker(*args: str, timeout: float = 900, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, env=env)  # noqa: S603, S607


def published_port(container: str, port: int) -> str:
    mapping = docker("port", container, str(port)).stdout.split()
    return f"http://{mapping[0]}" if mapping else ""


def wait_ready(url: str, timeout: float = 600, key: str | None = None) -> bool:
    deadline = time.monotonic() + timeout
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, headers=headers, timeout=3).status_code == 200:
                return True
        except httpx.HTTPError:
            pass  # not listening yet; retried until the deadline
        time.sleep(2)
    return False


def split_read(read: str) -> tuple[str, str]:
    """``"POST /path"`` -> ``("POST", "/path")``; a bare path is a GET."""
    method, _, path = read.rpartition(" ")
    return method or "GET", path


def auth_matrix(base: str, reads: list[str], key: str) -> dict[str, dict[str, int]]:
    """Status per read with no token, a wrong token and the right token."""
    tokens = {"none": None, "wrong": "wrong-" + secrets.token_hex(8), "right": key}
    matrix: dict[str, dict[str, int]] = {}
    for read in reads:
        method, path = split_read(read)
        matrix[read] = {}
        for label, token in tokens.items():
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            body = {"json": {}} if method == "POST" else {}
            matrix[read][label] = httpx.request(method, base + path, headers=headers, timeout=10, **body).status_code
    return matrix


def probe(args: list[str], workdir: Path, token_file: Path | None = None) -> dict[str, Any]:
    """Run agent-bom against one endpoint and summarize serving evidence, findings, outcome and exit code."""
    out = workdir / f"report-{secrets.token_hex(4)}.json"
    env = {**os.environ, "HOME": str(workdir / "home"), "AGENT_BOM_SKIP_UPDATE_CHECK": "1"}
    env.pop(TOKEN_ENV, None)
    if token_file:
        env[f"{TOKEN_ENV}_FILE"] = str(token_file)
    run = run_measured(
        agent_bom_command("agents", "--no-discover", "--offline", "--quiet", "-f", "json", "-o", str(out), *args), env=env, timeout=300
    )
    report = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    found = [(agent.get("metadata") or {}).get("serving_evidence") for agent in report.get("agents", [])]
    evidence: list[dict[str, Any]] = [item for item in found if isinstance(item, dict)]
    return {
        "exit_code": run.returncode,
        "outcome": (report.get("scan_run") or {}).get("outcome"),
        "statuses": sorted({item["collection"]["status"] for item in evidence}),
        "request_identity": sorted({item["collection"]["request_identity"] for item in evidence}),
        "runtime": sorted({f"{item['runtime']['name']} {item['runtime']['version']} {item['runtime']['identity']}" for item in evidence}),
        "models": sorted(item["model"]["served_name"] for item in evidence),
        "records": sorted(model_record(item["model"]) for item in evidence),
        "agent_names": sorted(
            {str(agent.get("name")) for agent in report.get("agents", []) if (agent.get("metadata") or {}).get("serving_evidence")}
        ),
        "findings": sorted(finding.get("title") for finding in report.get("findings", [])),
        "warnings": [str(warning)[:200] for warning in report.get("warnings", [])],
        "stderr": tail(run.stderr, 5) if run.returncode not in (0, 1) else "",
    }


def model_record(model: dict[str, Any]) -> str:
    """One comparable line per model: name, version, digest and state as reported."""
    return " ".join(f"{key}={model.get(key)}" for key in ("served_name", "version", "digest", "state"))


def tgi_truth(info: dict[str, Any]) -> dict[str, Any]:
    """What a TGI ``/info`` response says the server serves."""
    model = {"served_name": info.get("model_id"), "version": None, "digest": info.get("model_sha"), "state": None}
    return {"records": [model_record(model)], "runtime_version": info.get("version")}


def triton_truth(index: list[dict[str, Any]], metadata: dict[str, Any]) -> dict[str, Any]:
    """What Triton's repository index and server metadata say the server serves."""
    records = [model_record({"served_name": e.get("name"), "version": e.get("version"), "state": e.get("state")}) for e in index]
    return {"records": sorted(records), "runtime_version": metadata.get("version")}


def server_truth(runtime: str, base: str) -> dict[str, Any]:
    if runtime == "tgi":
        return tgi_truth(httpx.get(base + "/info", timeout=10).json())
    index = httpx.post(base + "/v2/repository/index", json={}, timeout=10).json()
    return triton_truth(index, httpx.get(base + "/v2", timeout=10).json())


def expect_truth(result: LaneResult, runtime: str, outcome: dict[str, Any], truth: dict[str, Any]) -> None:
    """agent-bom must report exactly the models and runtime version the server reports, each under its own name."""
    versions = {line.split(" ")[1] for line in outcome["runtime"]}
    ok = outcome["records"] == truth["records"] and versions == {str(truth["runtime_version"])}
    ok = ok and len(outcome["agent_names"]) == len(truth["records"])
    result.check(f"{runtime}_matches_server", ok, {"agent_bom": outcome, "server": truth})


def expect_success(result: LaneResult, name: str, outcome: dict[str, Any], identity: str) -> None:
    ok = outcome["exit_code"] == 0 and outcome["statuses"] == ["success"] and outcome["request_identity"] == [identity]
    ok = ok and outcome["outcome"] == "complete" and not outcome["findings"] and all("confirmed" in r for r in outcome["runtime"])
    result.check(name, ok, outcome)


def expect_denied(result: LaneResult, name: str, outcome: dict[str, Any]) -> None:
    denied = any("denied (HTTP 401" in warning or "denied (HTTP 403" in warning for warning in outcome["warnings"])
    result.check(name, outcome["exit_code"] == 1 and not outcome["models"] and denied, outcome)


def secret_file(directory: Path, name: str) -> Path:
    path = directory / name
    path.write_text(secrets.token_hex(24), encoding="utf-8")
    path.chmod(0o600)
    return path


def keyed_runtime(result: LaneResult, runtime: str, workdir: Path, start: Callable[[str, Path | None], str]) -> None:
    """Start the runtime with an API key, record the auth matrix, then probe with none, a wrong and the right token."""
    key_file = secret_file(workdir, f"{runtime}-key")
    wrong_file = secret_file(workdir, f"{runtime}-wrong")
    key = key_file.read_text(encoding="utf-8")
    base = start(f"{runtime}-key", key_file)
    if not result.check(f"{runtime}_ready", wait_ready(base + READY[runtime], key=key), base):
        return
    matrix = auth_matrix(base, READS[runtime], key)
    result.measurements[f"{runtime}_auth_status"] = matrix
    listing = matrix[LISTING[runtime]]
    endpoint = ["--serving-endpoint", f"{runtime}={base}"]
    paired = [*endpoint, "--serving-token-env", f"{base}={TOKEN_ENV}"]
    if runtime in LISTING_OPEN_WITH_KEY:
        result.check(f"{runtime}_listing_open_with_key", listing == {"none": 200, "wrong": 200, "right": 200}, matrix)
        expect_success(result, f"{runtime}_keyed_no_token_success", probe(endpoint, workdir), "anonymous")
        expect_success(result, f"{runtime}_keyed_wrong_token_success", probe(paired, workdir, wrong_file), "bearer")
    else:
        result.check(f"{runtime}_listing_requires_key", listing["none"] in (401, 403) and listing["right"] == 200, matrix)
        expect_denied(result, f"{runtime}_no_token_denied", probe(endpoint, workdir))
        expect_denied(result, f"{runtime}_wrong_token_denied", probe(paired, workdir, wrong_file))
    right = probe(paired, workdir, key_file)
    result.measurements[f"{runtime}_success"] = right
    expect_success(result, f"{runtime}_token_success", right, "bearer")


def anonymous_runtime(result: LaneResult, runtime: str, workdir: Path, start: Callable[[str, Path | None], str]) -> None:
    """Start the runtime without a key, expect an anonymous ``success`` and compare it with the server's own answer."""
    base = start(f"{runtime}-open", None)
    if not result.check(f"{runtime}_open_ready", wait_ready(base + READY[runtime], timeout=1800), base):
        return
    outcome = probe(["--serving-endpoint", f"{runtime}={base}"], workdir)
    result.measurements[f"{runtime}_anonymous"] = outcome
    expect_success(result, f"{runtime}_anonymous_success", outcome, "anonymous")
    if runtime in ("tgi", "triton"):
        expect_truth(result, runtime, outcome, server_truth(runtime, base))


TRITON_CONFIG = f"""name: "{TRITON_MODEL}"
backend: "python"
max_batch_size: 0
input [{{ name: "INPUT0", data_type: TYPE_FP32, dims: [ 4 ] }}]
output [{{ name: "OUTPUT0", data_type: TYPE_FP32, dims: [ 4 ] }}]
instance_group [{{ kind: KIND_CPU, count: 1 }}]
version_policy: {{ all: {{}} }}
"""
TRITON_PYTHON = """import triton_python_backend_utils as pb_utils


class TritonPythonModel:
    def execute(self, requests):
        return [
            pb_utils.InferenceResponse([pb_utils.Tensor("OUTPUT0", pb_utils.get_input_tensor_by_name(r, "INPUT0").as_numpy())])
            for r in requests
        ]
"""


def write_triton_repository(root: Path) -> Path:
    """A CPU-only Python-backend identity model with two versions, both served under ``version_policy: all``."""
    model = root / TRITON_MODEL
    for version in ("1", "2"):
        (model / version).mkdir(parents=True, exist_ok=True)
        (model / version / "model.py").write_text(TRITON_PYTHON, encoding="utf-8")
    (model / "config.pbtxt").write_text(TRITON_CONFIG, encoding="utf-8")
    return root


def triton_command(keyed: bool) -> list[str]:
    """Shell command for the Triton container; the key arrives only through ``$TRITON_QUALIFICATION_KEY``."""
    command = "exec tritonserver --model-repository=/models --allow-grpc=false --allow-metrics=false"
    if keyed:
        command += ' "--http-restricted-api=model-repository,metadata:Authorization=Bearer ${TRITON_QUALIFICATION_KEY}"'
    return ["sh", "-c", command]


def tgi_command() -> list[str]:
    return ["--model-id", TGI_MODEL, "--port", "8080", "--max-input-tokens", "256", "--max-total-tokens", "512"]


def runtime_starter(runtime: str, prefix: str, started: list[str], volume: str) -> Callable[[str, Path | None], str]:
    """``start(name, key_file)`` for TGI or Triton, publishing only on loopback."""
    image, port = IMAGES[runtime], 8080 if runtime == "tgi" else 8000
    key_name = "API_KEY" if runtime == "tgi" else "TRITON_QUALIFICATION_KEY"

    def start(name: str, key: Path | None) -> str:
        container = f"{prefix}-{name}"
        started.append(container)
        env = ["-e", "USAGE_STATS=off"] if runtime == "tgi" else []
        key_env: dict[str, str] | None = None
        if key:
            key_args, key_env = secret_env({key_name: key.read_text(encoding="utf-8")})
            env += key_args
        platform = ["--platform", PLATFORMS[runtime]] if runtime in PLATFORMS else []
        command = tgi_command() if runtime == "tgi" else triton_command(key is not None)
        docker(
            "run",
            "-d",
            "--name",
            container,
            *platform,
            "-p",
            f"127.0.0.1::{port}",
            "--shm-size=1g",
            "-v",
            volume,
            *env,
            image,
            *command,
            env=key_env,
        )
        return published_port(container, port)

    return start


def run_lane(result: LaneResult, runtimes: list[str], models: Path, prefix: str) -> None:
    started: list[str] = []
    with tempfile.TemporaryDirectory(prefix="serving-lane-") as tmp:
        workdir = Path(tmp)
        try:
            for runtime in runtimes:
                image = IMAGES[runtime]
                platform = ["--platform", PLATFORMS[runtime]] if runtime in PLATFORMS else []
                pulled = docker("pull", "-q", *platform, image, timeout=3600)
                digest = docker("image", "inspect", image, "--format", "{{index .RepoDigests 0}}").stdout.strip()
                result.measurements[f"{runtime}_image"] = digest or tail(pulled.stderr, 3)
                if runtime == "llamacpp":
                    gguf = models / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
                    if not gguf.exists():
                        urllib.request.urlretrieve(GGUF_URL, gguf)  # noqa: S310  # nosec B310

                    def start_llama(name: str, key: Path | None) -> str:
                        container = f"{prefix}-{name}"
                        started.append(container)
                        extra = ["-v", f"{key}:/run/key:ro"] if key else []
                        command = ["-m", "/models/" + gguf.name, "--host", "0.0.0.0", "--port", "8080", "-c", "512", "-t", "2"]
                        command += ["--api-key-file", "/run/key"] if key else []
                        docker(
                            "run", "-d", "--name", container, "-p", "127.0.0.1::8080", "-v", f"{models}:/models:ro", *extra, image, *command
                        )
                        return published_port(container, 8080)

                    anonymous_runtime(result, "llamacpp", workdir, start_llama)
                    keyed_runtime(result, "llamacpp", workdir, start_llama)
                elif runtime == "vllm":
                    cache = models / "huggingface"
                    cache.mkdir(exist_ok=True)

                    def start_vllm(name: str, key: Path | None) -> str:
                        container = f"{prefix}-{name}"
                        started.append(container)
                        env = ["-e", "VLLM_CPU_KVCACHE_SPACE=1"]
                        command = ["--model", "facebook/opt-125m", "--dtype", "bfloat16", "--max-model-len", "512"]
                        key_env: dict[str, str] | None = None
                        if key:
                            key_args, key_env = secret_env({"VLLM_API_KEY": key.read_text(encoding="utf-8")})
                            env += key_args
                        docker(
                            "run",
                            "-d",
                            "--name",
                            container,
                            "-p",
                            "127.0.0.1::8000",
                            "--shm-size=1g",
                            "-v",
                            f"{cache}:/root/.cache/huggingface",
                            *env,
                            image,
                            *command,
                            env=key_env,
                        )
                        return published_port(container, 8000)

                    keyed_runtime(result, "vllm", workdir, start_vllm)
                elif runtime in ("tgi", "triton"):
                    if runtime == "tgi":
                        (models / "huggingface").mkdir(exist_ok=True)
                        volume = f"{models / 'huggingface'}:/data"
                    else:
                        volume = f"{write_triton_repository(workdir / 'triton-models')}:/models:ro"
                    start = runtime_starter(runtime, prefix, started, volume)
                    anonymous_runtime(result, runtime, workdir, start)
                    remove(started)
                    keyed_runtime(result, runtime, workdir, start)
                    remove(started)
                elif runtime == "ollama":
                    container = f"{prefix}-ollama"
                    started.append(container)
                    docker("run", "-d", "--name", container, "-p", "127.0.0.1::11434", "-v", f"{models / 'ollama'}:/root/.ollama", image)
                    base = published_port(container, 11434)
                    if result.check("ollama_ready", wait_ready(base + "/api/tags"), base):
                        docker("exec", container, "ollama", "pull", "qwen2.5:0.5b", timeout=1800)
                        outcome = probe(["--ollama", "--ollama-host", base], workdir)
                        result.measurements["ollama_success"] = outcome
                        result.check(
                            "ollama_success",
                            outcome["exit_code"] == 0 and outcome["statuses"] == ["success"] and outcome["models"],
                            outcome,
                        )
        finally:
            remove(started)


def remove(started: list[str]) -> None:
    while started:
        docker("rm", "-f", started.pop())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runtime", action="append", choices=sorted(IMAGES), help="repeatable; default all")
    parser.add_argument("--models-dir", type=Path, default=Path(tempfile.gettempdir()) / "agent-bom-serving-models")
    parser.add_argument("--name-prefix", default="agent-bom-serving")
    parser.add_argument("--clean", action="store_true", help="delete the downloaded models afterwards")
    args = parser.parse_args()
    args.models_dir.mkdir(parents=True, exist_ok=True)
    result = LaneResult("serving", "containers")
    try:
        run_lane(result, args.runtime or sorted(IMAGES), args.models_dir, args.name_prefix)
    except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
        result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
    finally:
        if args.clean:
            docker("run", "--rm", "-v", f"{args.models_dir}:/m", "alpine:3.20", "sh", "-c", "rm -rf /m/*")
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
