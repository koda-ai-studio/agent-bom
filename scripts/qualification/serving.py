#!/usr/bin/env python3
"""Serving lane: ``--serving-endpoint`` and ``--ollama`` against real runtimes in containers.

Starts each runtime from its vendor's image with a tiny model, records which
status the runtime answers with and without a token, then runs ``agent-bom
agents --no-discover --offline`` against it and checks the outcome the docs
promise: ``success`` with exit 0 and the runtime identity confirmed when the
listing is readable, ``denied`` with exit 1 and no inventory when it is not.

    python scripts/qualification/serving.py --runtime llamacpp --runtime vllm --runtime ollama

Models (downloaded on first use, removed with ``--clean``):
llama.cpp serves Qwen/Qwen2.5-0.5B-Instruct-GGUF ``q4_k_m`` (~470 MiB); vLLM's
CPU image serves ``facebook/opt-125m`` (~250 MiB); Ollama pulls
``qwen2.5:0.5b`` (~380 MiB). API keys are generated per run and reach the
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

from common import LaneResult, agent_bom_command, run_measured, tail  # noqa: E402

IMAGES = {
    "llamacpp": "ghcr.io/ggml-org/llama.cpp:server",
    "vllm": "vllm/vllm-openai-cpu:latest",
    "ollama": "ollama/ollama:latest",
}
GGUF_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
TOKEN_ENV = "AGENT_BOM_SERVING_TOKEN_QUALIFICATION"
# The inventory and metadata reads agent-bom sends, plus /health, per runtime.
READS = {"llamacpp": ["/v1/models", "/props", "/health"], "vllm": ["/v1/models", "/version", "/health", "/metrics"]}


def docker(*args: str, timeout: float = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607


def published_port(container: str, port: int) -> str:
    mapping = docker("port", container, str(port)).stdout.split()
    return f"http://{mapping[0]}" if mapping else ""


def wait_ready(url: str, timeout: float = 600) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=3).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(2)
    return False


def auth_matrix(base: str, paths: list[str], key: str) -> dict[str, dict[str, int]]:
    """Status per path with no token, a wrong token and the right token."""
    tokens = {"none": None, "wrong": "wrong-" + secrets.token_hex(8), "right": key}
    matrix: dict[str, dict[str, int]] = {}
    for path in paths:
        matrix[path] = {}
        for label, token in tokens.items():
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            matrix[path][label] = httpx.get(base + path, headers=headers, timeout=10).status_code
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
        "findings": sorted(finding.get("title") for finding in report.get("findings", [])),
        "warnings": [str(warning)[:200] for warning in report.get("warnings", [])],
        "stderr": tail(run.stderr, 5) if run.returncode not in (0, 1) else "",
    }


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


def openai_compatible(result: LaneResult, runtime: str, workdir: Path, start: Callable[[str, Path | None], str]) -> None:
    """Start the runtime with an API key, record the auth matrix, then probe with none, a wrong and the right token."""
    key_file = secret_file(workdir, f"{runtime}-key")
    wrong_file = secret_file(workdir, f"{runtime}-wrong")
    base = start(f"{runtime}-key", key_file)
    if not result.check(f"{runtime}_ready", wait_ready(base + "/health"), base):
        return
    matrix = auth_matrix(base, READS[runtime], key_file.read_text(encoding="utf-8"))
    result.measurements[f"{runtime}_auth_status"] = matrix
    result.check(f"{runtime}_listing_requires_key", matrix["/v1/models"] == {"none": 401, "wrong": 401, "right": 200}, matrix)
    endpoint = ["--serving-endpoint", f"{runtime}={base}"]
    expect_denied(result, f"{runtime}_no_token_denied", probe(endpoint, workdir))
    paired = [*endpoint, "--serving-token-env", f"{base}={TOKEN_ENV}"]
    expect_denied(result, f"{runtime}_wrong_token_denied", probe(paired, workdir, wrong_file))
    right = probe(paired, workdir, key_file)
    result.measurements[f"{runtime}_success"] = right
    expect_success(result, f"{runtime}_token_success", right, "bearer")


def run_lane(result: LaneResult, runtimes: list[str], models: Path, prefix: str) -> None:
    started: list[str] = []
    with tempfile.TemporaryDirectory(prefix="serving-lane-") as tmp:
        workdir = Path(tmp)
        try:
            for runtime in runtimes:
                image = IMAGES[runtime]
                pulled = docker("pull", "-q", image, timeout=3600)
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

                    open_base = start_llama("llamacpp-open", None)
                    if result.check("llamacpp_open_ready", wait_ready(open_base + "/health"), open_base):
                        expect_success(
                            result,
                            "llamacpp_anonymous_success",
                            probe(["--serving-endpoint", f"llamacpp={open_base}"], workdir),
                            "anonymous",
                        )
                    openai_compatible(result, "llamacpp", workdir, start_llama)
                elif runtime == "vllm":
                    cache = models / "huggingface"
                    cache.mkdir(exist_ok=True)

                    def start_vllm(name: str, key: Path | None) -> str:
                        container = f"{prefix}-{name}"
                        started.append(container)
                        env = ["-e", "VLLM_CPU_KVCACHE_SPACE=1"]
                        command = ["--model", "facebook/opt-125m", "--dtype", "bfloat16", "--max-model-len", "512"]
                        if key:
                            env_file = key.with_suffix(".env")
                            env_file.write_text(f"VLLM_API_KEY={key.read_text(encoding='utf-8')}\n", encoding="utf-8")
                            env_file.chmod(0o600)
                            env += ["--env-file", str(env_file)]
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
                        )
                        return published_port(container, 8000)

                    openai_compatible(result, "vllm", workdir, start_vllm)
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
            for container in started:
                docker("rm", "-f", container)


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
