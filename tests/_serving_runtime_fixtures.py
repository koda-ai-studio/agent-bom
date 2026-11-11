"""Loopback HTTP fixtures that mimic documented model-serving runtime APIs.

Response shapes follow each runtime's published contract:

* vLLM: ``GET /v1/models`` (``ModelList``/``ModelCard``) and ``GET /version``;
  ``/v1`` paths return ``401 {"error": "Unauthorized"}`` when ``--api-key`` is set.
* Text Generation Inference: ``GET /info`` (``Info`` schema in docs/openapi.json).
* Triton (KServe v2): ``GET /v2`` server metadata and ``POST /v2/repository/index``.
* llama.cpp server: ``GET /v1/models`` (one element, ``owned_by: llamacpp``) and ``GET /props``.
* LM Studio: ``GET /api/v0/models`` (``state`` is ``loaded``/``not-loaded``).
* Ollama: ``GET /api/tags``.

No model runtime is installed or started; nothing is downloaded or executed.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Route = tuple[int, Any, float]

_VLLM_MODEL = {
    "id": "qwen2.5-0.5b-instruct",
    "object": "model",
    "created": 1735142223,
    "owned_by": "vllm",
    "root": "Qwen/Qwen2.5-0.5B-Instruct",
    "parent": None,
    "max_model_len": 32768,
    "permission": [],
}
_LLAMACPP_MODEL = {
    "id": "../models/tiny-q4_k_m.gguf",
    "object": "model",
    "created": 1735142223,
    "owned_by": "llamacpp",
    "meta": None,
}
_LMSTUDIO_MODELS = [
    {
        "id": "qwen2-vl-7b-instruct",
        "object": "model",
        "type": "vlm",
        "publisher": "mlx-community",
        "arch": "qwen2_vl",
        "compatibility_type": "mlx",
        "quantization": "4bit",
        "state": "not-loaded",
        "max_context_length": 32768,
    },
    {
        "id": "meta-llama-3.1-8b-instruct",
        "object": "model",
        "type": "llm",
        "publisher": "lmstudio-community",
        "arch": "llama",
        "compatibility_type": "gguf",
        "quantization": "Q4_K_M",
        "state": "loaded",
        "max_context_length": 131072,
    },
]
_TGI_INFO = {
    "model_id": "bigscience/bloom-560m",
    "model_sha": "e985a63cdc139290c5f700ff1929f0b5942cced2",
    "model_pipeline_tag": "text-generation",
    "max_concurrent_requests": 128,
    "max_best_of": 2,
    "max_stop_sequences": 4,
    "max_input_tokens": 1024,
    "max_total_tokens": 2048,
    "validation_workers": 2,
    "max_client_batch_size": 4,
    "router": "text-generation-router",
    "version": "3.3.4",
    "sha": None,
    "docker_label": None,
}
_TRITON_INDEX = [
    {"name": "densenet_onnx", "version": "1", "state": "READY", "reason": ""},
    {"name": "simple", "version": "1", "state": "UNAVAILABLE", "reason": "unloaded"},
]

DENIED: Route = (401, {"error": "Unauthorized"}, 0.0)

# runtime -> outcome -> {(method, path): (status, body, delay_seconds)}
SCENARIOS: dict[str, dict[str, dict[tuple[str, str], Route]]] = {
    "vllm": {
        "success": {
            ("GET", "/v1/models"): (200, {"object": "list", "data": [_VLLM_MODEL]}, 0.0),
            ("GET", "/version"): (200, {"version": "0.11.0"}, 0.0),
        },
        "denied": {("GET", "/v1/models"): DENIED, ("GET", "/version"): (200, {"version": "0.11.0"}, 0.0)},
        "partial": {
            ("GET", "/v1/models"): (200, {"object": "list", "data": [_VLLM_MODEL, {"object": "model"}]}, 0.0),
            ("GET", "/version"): (200, {"version": "0.11.0"}, 0.0),
        },
        "timeout": {("GET", "/v1/models"): (200, {"object": "list", "data": [_VLLM_MODEL]}, 2.0)},
    },
    "tgi": {
        "success": {("GET", "/info"): (200, _TGI_INFO, 0.0)},
        "denied": {("GET", "/info"): (403, {"error": "Forbidden"}, 0.0)},
        "partial": {("GET", "/info"): (200, {k: v for k, v in _TGI_INFO.items() if k != "version"}, 0.0)},
        "timeout": {("GET", "/info"): (200, _TGI_INFO, 2.0)},
    },
    "triton": {
        "success": {
            ("GET", "/v2"): (200, {"name": "triton", "version": "2.59.0", "extensions": ["model_repository"]}, 0.0),
            ("POST", "/v2/repository/index"): (200, _TRITON_INDEX, 0.0),
        },
        "denied": {("POST", "/v2/repository/index"): DENIED, ("GET", "/v2"): DENIED},
        "partial": {
            ("GET", "/v2"): (500, {"error": "internal"}, 0.0),
            ("POST", "/v2/repository/index"): (200, [*_TRITON_INDEX, {"state": "READY"}], 0.0),
        },
        "timeout": {("POST", "/v2/repository/index"): (200, _TRITON_INDEX, 2.0)},
    },
    "llamacpp": {
        "success": {
            ("GET", "/v1/models"): (200, {"object": "list", "data": [_LLAMACPP_MODEL]}, 0.0),
            ("GET", "/props"): (200, {"model_path": "../models/tiny-q4_k_m.gguf", "build_info": "b6100-abc1234", "total_slots": 1}, 0.0),
        },
        "denied": {("GET", "/v1/models"): DENIED, ("GET", "/props"): DENIED},
        "partial": {
            ("GET", "/v1/models"): (200, {"object": "list", "data": [_LLAMACPP_MODEL]}, 0.0),
            ("GET", "/props"): (503, {"error": {"code": 503, "message": "Loading model", "type": "unavailable_error"}}, 0.0),
        },
        "timeout": {("GET", "/v1/models"): (200, {"object": "list", "data": [_LLAMACPP_MODEL]}, 2.0)},
    },
    "lmstudio": {
        "success": {("GET", "/api/v0/models"): (200, {"object": "list", "data": _LMSTUDIO_MODELS}, 0.0)},
        "denied": {("GET", "/api/v0/models"): DENIED},
        "partial": {("GET", "/api/v0/models"): (200, {"object": "list", "data": [_LMSTUDIO_MODELS[1], "bad"]}, 0.0)},
        "timeout": {("GET", "/api/v0/models"): (200, {"object": "list", "data": _LMSTUDIO_MODELS}, 2.0)},
    },
    "ollama": {
        "success": {
            ("GET", "/api/tags"): (
                200,
                {
                    "models": [
                        {"name": "llama3.2:1b", "digest": "a" * 64, "size": 1, "details": {"family": "llama", "format": "gguf"}},
                        {"name": "llama3.2:3b", "digest": "b" * 64, "size": 1, "details": {"family": "llama", "format": "gguf"}},
                    ]
                },
                0.0,
            )
        },
        "denied": {("GET", "/api/tags"): (403, {"error": "forbidden"}, 0.0)},
        "partial": {("GET", "/api/tags"): (200, {"models": [{"name": "llama3.2:1b", "digest": "a" * 64}, None]}, 0.0)},
        "timeout": {("GET", "/api/tags"): (200, {"models": []}, 2.0)},
    },
}


def _handler(routes: dict[tuple[str, str], Route]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            status, body, delay = routes.get((method, self.path), (404, {"error": "not found"}, 0.0))
            if delay:
                time.sleep(delay)
            payload = json.dumps(body).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                # Timeout cases close the client before the delayed reply is written.
                return

        def do_GET(self) -> None:  # noqa: N802
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    return Handler


@contextmanager
def serving_fixture(routes: dict[tuple[str, str], Route]) -> Iterator[str]:
    """Serve *routes* on a random loopback port and yield its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(routes))
    server.daemon_threads = True
    server.block_on_close = False
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def closed_port_url() -> str:
    """Return a loopback URL whose port has no listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}"
