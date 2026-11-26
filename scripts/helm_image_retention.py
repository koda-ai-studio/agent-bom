#!/usr/bin/env python3
"""Record Docker Hub image tags required by every published OCI Helm chart."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

_ORIGIN = "https://ghcr.io"
_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_IMAGES = frozenset({"agentbom/agent-bom", "agentbom/agent-bom-ui", "agentbom/agent-bom-collector"})
_MAX_BYTES = 2 * 1024 * 1024
_MAX_PAGES = 100


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        raise RuntimeError("Chart listing refused a redirect")


def _json(url: str, token: str | None = None) -> tuple[dict, str]:
    if urllib.parse.urlsplit(url).netloc != "ghcr.io" or not url.startswith(_ORIGIN + "/"):
        raise RuntimeError("Chart listing refused an off-origin URL")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(_NoRedirects()).open(request, timeout=30) as response:
        raw = response.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise RuntimeError("Chart listing exceeded the response limit")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise RuntimeError("Malformed chart listing response")
        return data, response.headers.get("Link", "")


def chart_versions(repository: str) -> list[str]:
    """A complete public registry listing; partial or ambiguous pages abort."""
    if not _REPOSITORY.fullmatch(repository):
        raise ValueError("Invalid GHCR chart repository")
    query = urllib.parse.urlencode({"scope": f"repository:{repository}:pull", "service": "ghcr.io"})
    auth, _ = _json(f"{_ORIGIN}/token?{query}")
    token = auth.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Chart listing returned no public pull token")
    path = f"/v2/{repository}/tags/list"
    url = f"{_ORIGIN}{path}?n=100"
    seen: set[str] = set()
    versions: set[str] = set()
    for _ in range(_MAX_PAGES):
        if url in seen:
            raise RuntimeError("Chart listing contains a pagination cycle")
        seen.add(url)
        data, link = _json(url, token)
        tags = data.get("tags")
        if (
            data.get("name") != repository
            or not isinstance(tags, list)
            or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) for tag in tags)
        ):
            raise RuntimeError("Malformed chart tag listing")
        versions.update(tags)
        if not link:
            if not versions:
                raise RuntimeError("Chart listing is empty")
            return sorted(versions)
        next_link = re.fullmatch(r'<([^>]+)>;\s*rel="next"', link)
        if not next_link:
            raise RuntimeError("Malformed chart pagination link")
        url = urllib.parse.urljoin(_ORIGIN, next_link.group(1))
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.netloc != "ghcr.io" or parts.path != path or parts.fragment:
            raise RuntimeError("Chart pagination left its repository")
    raise RuntimeError("Chart listing exceeded the page limit")


def images_from_values(values: object) -> dict[str, set[str]]:
    """Read every nested image block, including disabled control-plane images.

    Release checks align default image tags, but custom chart pins are read as
    published rather than guessed from the chart version. A blank tag uses the
    chart's image.tag fallback, as the collector template does.
    """
    if not isinstance(values, dict) or not isinstance(values.get("image"), dict):
        raise ValueError("Chart values have no image block")
    fallback = values["image"].get("tag")
    images: dict[str, set[str]] = {}
    pending = [values]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if not isinstance(item, (dict, list)):
            continue
        if id(item) in seen or len(seen) >= 20_000:
            raise ValueError("Chart values contain aliases or exceed the node limit")
        seen.add(id(item))
        if isinstance(item, list):
            pending.extend(item)
            continue
        repository = item.get("repository")
        if isinstance(repository, str):
            repository = repository.removeprefix("docker.io/").removeprefix("index.docker.io/")
            if repository in _IMAGES:
                tag = item.get("tag") or fallback
                if not isinstance(tag, str) or not _TAG.fullmatch(tag):
                    raise ValueError("Chart image has no explicit tag or valid fallback")
                images.setdefault(repository, set()).add(tag)
        pending.extend(item.values())
    if not images:
        raise ValueError("Chart values contain no managed images")
    return images


def collect_images(repository: str) -> dict:
    charts = []
    images: dict[str, set[str]] = {}
    for version in chart_versions(repository):
        result = subprocess.run(
            ["helm", "show", "values", f"oci://ghcr.io/{repository}", "--version", version],
            capture_output=True,
            timeout=60,
            check=True,
        )
        if len(result.stdout) > _MAX_BYTES:
            raise RuntimeError("Chart values exceeded the response limit")
        refs = images_from_values(yaml.safe_load(result.stdout))
        charts.append({"version": version, "images": {repo: sorted(tags) for repo, tags in sorted(refs.items())}})
        for repo, tags in refs.items():
            images.setdefault(repo, set()).update(tags)
    if set(images) != _IMAGES:
        raise RuntimeError("Published charts do not cover every managed image repository")
    return {
        "schema_version": 1,
        "chart_repository": repository,
        "charts": charts,
        "images": {repo: sorted(tags) for repo, tags in sorted(images.items())},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="koda-ai-studio/charts/agent-bom")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = collect_images(args.repository)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"Protected image references from {len(receipt['charts'])} published charts")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError):
        print("Could not establish complete published chart image references; no retention receipt written", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
