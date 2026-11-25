from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import dockerhub_tag_cleanup as cleanup
from scripts import helm_image_retention as mod
from scripts.dockerhub_tag_cleanup import plan_cleanup
from scripts.helm_image_retention import images_from_values


def test_actual_chart_image_tags_survive_retention_even_when_chart_version_differs():
    values = {
        "image": {"repository": "agentbom/agent-bom", "tag": "0.109.0"},
        "collectorImage": {"repository": "agentbom/agent-bom-collector", "tag": "0.108.4"},
        "uiImage": {"repository": "docker.io/agentbom/agent-bom-ui", "tag": "0.109.0"},
        "controlPlane": {"worker": {"image": {"repository": "agentbom/agent-bom", "tag": "0.107.1"}}},
    }
    images = images_from_values(values)
    assert images == {
        "agentbom/agent-bom": {"0.109.0", "0.107.1"},
        "agentbom/agent-bom-collector": {"0.108.4"},
        "agentbom/agent-bom-ui": {"0.109.0"},
    }
    tags = ["latest", "0.115.6", "0.115.5", "0.108.4"]
    plan = plan_cleanup("agentbom/agent-bom-collector", tags, 2, images["agentbom/agent-bom-collector"])
    assert "0.108.4" in plan.keep
    assert "0.108.4" not in plan.delete


def test_blank_collector_tag_falls_back_to_chart_image_tag():
    images = images_from_values(
        {
            "image": {"repository": "agentbom/agent-bom", "tag": "0.109.0"},
            "collectorImage": {"repository": "agentbom/agent-bom-collector", "tag": ""},
        }
    )
    assert images["agentbom/agent-bom-collector"] == {"0.109.0"}


def test_published_tags_include_older_versions_and_complete_all_pages(monkeypatch):
    repository = "koda-ai-studio/charts/agent-bom"
    urls = []

    def get(url, token=None):
        urls.append(url)
        if "/token?" in url:
            return {"token": "public-pull"}, ""
        assert token == "public-pull"
        if "last=" in url:
            return {"name": repository, "tags": ["0.109.0"]}, ""
        return {"name": repository, "tags": ["0.115.6"]}, f'</v2/{repository}/tags/list?n=100&last=0.115.6>; rel="next"'

    monkeypatch.setattr(mod, "_json", get)
    assert mod.chart_versions(repository) == ["0.109.0", "0.115.6"]
    assert len(urls) == 3


@pytest.mark.parametrize("link", ['<https://elsewhere.example/steal>; rel="next"', '</v2/different/repo/tags/list>; rel="next"', "invalid"])
def test_chart_pagination_cannot_move_token_or_omit_unread_pages(monkeypatch, link):
    def get(url, token=None):
        if token is None:
            return {"token": "public-pull"}, ""
        return {"name": "org/chart", "tags": ["0.109.0"]}, link

    monkeypatch.setattr(mod, "_json", get)
    with pytest.raises(RuntimeError):
        mod.chart_versions("org/chart")


@pytest.mark.parametrize("tags", [[], None, [7], ["--bad-tag"], "0.109.0"])
def test_invalid_or_empty_chart_listing_fails_closed(monkeypatch, tags):
    monkeypatch.setattr(
        mod, "_json", lambda url, token=None: ({"token": "public-pull"}, "") if token is None else ({"name": "org/chart", "tags": tags}, "")
    )
    with pytest.raises(RuntimeError):
        mod.chart_versions("org/chart")


def test_chart_pagination_cycle_fails_closed(monkeypatch):
    monkeypatch.setattr(
        mod,
        "_json",
        lambda url, token=None: (
            ({"token": "public-pull"}, "")
            if token is None
            else ({"name": "org/chart", "tags": ["0.109.0"]}, '</v2/org/chart/tags/list?n=100>; rel="next"')
        ),
    )
    with pytest.raises(RuntimeError, match="cycle"):
        mod.chart_versions("org/chart")


@pytest.mark.parametrize(
    "values",
    [
        None,
        {},
        {"image": {"repository": "agentbom/agent-bom", "tag": None}},
        {"image": {"repository": "agentbom/agent-bom", "tag": "bad tag"}},
    ],
)
def test_ambiguous_values_fail_closed(values):
    with pytest.raises(ValueError):
        mod.images_from_values(values)


def test_all_charts_contribute_their_actual_image_pins(monkeypatch):
    monkeypatch.setattr(mod, "chart_versions", lambda _: ["0.109.0", "0.115.6"])
    seen = []

    def run(args, **kwargs):
        from subprocess import CompletedProcess

        seen.append(args)
        version = args[-1]
        values = {
            key: {"repository": repo, "tag": version}
            for key, repo in [
                ("image", "agentbom/agent-bom"),
                ("uiImage", "agentbom/agent-bom-ui"),
                ("collectorImage", "agentbom/agent-bom-collector"),
            ]
        }
        assert kwargs["check"] and kwargs["timeout"] == 60
        return CompletedProcess(args, 0, yaml.safe_dump(values).encode(), b"")

    monkeypatch.setattr(mod.subprocess, "run", run)
    receipt = mod.collect_images("org/chart")
    assert len(receipt["charts"]) == 2
    assert receipt["images"]["agentbom/agent-bom-collector"] == ["0.109.0", "0.115.6"]
    assert seen[0] == ["helm", "show", "values", "oci://ghcr.io/org/chart", "--version", "0.109.0"]


def test_cleanup_requires_chart_receipt_for_release_images():
    with pytest.raises(ValueError, match="required"):
        cleanup.load_protected_images(None, ["agentbom/agent-bom-collector"])


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": 1, "charts": []},
        {"schema_version": 1, "charts": [{}], "images": {}},
        {"schema_version": 1, "charts": [{}], "images": {"agentbom/agent-bom-collector": []}},
    ],
)
def test_incomplete_receipt_prevents_cleanup(tmp_path, payload):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        cleanup.load_protected_images(path, ["agentbom/agent-bom-collector"])


def test_cleanup_uses_published_references_before_planning_deletions(tmp_path, monkeypatch, capsys):
    repo = "agentbom/agent-bom-collector"
    receipt = {"schema_version": 1, "charts": [{"version": "0.109.0", "images": {repo: ["0.109.0"]}}], "images": {repo: ["0.109.0"]}}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))

    class Fake:
        def __init__(self, *_):
            pass

        def list_tags(self, _):
            return ["latest", "0.115.6", "0.115.5", "0.109.0"]

        def delete_tag(self, *_):
            raise AssertionError("dry run must not delete")

    monkeypatch.setattr(cleanup, "DockerHubClient", Fake)
    monkeypatch.setenv("DOCKERHUB_USERNAME", "placeholder")
    monkeypatch.setenv("DOCKERHUB_TOKEN", "placeholder")
    assert cleanup.main(["--repository", repo, "--keep-count", "2", "--protected-images-file", str(path), "--dry-run"]) == 0
    assert "KEEP   0.109.0" in capsys.readouterr().out


def test_cleanup_workflow_collects_all_published_chart_refs_before_mutation():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/dockerhub-cleanup.yml").read_text())
    steps = workflow["jobs"]["cleanup"]["steps"]
    discovery = next(i for i, step in enumerate(steps) if "scripts/helm_image_retention.py" in step.get("run", ""))
    mutation = next(i for i, step in enumerate(steps) if "scripts/dockerhub_tag_cleanup.py" in step.get("run", ""))
    assert discovery < mutation
    assert "--protected-images-file" in steps[mutation]["run"]


def test_chart_registry_transport_rejects_off_origin_before_open(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("off-origin request must not reach the network")

    monkeypatch.setattr(mod.urllib.request, "build_opener", forbidden)
    with pytest.raises(RuntimeError, match="off-origin"):
        mod._json("https://elsewhere.example/v2/chart/tags/list", "public-pull")


def test_chart_registry_redirect_is_rejected():
    with pytest.raises(RuntimeError, match="redirect"):
        mod._NoRedirects().redirect_request(None, None, 302, "", {}, "https://elsewhere.example")


def test_failed_later_chart_writes_no_partial_receipt(tmp_path, monkeypatch):
    import subprocess
    import sys

    monkeypatch.setattr(mod, "chart_versions", lambda _: ["0.109.0", "0.115.6"])
    calls = []

    def run(args, **kwargs):
        calls.append(args[-1])
        if args[-1] == "0.115.6":
            raise subprocess.TimeoutExpired(args, 60)
        values = {"image": {"repository": "agentbom/agent-bom", "tag": "0.109.0"}}
        return subprocess.CompletedProcess(args, 0, yaml.safe_dump(values).encode(), b"")

    output = tmp_path / "receipt.json"
    monkeypatch.setattr(mod.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["helm_image_retention.py", "--output", str(output)])
    assert mod.main() == 1
    assert calls == ["0.109.0", "0.115.6"]
    assert not output.exists()


def test_receipt_cannot_omit_an_older_chart_reference(tmp_path):
    repo = "agentbom/agent-bom-collector"
    receipt = {"schema_version": 1, "charts": [{"version": "0.109.0", "images": {repo: ["0.109.0"]}}], "images": {repo: ["0.115.6"]}}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="match"):
        cleanup.load_protected_images(path, [repo])
