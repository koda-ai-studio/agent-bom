"""The base image is named only from explicit evidence, and packages are split base/app only on an exact layer match."""

from __future__ import annotations

import shutil

import pytest

from agent_bom.image import scan_image, scan_image_tar
from agent_bom.image_evidence import collect_image_evidence
from agent_bom.oci_registry import client as registry_client
from tests._oci_image_builder import build_image, dpkg_status, tar_bytes
from tests._oci_registry_fake import REGISTRY, FakeRegistry

BASE_REF = f"{REGISTRY}/base/debian:12"
APP_REF = f"{REGISTRY}/team/app:1.0"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    return fake


def _base_layer() -> bytes:
    return tar_bytes({"var/lib/dpkg/status": dpkg_status(("libc6", "2.36-9"), ("openssl", "3.0.11-1"))})


def _push_base(registry: FakeRegistry, raw_layer: bytes):
    base = build_image([], base_layers=[raw_layer])
    registry.push_image("base/debian", base, "12")
    return base


def _app(base_digest: str, base_layer: bytes, *, name: str = BASE_REF):
    status = dpkg_status(("libc6", "2.36-9"), ("openssl", "3.0.11-1"), ("nginx", "1.25.4"))
    return build_image(
        [{"var/lib/dpkg/status": status}],
        base_layers=[base_layer],
        annotations={"org.opencontainers.image.base.name": name, "org.opencontainers.image.base.digest": base_digest},
    )


def _origins(packages) -> dict[str, set[str]]:
    return {p.name: {o.layer_origin for o in p.occurrences} for p in packages}


def test_exact_layer_prefix_splits_packages_between_base_and_app(registry):
    base = _push_base(registry, _base_layer())
    app = _app(base.manifest_digest, _base_layer())
    registry.push_image("team/app", app, "1.0")

    with collect_image_evidence(APP_REF) as evidence:
        packages, _ = scan_image(APP_REF)

    assert evidence.base_image["name"] == BASE_REF
    assert evidence.base_image["source"] == "manifest-annotation"
    assert evidence.base_image["attribution"] == "layer-digest-match"
    assert evidence.base_image["layer_count"] == 1
    origins = _origins(packages)
    # apt in the app layer rewrites dpkg status; packages the base already shipped at this version stay inherited.
    assert origins["nginx"] == {"app"}
    assert origins["openssl"] == {"base", "app"}
    assert (evidence.base_image["packages_from_base"], evidence.base_image["packages_from_app"]) == (2, 1)


def test_packages_only_in_base_layers_are_attributed_to_the_base(registry):
    base_layer = tar_bytes({"usr/lib/python3/dist-packages/six-1.16.0.dist-info/METADATA": b"Name: six\nVersion: 1.16.0\n"})
    base = _push_base(registry, base_layer)
    app = build_image(
        [{"app/node_modules/left-pad/package.json": b'{"name": "left-pad", "version": "1.3.0"}'}],
        base_layers=[base_layer],
        annotations={"org.opencontainers.image.base.name": BASE_REF, "org.opencontainers.image.base.digest": base.manifest_digest},
    )
    registry.push_image("team/app", app, "1.0")

    with collect_image_evidence(APP_REF) as evidence:
        packages, _ = scan_image(APP_REF)

    origins = _origins(packages)
    assert origins["six"] == {"base"} and origins["left-pad"] == {"app"}
    assert evidence.base_image["packages_from_base"] == 1
    six = next(p for p in packages if p.name == "six")
    assert six.occurrences[0].to_dict()["base_image"] == BASE_REF


def test_named_base_whose_layers_do_not_match_attributes_nothing(registry):
    base = _push_base(registry, tar_bytes({"etc/debian_version": b"12.4\n"}))
    app = _app(base.manifest_digest, _base_layer())
    registry.push_image("team/app", app, "1.0")

    with collect_image_evidence(APP_REF) as evidence:
        packages, _ = scan_image(APP_REF)

    assert evidence.base_image["attribution"] == "layer-digest-mismatch"
    assert all(o.layer_origin is None for p in packages for o in p.occurrences)


def test_archive_scan_names_base_from_labels_without_claiming_attribution(tmp_path):
    image = build_image(
        [{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}],
        labels={"org.opencontainers.image.base.name": "docker.io/library/debian:12"},
    )
    with collect_image_evidence("app.tar") as evidence:
        packages, _ = scan_image_tar(str(image.write_layout(tmp_path / "layout")))

    assert evidence.source == "archive"
    assert evidence.base_image == {
        "name": "docker.io/library/debian:12",
        "digest": None,
        "source": "config-label",
        "attribution": "unresolved",
        "layer_count": None,
    }
    assert [o.layer_origin for p in packages for o in p.occurrences] == [None]


def test_image_without_base_evidence_has_no_base(registry):
    registry.push_image("team/app", build_image([{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}]), "1.0")
    with collect_image_evidence(APP_REF) as evidence:
        scan_image(APP_REF)
    assert evidence.base_image is None


@pytest.mark.parametrize("config", [{"rootfs": {"diff_ids": 7}}, {"rootfs": {"diff_ids": ["invalid"]}}, {"history": ["bad"]}])
def test_malformed_base_config_is_unresolved_with_coverage(config):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from agent_bom.image_evidence.model import ImageEvidence
    from agent_bom.oci_registry.supply_chain import resolve_base_layers
    from agent_bom.scanners.state import consume_coverage_warnings

    digest = "sha256:" + "a" * 64
    manifest = SimpleNamespace(
        media_type="application/vnd.oci.image.manifest.v1+json", document={"layers": [], "config": {"digest": digest}}
    )
    client = SimpleNamespace(get_manifest=lambda *_args, **_kwargs: manifest, fetch_json_blob=lambda *_args: config)
    evidence = ImageEvidence(APP_REF, base_image={"name": BASE_REF, "digest": digest}, diff_ids=[digest])
    resolve_base_layers(evidence, lambda _ref: nullcontext(client))
    assert evidence.base_image["attribution"] == "unresolved"
    assert any(w["reason"] == "image_base_attribution_incomplete" for w in consume_coverage_warnings())


@pytest.mark.parametrize("digest", ["sha512:" + "b" * 128, "sha512:invalid"])
def test_base_digest_pin_is_preserved_or_refused_never_replaced_by_tag(digest):
    from agent_bom.image_evidence.base_image import BASE_DIGEST_KEY, BASE_NAME_KEY, identify_base_image
    from agent_bom.image_evidence.model import ImageEvidence
    from agent_bom.oci_registry.client import RegistryError
    from agent_bom.oci_registry.supply_chain import resolve_base_layers
    from agent_bom.scanners.state import consume_coverage_warnings

    evidence = ImageEvidence(APP_REF, annotations={BASE_NAME_KEY: BASE_REF, BASE_DIGEST_KEY: digest})
    evidence.base_image = identify_base_image(evidence)
    fetched = []

    def open_client(ref):
        fetched.append(ref.manifest_ref)
        raise RegistryError("fixture unavailable")

    resolve_base_layers(evidence, open_client)
    if digest.endswith("invalid"):
        assert not fetched
        assert evidence.base_image["digest"] is None
        assert any(w["reason"] == "image_base_attribution_incomplete" for w in consume_coverage_warnings())
    else:
        assert evidence.base_image["digest"] == digest
        assert fetched == [digest]
    assert evidence.base_image["attribution"] == "unresolved"
