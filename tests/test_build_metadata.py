"""Build quantities are exempted only at their structural configuration paths."""

import json
from pathlib import Path

import pytest

from agent_bom.scanners.build_metadata import mask_build_config_quantities
from agent_bom.secret_scanner import scan_content

MANIFEST = Path("app/.next/required-server-files.json")


@pytest.mark.parametrize("indent", [None, 2])
def test_known_quantities_preserve_offsets_and_other_values(indent):
    document = {
        "version": 1,
        "config": {
            "cacheLife": {"default": {"expire": 4294967294}},
            "experimental": {"imgOptMaxInputPixels": 268402689, "turbopackStaleOutputMaxAge": 604800000},
            "env": {"expire": 123456789, "password": "fixture-" + "credential-387"},
        },
    }
    source = json.dumps(document, indent=indent)
    masked = mask_build_config_quantities(source, MANIFEST)
    expected = source
    for value in (4294967294, 268402689, 604800000):
        expected = expected.replace(str(value), " " * len(str(value)))
    assert masked == expected
    findings = scan_content(source, MANIFEST, str(MANIFEST))
    assert {finding.category for finding in findings} == {"secret", "pii"}


@pytest.mark.parametrize(
    "source",
    [
        '{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":"123456789"}}}',
        '{"version":1,"config":{"other":{"imgOptMaxInputPixels":123456789}}}',
        '{"version":1,"config":{"cacheLife":{"expire":123456789}}}',
        '{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":true}}}',
        '{"version":2,"config":{"experimental":{"imgOptMaxInputPixels":123456789}}}',
        '{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":123456789}',
        "[]",
        '{"version":1,"config":null}',
        '{"version":1,"config":{}}' + " " * (1024 * 1024),
    ],
)
def test_unknown_quoted_invalid_and_oversized_values_remain_unchanged(source):
    assert mask_build_config_quantities(source, MANIFEST) == source


def test_duplicate_config_leaves_shadowed_object_visible():
    source = '{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":123456789}},"config":{"env":{}}}'
    assert mask_build_config_quantities(source, MANIFEST) == source


@pytest.mark.parametrize("path", ["app/required-server-files.json", "app/.next/data.json"])
def test_only_next_manifest_path_is_eligible(path):
    source = '{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":123456789}}}'
    assert mask_build_config_quantities(source, Path(path)) == source
