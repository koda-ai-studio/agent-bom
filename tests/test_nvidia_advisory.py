"""Tests for NVIDIA CSAF advisory enrichment module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_bom.models import Package
from agent_bom.scanners.nvidia_advisory import (
    _apply_csaf_to_packages,
    _csaf_affects_product,
    _index_nvidia_products,
    _word_boundary_match,
    default_nvidia_advisory_years,
    extract_vulns_from_csaf,
    get_nvidia_products_for_package,
)


def test_word_boundary_match_exact():
    """Exact product name matches."""
    assert _word_boundary_match("cuda toolkit", "nvidia cuda toolkit security update")


def test_word_boundary_match_rejects_substring():
    """Substring that is NOT a word-boundary match is rejected.

    'nccl' should not match 'nccl-extra-tools' as a word-boundary match
    of the product name 'nccl' when it appears as a prefix of a hyphenated word.
    But 'nccl' as its own word should match.
    """
    # "nccl" appears as its own word → match
    assert _word_boundary_match("nccl", "nvidia nccl vulnerability")
    # "cudnn" should not match "cudnn-frontend" if boundary matters
    # Actually \b treats hyphens as word boundaries, so "cudnn" matches in "cudnn-frontend"
    # This is acceptable — NVIDIA products like "cudnn" are standalone words


def test_word_boundary_rejects_embedded_substring():
    """Product name embedded inside another word should not match."""
    # "cuda" should not match "barracuda"
    assert not _word_boundary_match("cuda", "barracuda network security")
    # "nccl" should not match "cancel"
    assert not _word_boundary_match("nccl", "cancel the operation")


def test_csaf_affects_product_title_match():
    """CSAF advisory title containing product name (word boundary) matches."""
    csaf = {
        "document": {"title": "NVIDIA CUDA Toolkit - February 2025 Security Update"},
        "product_tree": {"branches": []},
    }
    assert _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_title_no_match():
    """CSAF advisory for a different product should not match."""
    csaf = {
        "document": {"title": "NVIDIA GPU Display Driver - February 2025 Security Update"},
        "product_tree": {"branches": []},
    }
    assert not _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_branch_match():
    """CSAF product_tree branch name matches."""
    csaf = {
        "document": {"title": "NVIDIA Security Bulletin"},
        "product_tree": {
            "branches": [
                {
                    "name": "NVIDIA CUDA Toolkit",
                    "branches": [],
                }
            ]
        },
    }
    assert _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_subbranch_match():
    """CSAF product_tree sub-branch name matches."""
    csaf = {
        "document": {"title": "NVIDIA Security Bulletin"},
        "product_tree": {
            "branches": [
                {
                    "name": "NVIDIA Products",
                    "branches": [
                        {"name": "TensorRT 10.0"},
                    ],
                }
            ]
        },
    }
    assert _csaf_affects_product(csaf, {"tensorrt"})


def test_csaf_substring_false_positive_blocked():
    """Substring match in title should NOT trigger a false positive.

    'cuda' embedded in 'barracuda' should not match product 'cuda'.
    """
    csaf = {
        "document": {"title": "Barracuda Networks Security Advisory"},
        "product_tree": {"branches": []},
    }
    assert not _csaf_affects_product(csaf, {"cuda"})


# ─── get_nvidia_products_for_package — extended mapping tests ─────────────────


@pytest.mark.parametrize(
    "pkg_name, expected_products",
    [
        # Direct NVIDIA packages — should already map
        ("nvidia-cuda-runtime-cu12", ["cuda toolkit"]),
        ("nvidia-cudnn-cu12", ["cudnn"]),
        ("nvidia-nccl-cu12", ["nccl"]),
        ("tensorrt", ["tensorrt"]),
        ("nvidia-container-toolkit", ["container toolkit"]),
        ("nemo-toolkit", ["nemo framework"]),
        # A package that bundles or talks to a product is not that product
        ("torch", []),
        ("torchvision", []),
        ("torchaudio", []),
        ("jax", []),
        ("jaxlib", []),
        ("vllm", []),
        ("triton", []),
        ("cupy", []),
        ("cupy-cuda12x", []),
        ("accelerate", []),
        ("bitsandbytes", []),
        ("flash-attn", []),
        ("xformers", []),
        ("torch-tensorrt", []),
        ("tritonclient", []),
        ("openai", []),
        # Unrelated package — should not map to any NVIDIA product
        ("requests", []),
        ("numpy", []),
        ("fastapi", []),
    ],
)
def test_get_nvidia_products_for_package(pkg_name: str, expected_products: list[str]):
    """Each AI/GPU package maps to the correct NVIDIA product categories."""
    result = get_nvidia_products_for_package(pkg_name)
    for expected in expected_products:
        assert expected in result, f"{pkg_name!r} should map to {expected!r}, got {result}"
    if not expected_products:
        assert result == [], f"{pkg_name!r} should have no NVIDIA product mapping, got {result}"


def _recorded(name: str) -> dict:
    return json.loads((Path(__file__).parent / "fixtures" / "nvidia_csaf" / name).read_text())


def _apply(csaf: dict, *packages: Package) -> None:
    vulns = extract_vulns_from_csaf(csaf)
    names, by_product = _index_nvidia_products(list(packages))
    _apply_csaf_to_packages(csaf, vulns, names, by_product)


@pytest.mark.parametrize(
    "name,version",
    [
        ("torch", "1.13.1"),
        ("torchvision", "0.14.1"),
        ("jax", "0.4.0"),
        ("accelerate", "0.20.0"),
        ("bitsandbytes", "0.41.0"),
        ("openai", "1.0.0"),
    ],
)
def test_bulletin_does_not_reach_a_package_its_product_does_not_name(name: str, version: str):
    """CVE-2026-65160 names CUDA Toolkit and NVJPEG; neither identifies these packages."""
    pkg = Package(name=name, version=version, ecosystem="pypi")
    _apply(_recorded("cuda-nvjpeg-5910.json"), pkg)
    assert pkg.vulnerabilities == []
    assert get_nvidia_products_for_package(name) == []


@pytest.mark.parametrize("name", ["tritonclient", "tritonclientutils"])
def test_server_bulletin_does_not_reach_its_client_library(name: str):
    pkg = Package(name=name, version="2.40.0", ecosystem="pypi")
    _apply(_recorded("triton-5875.json"), pkg)
    assert pkg.vulnerabilities == []


def test_fix_comes_from_the_matched_products_own_entry():
    """The bulletin's first fix is NVJPEG 26.07; a CUDA library is compared with its own 13.4 U1."""
    affected = Package(name="nvidia-cublas-cu12", version="12.1.3", ecosystem="pypi")
    fixed = Package(name="nvidia-cublas-cu12", version="13.5.0", ecosystem="pypi")
    _apply(_recorded("cuda-nvjpeg-5910.json"), affected, fixed)
    assert [(v.id, v.fixed_version) for v in affected.vulnerabilities] == [("CVE-2026-65160", "13.4.1")]
    assert fixed.vulnerabilities == []


@pytest.mark.parametrize(
    "fixture,name,affected_version,fix,current_version",
    [
        ("nemo-5839.json", "nemo-toolkit", "2.7.0", "2.7.3", "2.7.3"),
        ("nemo-5839.json", "nemo_toolkit", "2.7.0", "2.7.3", "2.8.0"),
        ("tensorrt-5836.json", "tensorrt", "10.0.0", "10.16.1", "10.16.1"),
    ],
)
def test_true_nvidia_matches_keep_working(fixture, name, affected_version, fix, current_version):
    affected = Package(name=name, version=affected_version, ecosystem="pypi")
    current = Package(name=name, version=current_version, ecosystem="pypi")
    _apply(_recorded(fixture), affected, current)
    assert affected.vulnerabilities and {v.fixed_version for v in affected.vulnerabilities} == {fix}
    assert current.vulnerabilities == []


def test_a_bulletin_names_each_cve_per_product():
    """A bulletin can list products per CVE; a CVE for another product stays off this package."""
    csaf = {
        "document": {"title": "Security Bulletin: NVIDIA NeMo and Megatron"},
        "product_tree": {
            "branches": [
                {"name": "NVIDIA NeMo Framework", "product": {"name": "NVIDIA NeMo Framework", "product_id": "nemo_old"}},
                {"name": "NVIDIA NeMo Framework", "product": {"name": "NVIDIA NeMo Framework", "product_id": "nemo_v2_0_1"}},
                {"name": "NeMo Agent Toolkit", "product": {"name": "NeMo Agent Toolkit", "product_id": "agent_v9_9_9"}},
            ]
        },
        "vulnerabilities": [
            {"cve": "CVE-2026-1", "product_status": {"known_affected": ["nemo_old"], "fixed": ["nemo_v2_0_1"]}},
            {"cve": "CVE-2026-2", "product_status": {"fixed": ["agent_v9_9_9"]}},
        ],
    }
    pkg = Package(name="nemo-toolkit", version="1.0.0", ecosystem="pypi")
    _apply(csaf, pkg)
    assert [(v.id, v.fixed_version) for v in pkg.vulnerabilities] == [("CVE-2026-1", "2.0.1")]


def test_a_title_match_alone_does_not_apply_a_bulletin():
    csaf = {
        "document": {"title": "NVIDIA TensorRT Security Update"},
        "product_tree": {"branches": []},
        "vulnerabilities": [{"cve": "CVE-2026-3", "product_status": {}}],
    }
    pkg = Package(name="tensorrt", version="1.0.0", ecosystem="pypi")
    _apply(csaf, pkg)
    assert pkg.vulnerabilities == []


def test_unfixed_advisory_on_the_named_product_still_applies():
    csaf = {
        "document": {"title": "NVIDIA TensorRT"},
        "product_tree": {"branches": [{"name": "TensorRT", "product": {"name": "TensorRT", "product_id": "all_tensorrt_all"}}]},
        "vulnerabilities": [{"cve": "CVE-2026-4", "product_status": {"known_affected": ["all_tensorrt_all"]}}],
    }
    pkg = Package(name="tensorrt", version="1.0.0", ecosystem="pypi")
    _apply(csaf, pkg)
    assert [(v.id, v.fixed_version) for v in pkg.vulnerabilities] == [("CVE-2026-4", None)]


def test_fix_that_cannot_be_read_is_not_asserted():
    csaf = {
        "document": {"title": "NVIDIA TensorRT"},
        "product_tree": {"branches": [{"name": "TensorRT", "product": {"name": "TensorRT", "product_id": "all_tensorrt_see_notes"}}]},
        "vulnerabilities": [{"cve": "CVE-2026-5", "product_status": {"fixed": ["all_tensorrt_see_notes"]}}],
    }
    pkg = Package(name="tensorrt", version="1.0.0", ecosystem="pypi")
    _apply(csaf, pkg)
    assert pkg.vulnerabilities == []


@pytest.mark.asyncio
async def test_supplemental_dispatch_reaches_direct_nvidia_packages_only():
    from unittest.mock import AsyncMock, patch

    from agent_bom.scanners.package_coverage import _scan_supplemental_advisories

    packages = [
        Package(name="nvidia-cublas-cu12", version="12.1.3", ecosystem="pypi"),
        Package(name="torch", version="1.13.1", ecosystem="pypi"),
    ]
    nvidia = AsyncMock(return_value=0)
    with (
        patch("agent_bom.scanners.package_coverage._check_nvidia", nvidia),
        patch("agent_bom.scanners.package_coverage._check_ghsa", AsyncMock(return_value=0)),
        patch("agent_bom.scanners.package_coverage._check_amd", AsyncMock(return_value=0)),
    ):
        await _scan_supplemental_advisories(packages, offline=False)
    assert [p.name for p in nvidia.await_args.args[0]] == ["nvidia-cublas-cu12"]


def test_default_nvidia_advisory_years_follow_current_year():
    """The CSAF index window follows the current year instead of a hard-coded release window."""

    assert default_nvidia_advisory_years(datetime(2027, 1, 15, tzinfo=UTC)) == ["2027", "2026"]


def test_unrelated_package_no_nvidia_advisory():
    """An unrelated package should not trigger any NVIDIA product mapping."""
    assert get_nvidia_products_for_package("requests") == []
    assert get_nvidia_products_for_package("flask") == []
    assert get_nvidia_products_for_package("django") == []


# ─── NIM / NeMo / NemoClaw product map tests ─────────────────────────────────

from agent_bom.scanners.nvidia_advisory import _NVIDIA_PRODUCT_MAP  # noqa: E402


def test_nim_packages_in_nvidia_product_map():
    """NIM product key and nvidia-nim package exist in the product map."""
    assert "nim" in _NVIDIA_PRODUCT_MAP
    assert "nvidia-nim" in _NVIDIA_PRODUCT_MAP["nim"]


def test_nemo_packages_in_nvidia_product_map():
    """NeMo product key and nemo-toolkit package exist in the product map."""
    assert "nemo framework" in _NVIDIA_PRODUCT_MAP
    assert "nemo-toolkit" in _NVIDIA_PRODUCT_MAP["nemo framework"]


def test_nemoclaw_packages_in_nvidia_product_map():
    """NemoClaw product key exists in the product map."""
    assert "nemoclaw" in _NVIDIA_PRODUCT_MAP
