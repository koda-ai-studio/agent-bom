"""Supplemental NVIDIA security advisory enrichment.

Fetches CSAF 2.0 advisories from NVIDIA's product-security GitHub repo and
matches them to packages a bulletin's product actually identifies.  This catches
NVIDIA CVEs that may not yet be indexed by OSV.dev's PyPI advisory database.
"""

from __future__ import annotations

import copy
import logging
import re
from datetime import UTC, datetime
from functools import cmp_to_key

import httpx

from agent_bom.cpe_match import cpe_applicability, cpe_identity
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.version_utils import compare_version_order, compare_versions

logger = logging.getLogger(__name__)

# GitHub raw URL for the NVIDIA product-security repo
_GITHUB_API = "https://api.github.com/repos/NVIDIA/product-security/contents"

# CSAF product names (normalised by ``_product_key``) mapped to the PyPI packages
# that ARE that product: NVIDIA's own redistributions of it. A package that links,
# bundles or talks to a product is not identified by a bulletin about that product:
# a CUDA Toolkit fix is not a torch release, and a Triton server fix is not a
# tritonclient release. Those packages get their advisories from their own feeds.
_NVIDIA_PRODUCT_MAP: dict[str, list[str]] = {
    "cuda toolkit": [
        "nvidia-cuda-runtime-cu11",
        "nvidia-cuda-runtime-cu12",
        "nvidia-cuda-cupti-cu11",
        "nvidia-cuda-cupti-cu12",
        "nvidia-cuda-nvrtc-cu11",
        "nvidia-cuda-nvrtc-cu12",
        "nvidia-cublas-cu11",
        "nvidia-cublas-cu12",
        "nvidia-cusolver-cu11",
        "nvidia-cusolver-cu12",
        "nvidia-cusparse-cu11",
        "nvidia-cusparse-cu12",
        "nvidia-cufft-cu11",
        "nvidia-cufft-cu12",
        "nvidia-curand-cu11",
        "nvidia-curand-cu12",
        "nvidia-nvjitlink-cu12",
    ],
    "cudnn": ["nvidia-cudnn-cu11", "nvidia-cudnn-cu12"],
    "nccl": ["nvidia-nccl-cu11", "nvidia-nccl-cu12"],
    "tensorrt": ["tensorrt", "nvidia-tensorrt"],
    "container toolkit": ["nvidia-container-toolkit"],
    "nvjpeg": [],  # Ships in images and the toolkit, not as a PyPI package
    "triton inference server": [],  # Ships as a container; tritonclient is a separate client library
    "nim": ["nvidia-nim"],
    "nemo framework": ["nemo-toolkit"],
    "megatron lm": ["megatron-core"],
    "nemoclaw": ["nemoclaw"],
    "morpheus": ["morpheus-sdk", "morpheus"],
    "rapids": ["cudf", "cuml", "cugraph", "raft-dask"],
}

# Reverse map: PyPI package name → NVIDIA product names it belongs to
_PYPI_TO_NVIDIA: dict[str, list[str]] = {}
for _product, _packages in _NVIDIA_PRODUCT_MAP.items():
    for _pkg in _packages:
        _PYPI_TO_NVIDIA.setdefault(_pkg.lower().replace("-", "_"), []).append(_product)


# NVD CPE products (``cpe:2.3:a:nvidia:<product>``) of GPU stack components
# found on hosts and images, mapped to the CSAF product names above.
_CPE_PRODUCT_TO_NVIDIA: dict[str, str] = {
    "gpu_display_driver": "gpu display driver",
    "cuda_toolkit": "cuda toolkit",
    "nvidia_container_toolkit": "container toolkit",
}
# CSAF ``product_status.fixed`` ids name the platform, product line and the
# release with underscores (``linuxr550_tesla_550_127_05``,
# ``linux_nvidia_container_toolkit_v1_16_2``). Only Linux ids of the product
# itself apply to a Linux host component.
_FIXED_ID_TOKENS: dict[str, tuple[str, ...]] = {
    "gpu display driver": ("geforce", "tesla", "quadro", "rtx"),
    "cuda toolkit": ("cuda_toolkit",),
    "container toolkit": ("container_toolkit",),
}
_EXCLUDED_ID_TOKENS = ("windows", "vgpu", "virtual_gpu", "guest_driver")
# ``13_4_u1`` is CUDA Toolkit "13.4 Update 1"; NVIDIA numbers that release 13.4.1.
_ID_VERSION_RE = re.compile(r"(?:^|_)[vr]?([0-9]+(?:_u?[0-9]+)+)$")


def _normalise(name: str) -> str:
    """Normalise package name for comparison (lowercase, underscores)."""
    return name.lower().replace("-", "_")


def _product_key(name: str) -> str:
    """A CSAF product name as ``_NVIDIA_PRODUCT_MAP`` spells it: ``NVIDIA® CUDA Toolkit`` -> ``cuda toolkit``."""
    words = re.sub(r"[®™]", "", name).replace("-", " ").lower().split()
    return " ".join(words[1:] if words[:1] == ["nvidia"] else words)


def get_nvidia_products_for_package(pkg_name: str) -> list[str]:
    """Return NVIDIA product names that a PyPI package maps to."""
    return _PYPI_TO_NVIDIA.get(_normalise(pkg_name), [])


def _identity_product(pkg: Package) -> str | None:
    """CSAF product for a component that carries an NVIDIA CPE identity."""
    identity = cpe_identity(pkg)
    if identity is None or identity[0] != "nvidia":
        return None
    return _CPE_PRODUCT_TO_NVIDIA.get(identity[1])


def nvidia_products_for(pkg: Package) -> list[str]:
    """CSAF products a scanned package belongs to, by name mapping or NVIDIA CPE identity."""
    products = list(get_nvidia_products_for_package(pkg.name))
    product = _identity_product(pkg)
    if product and product not in products:
        products.append(product)
    return products


def _id_version(product_id: str) -> str | None:
    match = _ID_VERSION_RE.search(str(product_id))
    return match[1].replace("_u", ".").replace("_", ".") if match else None


def _branch_fixed_version(fixed_ids: list[str], product: str, version: str) -> str | None:
    """The fix on the component's own release branch, or ``None`` when the advisory does not say."""
    tokens = _FIXED_ID_TOKENS.get(product, ())
    candidates = {
        fixed
        for product_id in fixed_ids
        if any(token in product_id for token in tokens) and not any(token in product_id for token in _EXCLUDED_ID_TOKENS)
        if (fixed := _id_version(product_id))
    }
    same_branch = [fixed for fixed in candidates if fixed.split(".")[0] == version.split(".")[0]]
    if same_branch:
        return min(same_branch, key=cmp_to_key(lambda a, b: compare_version_order(a, b, "generic") or 0))
    return next(iter(candidates)) if len(candidates) == 1 else None


def default_nvidia_advisory_years(now: datetime | None = None) -> list[str]:
    """Return recent advisory years without pinning the scanner to a release year."""

    current_year = (now or datetime.now(UTC)).year
    return [str(current_year), str(current_year - 1)]


def _parse_csaf_severity(scores: list[dict]) -> tuple[Severity, float | None]:
    """Extract severity and CVSS score from CSAF scores array."""
    for score_entry in scores:
        cvss = score_entry.get("cvss_v3") or score_entry.get("cvss_v4") or {}
        if cvss.get("baseScore") is not None:
            from agent_bom.core.cvss import cvss_to_severity, normalize_cvss_score

            base_score = normalize_cvss_score(cvss["baseScore"])
            return cvss_to_severity(base_score), base_score
    return Severity.MEDIUM, None


def _extract_fixed_version(vuln: dict) -> str | None:
    """Extract fixed version from CSAF product_status.fixed entries."""
    fixed = vuln.get("product_status", {}).get("fixed", [])
    if fixed:
        # Product IDs often contain version info like "CUDA Toolkit 12.9 Update 1"
        for product_id in fixed:
            m = re.search(r"(\d+\.\d+[\w. ]*)", str(product_id))
            if m:
                return m.group(1).strip()
        for product_id in fixed:
            version = _id_version(product_id)
            if version:
                return version
    return None


async def fetch_nvidia_advisory_index(
    years: list[str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[dict]:
    """Fetch the list of advisory folders from NVIDIA's GitHub repo.

    Returns list of dicts with 'name' and 'path' keys.
    Only fetches recent years by default.
    """
    if years is None:
        years = default_nvidia_advisory_years()

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=15.0)
        close_client = True

    advisories = []
    try:
        for year in years:
            resp = await request_with_retry(
                client,
                "GET",
                f"{_GITHUB_API}/{year}",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp and resp.status_code == 200:
                for item in resp.json():
                    if item.get("type") == "dir":
                        advisories.append(
                            {
                                "id": item["name"],
                                "path": item["path"],
                                "url": f"https://raw.githubusercontent.com/NVIDIA/product-security/main/{item['path']}/{item['name']}.json",
                            }
                        )
    finally:
        if close_client:
            await client.aclose()

    return advisories


async def fetch_nvidia_csaf(
    advisory_url: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Fetch a single NVIDIA CSAF advisory JSON."""
    resp = await request_with_retry(client, "GET", advisory_url)
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except (ValueError, KeyError):
            return None
    return None


def _word_boundary_match(product: str, text: str) -> bool:
    """Check if product name appears as a whole word/phrase in text."""
    return bool(re.search(rf"\b{re.escape(product)}\b", text))


def _csaf_affects_product(csaf: dict, product_names: set[str]) -> bool:
    """Check if a CSAF advisory affects any of the given NVIDIA product names.

    Recursively traverses product_tree.branches at any depth — NVIDIA CSAF documents
    can nest product entries more than 2 levels deep.
    """
    title = (csaf.get("document", {}).get("title", "") or "").lower()
    for product in product_names:
        if _word_boundary_match(product, title):
            return True

    def _search_branches(branches: list, depth: int = 0) -> bool:
        if depth > 8:  # safety cap — CSAF docs are never this deep
            return False
        for branch in branches:
            _name = (branch.get("name", "") or "").lower()
            for product in product_names:
                if _word_boundary_match(product, _name):
                    return True
            if _search_branches(branch.get("branches", []), depth + 1):
                return True
        return False

    return _search_branches(csaf.get("product_tree", {}).get("branches", []))


def extract_vulns_from_csaf(csaf: dict) -> list[Vulnerability]:
    """Extract Vulnerability objects from a CSAF advisory."""
    vulns = []
    for vuln_data in csaf.get("vulnerabilities", []):
        cve_id = vuln_data.get("cve", "")
        if not cve_id:
            continue

        severity, cvss_score = _parse_csaf_severity(vuln_data.get("scores", []))
        summary = ""
        for note in vuln_data.get("notes", []):
            if note.get("category") in ("description", "summary"):
                summary = note.get("text", "")[:200]
                break

        cwe = vuln_data.get("cwe", {})
        cwe_ids = [cwe["id"]] if cwe.get("id") else []

        fixed_version = _extract_fixed_version(vuln_data)

        refs = []
        for ref in vuln_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)

        vulns.append(
            Vulnerability(
                id=cve_id,
                summary=summary or f"NVIDIA Security Advisory ({cve_id})",
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=fixed_version,
                references=refs,
                cwe_ids=cwe_ids,
                advisory_sources=["nvidia_csaf"],
            )
        )
    return vulns


def _index_nvidia_products(packages: list[Package]) -> tuple[set[str], dict[str, list[Package]]]:
    """Map each relevant NVIDIA product name to the scanned packages it covers."""
    product_names: set[str] = set()
    pkg_by_product: dict[str, list[Package]] = {}
    for pkg in packages:
        products = nvidia_products_for(pkg)
        for product in products:
            product_names.add(product)
            pkg_by_product.setdefault(product, []).append(pkg)
    return product_names, pkg_by_product


def _add_new_vulns(pkg: Package, csaf_vulns: list[Vulnerability], *, compare: bool = True) -> int:
    """Attach advisory vulns not already on ``pkg`` (by ID or alias); return the count added."""
    added = 0
    existing_ids = {v.id for v in pkg.vulnerabilities}
    for v in pkg.vulnerabilities:
        existing_ids.update(v.aliases)
    for vuln in csaf_vulns:
        if vuln.id in existing_ids:
            continue
        # Skip if the installed version is already at or beyond
        # the fix — same guard as ghsa_advisory.py.
        if compare and vuln.fixed_version and pkg.version:
            if not compare_versions(pkg.version, vuln.fixed_version, pkg.ecosystem):
                continue
        pkg.vulnerabilities.append(vuln)
        existing_ids.add(vuln.id)
        added += 1
    return added


def _identified_component_vulns(csaf: dict, csaf_vulns: list[Vulnerability], pkg: Package, product: str) -> list[Vulnerability]:
    """Per-component copies with the fix from the component's own Linux release branch.

    A component identified by NVIDIA CPE is compared at its upstream release;
    an advisory without a fix on that branch is not asserted against it.
    """
    version = cpe_applicability(pkg)[0] or pkg.version
    fixed_by_cve = {str(v.get("cve", "")): list(v.get("product_status", {}).get("fixed", [])) for v in csaf.get("vulnerabilities", [])}
    out: list[Vulnerability] = []
    for vuln in csaf_vulns:
        fixed = _branch_fixed_version(fixed_by_cve.get(vuln.id, []), product, version)
        if fixed is None or not compare_versions(version, fixed, "generic"):
            continue
        scoped = copy.deepcopy(vuln)
        scoped.fixed_version = fixed
        out.append(scoped)
    return out


def _csaf_product_ids(csaf: dict) -> dict[str, str]:
    """Each CSAF ``product_id`` mapped to its product's normalised name."""
    names: dict[str, str] = {}

    def walk(branches: list, depth: int = 0) -> None:
        if depth > 8:
            return
        for branch in branches:
            product = branch.get("product") or {}
            if product.get("product_id"):
                names[str(product["product_id"])] = _product_key(str(branch.get("name") or product.get("name") or ""))
            walk(branch.get("branches") or [], depth + 1)

    walk((csaf.get("product_tree") or {}).get("branches") or [])
    return names


def _product_vulns(csaf: dict, csaf_vulns: list[Vulnerability], product: str) -> list[Vulnerability]:
    """Copies of the CVEs whose ``product_status`` names ``product``, each with that product's own fix.

    A bulletin can list several products; one's fix says nothing about another.
    A fix that cannot be read as a version cannot be compared, so it is not asserted.
    """
    names = _csaf_product_ids(csaf)
    by_cve = {vuln.id: vuln for vuln in csaf_vulns}
    out: list[Vulnerability] = []
    for vuln_data in csaf.get("vulnerabilities", []):
        vuln = by_cve.get(str(vuln_data.get("cve", "")))
        status = vuln_data.get("product_status") or {}
        fixed_ids = [str(pid) for pid in status.get("fixed") or [] if names.get(str(pid)) == product]
        affected = any(names.get(str(pid)) == product for pid in status.get("known_affected") or [])
        if vuln is None or not (affected or fixed_ids):
            continue
        fixes = sorted(
            {fix for pid in fixed_ids if (fix := _id_version(pid))},
            key=cmp_to_key(lambda a, b: compare_version_order(a, b, "generic") or 0),
        )
        if fixed_ids and not fixes:
            continue
        scoped = copy.deepcopy(vuln)
        scoped.fixed_version = fixes[0] if fixes else None
        out.append(scoped)
    return out


def _apply_csaf_to_packages(
    csaf: dict,
    csaf_vulns: list[Vulnerability],
    product_names: set[str],
    pkg_by_product: dict[str, list[Package]],
) -> int:
    """Assign one advisory's vulns to matching packages (deduplicate by CVE ID)."""
    added = 0
    for product, pkgs in pkg_by_product.items():
        if product not in product_names:
            continue
        # Check if this advisory affects this product
        if not _csaf_affects_product(csaf, {product}):
            continue
        for pkg in pkgs:
            if _identity_product(pkg) == product:
                added += _add_new_vulns(pkg, _identified_component_vulns(csaf, csaf_vulns, pkg, product), compare=False)
            else:
                added += _add_new_vulns(pkg, _product_vulns(csaf, csaf_vulns, product))
    return added


async def check_nvidia_advisories(
    packages: list[Package],
    max_advisories: int = 20,
) -> int:
    """Check NVIDIA packages against NVIDIA's security advisories.

    Fetches recent CSAF advisories from NVIDIA's GitHub repo and
    cross-references against the given packages.  Only processes
    advisories relevant to the NVIDIA products matching the packages.

    Returns count of new vulnerabilities found.
    """
    # Determine which NVIDIA products are relevant
    product_names, pkg_by_product = _index_nvidia_products(packages)

    if not product_names:
        return 0

    logger.info("NVIDIA advisory check for products: %s", product_names)

    total_new = 0
    async with create_client(timeout=15.0) as client:
        # Fetch advisory index
        advisories = await fetch_nvidia_advisory_index(client=client)
        if not advisories:
            logger.debug("No NVIDIA advisories found")
            return 0

        # Process most recent advisories first (higher ID = more recent)
        advisories.sort(key=lambda a: a["id"], reverse=True)

        checked = 0
        for adv in advisories:
            if checked >= max_advisories:
                break

            csaf = await fetch_nvidia_csaf(adv["url"], client)
            if not csaf:
                continue

            checked += 1

            if not _csaf_affects_product(csaf, product_names):
                continue

            csaf_vulns = extract_vulns_from_csaf(csaf)
            if not csaf_vulns:
                continue

            total_new += _apply_csaf_to_packages(csaf, csaf_vulns, product_names, pkg_by_product)

    if total_new:
        logger.info("NVIDIA advisories: found %d new CVE(s)", total_new)

    return total_new
