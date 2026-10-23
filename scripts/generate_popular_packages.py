#!/usr/bin/env python3
"""Rebuild ``src/agent_bom/data/popular_packages.json``, the typosquat reference.

The typosquat check compares a package name against a small set of *targets*:
the names attackers imitate. Targets are the most-installed names per
ecosystem, taken from public download and dependent rankings:

* PyPI: the top ``PYPI_TARGETS`` projects by 30-day downloads from the
  top-pypi-packages dataset (hugovk.github.io/top-pypi-packages, built from the
  PyPI BigQuery download table).
* npm: the top ``NPM_DEPENDENT_TARGETS`` unscoped packages by dependent count
  plus the top ``NPM_DOWNLOAD_TARGETS`` by weekly downloads, from the
  ``npm-high-impact`` package at a pinned version. Dependent count ranks the
  names people declare directly (``cross-env``, ``express``), which is what a
  squatter imitates; raw downloads are dominated by transitive helpers.
* Plus a short curated list of names that were the target of a documented
  typosquat campaign but sit below the ranking cut (``CAMPAIGN_TARGETS``).

A popular project can itself sit one edit away from a target (``psycopg2`` and
``psycopg``, ``enquirer`` and ``inquirer``). Every name in the *full* rankings
that the check would flag is recorded under ``established`` and is never
reported: a project with that download or dependent count is not a squat.
Only those collisions are stored, so the file stays small.

This script needs network access; the scanner and the guard hook never do. Run
it when the rankings should be refreshed and commit the result together with
``python scripts/generate_guard_data.py``::

    python scripts/generate_popular_packages.py
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

TARGET = ROOT / "src" / "agent_bom" / "data" / "popular_packages.json"

PYPI_TARGETS = 300
NPM_DEPENDENT_TARGETS = 250
NPM_DOWNLOAD_TARGETS = 100
NPM_HIGH_IMPACT_VERSION = "1.13.0"
PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = "https://cdn.jsdelivr.net/npm/npm-high-impact@{version}/lib/{name}.js"

# Names below the ranking cut that were imitated in a documented campaign or
# that agent-bom already treated as targets before the rankings were adopted.
CAMPAIGN_TARGETS: dict[str, tuple[str, ...]] = {
    "npm": (
        "babel-core",
        "bcrypt",
        "dayjs",
        "helmet",
        "inquirer",
        "jsonwebtoken",
        "mongoose",
        "moment",
        "next",
        "nodemailer",
        "passport",
        "sequelize",
        "socket.io",
        "yup",
    ),
    "pypi": (
        "ansible",
        "celery",
        "django",
        "fabric",
        "jellyfish",
        "tensorflow",
        "torch",
    ),
}


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "agent-bom-popular-packages"})
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310 - fixed https URLs
        return bytes(response.read())


def _npm_ranking(name: str) -> list[str]:
    text = _fetch(NPM_URL.format(version=NPM_HIGH_IMPACT_VERSION, name=name)).decode("utf-8")
    return [n for n in re.findall(r"^\s+'([^']+)',?$", text, re.M) if not n.startswith("@")]


def build() -> dict[str, object]:
    from agent_bom.malicious import canonical_name, typosquat_target

    pypi_doc = json.loads(_fetch(PYPI_URL))
    pypi_rank = list(dict.fromkeys(canonical_name(row["project"], "pypi") for row in pypi_doc["rows"]))
    npm_dependents = _npm_ranking("top-dependent")
    npm_downloads = _npm_ranking("top-download")

    targets = {
        "npm": set(npm_dependents[:NPM_DEPENDENT_TARGETS]) | set(npm_downloads[:NPM_DOWNLOAD_TARGETS]) | set(CAMPAIGN_TARGETS["npm"]),
        "pypi": set(pypi_rank[:PYPI_TARGETS]) | set(CAMPAIGN_TARGETS["pypi"]),
    }
    rankings = {"npm": list(dict.fromkeys(npm_dependents + npm_downloads)), "pypi": pypi_rank}
    established = {
        eco: sorted(n for n in names if n not in targets[eco] and typosquat_target(n, eco, targets[eco], frozenset()))
        for eco, names in rankings.items()
    }
    return {
        "about": (
            "Typosquat reference for agent_bom.malicious and the agent-bom-guard hook. "
            "Regenerate with scripts/generate_popular_packages.py; the method is in its docstring."
        ),
        "sources": {
            "pypi": f"{PYPI_URL} (last_update {pypi_doc['last_update']}): top {PYPI_TARGETS} by 30-day downloads",
            "npm": (
                f"npm-high-impact@{NPM_HIGH_IMPACT_VERSION}: top {NPM_DEPENDENT_TARGETS} unscoped by dependents "
                f"and top {NPM_DOWNLOAD_TARGETS} by downloads"
            ),
            "curated": "CAMPAIGN_TARGETS in scripts/generate_popular_packages.py",
            "established": "names in the full rankings that sit within typosquat distance of a target",
        },
        "popular": {eco: sorted(names) for eco, names in sorted(targets.items())},
        "established": established,
    }


def main() -> int:
    TARGET.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
