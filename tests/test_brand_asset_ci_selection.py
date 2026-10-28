"""Brand source and renderer edits must run provenance checks before merge."""

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import select_targeted_tests


@pytest.mark.parametrize(
    "source",
    [
        "README.md",
        "docs/images/vendor/provenance.json",
        "docs/images/vendor/new-logo.svg",
        "docs/images/integrations-manifest.json",
        "docs/images/social-preview.svg",
        "scripts/render_social_preview_svg.py",
        "scripts/social_preview_coverage.py",
    ],
)
def test_brand_edits_select_provenance_and_layout(tmp_path: Path, source: str) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_vendor_visual_provenance.py",
            "test_social_preview_layout.py",
            "test_integrations_manifest.py",
        )
    )
    for path in expected:
        path.parent.mkdir(exist_ok=True)
        path.write_text("def test_contract(): pass\n")
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected
