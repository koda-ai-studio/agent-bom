"""Per-finding work on a large image scan must scale with distinct values, not findings.

One kernel-header package on a Debian image carries thousands of CVEs. Every
finding repeats the same package evidence (layer attribution, provenance), so
redaction work has to be paid once per distinct string rather than once per
finding.
"""

from __future__ import annotations

import pytest

from agent_bom import security
from agent_bom.domain.package_model import PackageOccurrence
from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability


def _kernel_package() -> Package:
    package = Package(
        name="linux-libc-dev",
        version="6.12.48-1",
        ecosystem="deb",
        distro_name="debian",
        distro_version="13",
        is_direct=False,
    )
    package.occurrences = [
        PackageOccurrence(
            layer_index=index,
            layer_id=f"sha256:{index:064x}",
            package_path="var/lib/dpkg/status",
            layer_path=f"blobs/sha256/{index:064x}",
            created_by=f"/bin/sh -c apt-get install -y build-essential # layer {index}",
        )
        for index in range(6)
    ]
    return package


def _blast_radii(count: int) -> list[BlastRadius]:
    package = _kernel_package()
    return [
        BlastRadius(
            vulnerability=Vulnerability(id=f"CVE-2026-{10_000 + index}", summary="kernel issue", severity=Severity.MEDIUM),
            package=package,
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )
        for index in range(count)
    ]


def test_shared_package_evidence_is_redacted_once_per_distinct_string(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    real = security._sanitize_text

    def counting(value: object, max_len: int = 1000) -> str:
        nonlocal calls
        calls += 1
        return real(value, max_len)

    monkeypatch.setattr(security, "_sanitize_text", counting)

    with security.sanitize_text_memo():
        [blast_radius_to_finding(br) for br in _blast_radii(20)]
        after_twenty = calls
        [blast_radius_to_finding(br) for br in _blast_radii(400)]
    extra_for_380_more = calls - after_twenty

    assert after_twenty > 0
    # Only each new CVE's own strings are new work; the shared package evidence
    # is not. Unmemoized, 380 more findings cost 19x the first twenty.
    assert extra_for_380_more <= after_twenty


def test_memoized_sanitize_text_matches_unmemoized_redaction() -> None:
    samples = [
        "plain text",
        "token=ghp_" + "a" * 36,
        "postgresql://user:pass@db.internal/app",
        "owner alice@corp.example on call",
        "\x1b[31mred\x1b[0m  spaced",
        "x" * 700,
    ]
    expected = [(security.sanitize_text(sample), security.sanitize_text(sample, max_len=20)) for sample in samples]
    with security.sanitize_text_memo():
        for _ in range(2):
            got = [(security.sanitize_text(sample), security.sanitize_text(sample, max_len=20)) for sample in samples]
            assert got == expected


def test_memo_is_bounded_and_released_after_the_scan() -> None:
    with security.sanitize_text_memo() as memo:
        for index in range(security.SANITIZE_TEXT_MEMO_LIMIT + 50):
            security.sanitize_text(f"value-{index}")
        security.sanitize_text("y" * (security.SANITIZE_TEXT_MEMO_MAX_INPUT + 1))
        security.sanitize_text(12345)
        assert len(memo) == security.SANITIZE_TEXT_MEMO_LIMIT
        with security.sanitize_text_memo() as nested:
            assert nested is memo
    assert memo == {}
    assert security._SANITIZE_TEXT_MEMO.get() is None


def test_cli_scan_pipeline_runs_every_stage_under_one_memo() -> None:
    from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
    from agent_bom.cli.agents.scan_pipeline.runner import run_scan

    seen: list[object] = []

    def stage(_opts: object, _st: object) -> None:
        seen.append(security._SANITIZE_TEXT_MEMO.get())

    run_scan(ScanOptions.__new__(ScanOptions), stages=(("a", stage), ("b", stage)))

    assert seen[0] is not None
    assert seen[0] is seen[1]
    assert security._SANITIZE_TEXT_MEMO.get() is None


def test_api_scan_job_runs_every_stage_under_one_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import pipeline
    from agent_bom.api.scan_context import ScanStage

    seen: list[object] = []

    def stage(_ctx: object) -> bool:
        seen.append(security._SANITIZE_TEXT_MEMO.get())
        return len(seen) == 2

    monkeypatch.setattr(pipeline, "SCAN_STAGES", (ScanStage("a", stage), ScanStage("b", stage)))
    monkeypatch.setattr(pipeline, "_begin_job", lambda job, lock: True)
    monkeypatch.setattr(pipeline, "_finalize", lambda ctx: None)
    monkeypatch.setattr(pipeline, "ScanPipeline", lambda job, lock: None)

    pipeline._run_scan_sync(type("Job", (), {"job_id": "memo-scope"})())

    assert seen[0] is not None
    assert seen[0] is seen[1]
    assert security._SANITIZE_TEXT_MEMO.get() is None
