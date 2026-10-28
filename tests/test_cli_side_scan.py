"""Tests for the ``agent-bom cloud side-scan`` CLI command.

The side-scan engine (:mod:`agent_bom.cloud.side_scan`) was fully built and
unit-tested but had no CLI caller, so it was unreachable. These tests pin the
new command's plumbing:

- the command invokes ``run_side_scan`` with the option values mapped to kwargs,
- results render in a Rich table (metadata only — secret type/location, never
  values),
- a disabled opt-in flag surfaces the actionable message and exits non-zero
  (never a raw traceback).

``run_side_scan`` is monkeypatched throughout — no real AWS, no asyncio plumbing
under test beyond the command's own ``asyncio.run`` call.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import agent_bom.cli._cloud_group as cg
from agent_bom.cloud.side_scan import (
    SideScanDisabledError,
    SideScanResult,
    SideScanSecret,
)


def test_side_scan_invokes_run_side_scan_with_mapped_kwargs(monkeypatch):
    captured: dict = {}

    async def fake_run_side_scan(**kwargs):
        captured.update(kwargs)
        return [
            SideScanResult(
                instance_id="i-target",
                volume_id="vol-target",
                snapshot_id="snap-1",
                vulnerability_count=2,
                cleaned_up=True,
            )
        ]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)

    result = CliRunner().invoke(
        cg.side_scan_cmd,
        [
            "--volume-id",
            "vol-target",
            "--instance-id",
            "i-target",
            "--collector-instance-id",
            "i-collector",
            "--availability-zone",
            "us-east-1a",
            "--region",
            "us-east-1",
            "--no-secrets",
            "--no-sweep-orphans",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["volume_id"] == "vol-target"
    assert captured["instance_id"] == "i-target"
    assert captured["collector_instance_id"] == "i-collector"
    assert captured["availability_zone"] == "us-east-1a"
    assert captured["region"] == "us-east-1"
    # --no-secrets -> scan_secrets_enabled=False; --no-sweep-orphans -> sweep_orphans=False
    assert captured["scan_secrets_enabled"] is False
    assert captured["sweep_orphans"] is False
    # Summary table rendered the instance + snapshot + cleanup status
    # (volume may ellipsize under narrow COLUMNS).
    assert "i-target" in result.output
    assert "snap-1" in result.output


def test_side_scan_defaults_enable_secrets_and_sweep(monkeypatch):
    captured: dict = {}

    async def fake_run_side_scan(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)

    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-x"])
    assert result.exit_code == 0, result.output
    assert captured["scan_secrets_enabled"] is True
    assert captured["sweep_orphans"] is True
    # No targets -> a clear, non-crashing note.
    assert "No target volumes resolved" in result.output


def test_side_scan_renders_redacted_secrets_only(monkeypatch):
    async def fake_run_side_scan(**kwargs):
        return [
            SideScanResult(
                volume_id="vol-target",
                snapshot_id="snap-1",
                secrets=[
                    SideScanSecret(
                        secret_type="aws_access_key",
                        file_path="/app/app.env",
                        line_number=1,
                        severity="high",
                        category="cloud",
                    )
                ],
                cleaned_up=True,
            )
        ]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-target"])
    assert result.exit_code == 0, result.output
    assert "aws_access_key" in result.output
    assert "/app/app.env" in result.output


def test_side_scan_disabled_flag_exits_nonzero_with_actionable_message(monkeypatch):
    async def fake_run_side_scan(**kwargs):
        raise SideScanDisabledError(
            "Disk side-scan is opt-in and currently OFF. To enable it, set AGENT_BOM_SIDESCAN=1, "
            "apply the scoped snapshot role, and provide an in-account collector instance."
        )

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-x"])

    assert result.exit_code != 0
    assert "AGENT_BOM_SIDESCAN" in result.output
    assert "opt-in" in result.output.lower()
    # Never a raw traceback.
    assert "Traceback" not in result.output


def test_side_scan_command_registered_on_group():
    assert "side-scan" in cg.cloud_group.commands
    assert "side-scan-capabilities" in cg.cloud_group.commands


@pytest.mark.parametrize(
    ("provider", "location"),
    [("azure", "eastus"), ("gcp", "us-central1-a")],
)
def test_side_scan_azure_gcp_dispatch_to_provider_executor(monkeypatch, provider: str, location: str):
    """--provider azure|gcp is accepted and dispatches to the shipped executor."""
    from agent_bom.cloud.side_scan_targets import CloudSideScanExecutionResult

    captured: dict = {}

    async def fake_run_provider_side_scan(**kwargs):
        captured.update(kwargs)
        return [
            CloudSideScanExecutionResult(
                provider=provider,
                target_type="managed_disk" if provider == "azure" else "persistent_disk",
                target_id="disk-1",
                account_id="acct-1",
                location=location,
                execution_id="exec-123",
                execution_status="scan_complete",
                cleanup_status="complete",
                snapshot_id="snap-1",
                scan_disk_id="scan-1",
                vulnerability_count=3,
                cleaned_up=True,
            )
        ]

    monkeypatch.setattr(
        "agent_bom.cloud.side_scan_targets.run_provider_side_scan",
        fake_run_provider_side_scan,
    )

    args = [
        "--provider",
        provider,
        "--volume-id",
        "disk-1",
        "--account-id",
        "acct-1",
        "--collector-instance-id",
        "collector-1",
        "--availability-zone",
        location,
        "--tenant-id",
        "tenant-a",
    ]
    if provider == "azure":
        args += ["--collector-resource-group", "collectors"]

    result = CliRunner().invoke(cg.side_scan_cmd, args)

    assert result.exit_code == 0, result.output
    assert captured["provider"] == provider
    assert captured["target_id"] == "disk-1"
    # Only the operator-run CLI may use the provider default credential chain.
    assert captured["allow_ambient"] is True
    assert "client_factory" not in captured
    assert captured["account_id"] == "acct-1"
    assert captured["collector_id"] == "collector-1"
    assert captured["location"] == location
    assert captured["tenant_id"] == "tenant-a"
    if provider == "azure":
        assert captured["collector_resource_group"] == "collectors"
    # Rendered honestly: snapshot + cleanup status + no clean-workload claim.
    assert "snap-1" in result.output
    assert "exec-123" in result.output
    assert "scan complete" in result.output.lower()
    assert "cleanup" in result.output.lower()
    assert "complete" in result.output.lower()
    assert "clean-workload" in result.output.lower()
    assert "Traceback" not in result.output


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_side_scan_provider_config_error_is_actionable_not_traceback(monkeypatch, provider: str):
    """A provider config/credential fault surfaces an actionable message, exit 1, no traceback."""
    from agent_bom.cloud.side_scan import SideScanConfigError

    async def fake_run_provider_side_scan(**kwargs):
        raise SideScanConfigError(f"{provider} side-scan requires the {provider} extra. Install with: pip install 'agent-bom[...]'")

    monkeypatch.setattr(
        "agent_bom.cloud.side_scan_targets.run_provider_side_scan",
        fake_run_provider_side_scan,
    )

    result = CliRunner().invoke(
        cg.side_scan_cmd,
        ["--provider", provider, "--volume-id", "disk-1", "--account-id", "a", "--collector-instance-id", "c", "--availability-zone", "z"],
    )
    assert result.exit_code == 1, result.output
    assert "side-scan unavailable" in result.output.lower()
    assert provider in result.output.lower()
    assert "Traceback" not in result.output


def test_side_scan_capabilities_json():
    result = CliRunner().invoke(cg.side_scan_capabilities_cmd, ["-f", "json"])
    assert result.exit_code == 0, result.output
    assert '"provider": "aws"' in result.output
    assert '"provider": "azure"' in result.output
    assert '"provider": "gcp"' in result.output
    # Azure/GCP now ship a CLI executor, but no live smoke is claimed for any provider.
    normalized = result.output.replace("False", "false").replace("True", "true")
    assert normalized.count('"cli_available": true') == 3
    assert normalized.count('"credentialed_smoke": false') == 3


# ── Packages and CVEs per VM, JSON output, machine images ──────────────────────


def _vulnerable_result(**kwargs):
    from agent_bom.models import Package, Severity, Vulnerability

    pkg = Package(
        name="openssl",
        version="3.0.2",
        ecosystem="deb",
        vulnerabilities=[Vulnerability(id="CVE-2099-0001", summary="synthetic", severity=Severity.HIGH)],
    )
    return SideScanResult(
        instance_id="i-target", volume_id="vol-target", account_id="000000000000", region="us-east-1", packages=[pkg], **kwargs
    )


def test_side_scan_console_lists_vulnerable_packages_per_vm(monkeypatch):
    async def fake_run_side_scan(**kwargs):
        return [_vulnerable_result(cleaned_up=True)]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-target"], env={"COLUMNS": "200"})

    assert result.exit_code == 0, result.output
    assert "CVE-2099-0001" in result.output
    assert "openssl" in result.output


def test_side_scan_json_matches_the_report_record(monkeypatch):
    import json

    from agent_bom.cloud.side_scan_inventory import side_scan_record

    async def fake_run_side_scan(**kwargs):
        return [_vulnerable_result(cleaned_up=True)]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-target", "-f", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["side_scan_results"] == [side_scan_record(_vulnerable_result(cleaned_up=True), provider="aws")]
    assert payload["side_scan_results"][0]["packages"][0]["vulnerabilities"][0]["id"] == "CVE-2099-0001"


def test_side_scan_image_id_dispatches_ami_and_gcp_image(monkeypatch):
    captured: dict = {}

    async def fake_run_side_scan(**kwargs):
        captured["aws"] = kwargs
        return []

    async def fake_run_provider_side_scan(**kwargs):
        captured["gcp"] = kwargs
        return []

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    monkeypatch.setattr("agent_bom.cloud.side_scan_targets.run_provider_side_scan", fake_run_provider_side_scan)

    aws = CliRunner().invoke(cg.side_scan_cmd, ["--image-id", "ami-0fedcba9876543210"])
    gcp = CliRunner().invoke(
        cg.side_scan_cmd,
        [
            "--provider",
            "gcp",
            "--image-id",
            "projects/p/global/images/golden",
            "--account-id",
            "p",
            "--collector-instance-id",
            "c",
            "--availability-zone",
            "z",
        ],
    )

    assert aws.exit_code == 0 and gcp.exit_code == 0, aws.output + gcp.output
    assert captured["aws"]["image_id"] == "ami-0fedcba9876543210"
    assert captured["gcp"]["target_type"] == "image"
    assert captured["gcp"]["target_id"] == "projects/p/global/images/golden"


def test_side_scan_azure_image_is_refused_with_reason(monkeypatch):
    result = CliRunner().invoke(cg.side_scan_cmd, ["--provider", "azure", "--image-id", "/subscriptions/s/images/golden"])

    assert result.exit_code == 2
    assert "managed image" in result.output.lower()
    assert "not supported" in result.output.lower()
