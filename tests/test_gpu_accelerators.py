"""Provider-specific GPU accelerator classification of machine types."""

from __future__ import annotations

import pytest

from agent_bom.cloud.gpu_accelerators import (
    aws_instance_accelerator,
    azure_vm_accelerator,
    databricks_node_accelerator,
    gcp_machine_accelerator,
    gke_accelerator_vendor,
    snowflake_instance_family_accelerator,
)


@pytest.mark.parametrize(
    ("instance_type", "vendor", "model", "count"),
    [
        ("p4d.24xlarge", "nvidia", "A100", 8),
        ("p5.48xlarge", "nvidia", "H100", 8),
        ("g5.xlarge", "nvidia", "A10G", 1),
        ("g5.48xlarge", "nvidia", "A10G", 8),
        ("g4dn.12xlarge", "nvidia", "T4", 4),
        ("g6e.xlarge", "nvidia", "L40S", 1),
        ("g4ad.xlarge", "amd", "Radeon Pro V520", 1),
        ("inf2.xlarge", "aws-neuron", "Inferentia2", 1),
        ("trn1.32xlarge", "aws-neuron", "Trainium", 16),
    ],
)
def test_aws_gpu_families(instance_type: str, vendor: str, model: str, count: int | None) -> None:
    acc = aws_instance_accelerator(instance_type)
    assert acc is not None
    assert (acc.vendor, acc.model, acc.count) == (vendor, model, count)


@pytest.mark.parametrize("instance_type", ["m5.large", "c6i.xlarge", "", "gp3", "p", "graviton"])
def test_aws_non_gpu_types_are_not_accelerated(instance_type: str) -> None:
    assert aws_instance_accelerator(instance_type) is None


def test_aws_unknown_size_keeps_family_but_not_count() -> None:
    acc = aws_instance_accelerator("g5.7xlarge")
    assert acc is not None and acc.model == "A10G" and acc.count is None


@pytest.mark.parametrize(
    ("machine", "model", "count"),
    [
        ("a2-highgpu-4g", "A100 40GB", 4),
        ("a2-ultragpu-8g", "A100 80GB", 8),
        ("a2-megagpu-16g", "A100 40GB", 16),
        ("a3-highgpu-8g", "H100 80GB", 8),
        ("a3-ultragpu-8g", "H200 141GB", 8),
        ("g2-standard-24", "L4", 2),
        ("g2-standard-8", "L4", 1),
    ],
)
def test_gcp_gpu_machine_families(machine: str, model: str, count: int) -> None:
    acc = gcp_machine_accelerator(machine)
    assert acc is not None and (acc.vendor, acc.model, acc.count) == ("nvidia", model, count)


@pytest.mark.parametrize("machine", ["n1-standard-4", "e2-medium", "n2-highmem-8", "c3-standard-4"])
def test_gcp_machines_without_bundled_gpus(machine: str) -> None:
    assert gcp_machine_accelerator(machine) is None


@pytest.mark.parametrize(
    ("accelerator_type", "vendor"),
    [("nvidia-tesla-t4", "nvidia"), ("nvidia-l4", "nvidia"), ("nvidia-h100-80gb", "nvidia"), ("tpu-v5-lite-podslice", "")],
)
def test_gke_accelerator_vendor(accelerator_type: str, vendor: str) -> None:
    assert gke_accelerator_vendor(accelerator_type) == vendor


@pytest.mark.parametrize(
    ("vm_size", "vendor", "model"),
    [
        ("Standard_NC6s_v3", "nvidia", "V100"),
        ("Standard_NC4as_T4_v3", "nvidia", "T4"),
        ("Standard_NC24ads_A100_v4", "nvidia", "A100"),
        ("Standard_NC40ads_H100_v5", "nvidia", "H100"),
        ("Standard_ND96isr_H100_v5", "nvidia", "H100"),
        ("Standard_ND96asr_v4", "nvidia", "A100"),
        ("Standard_NV36ads_A10_v5", "nvidia", "A10"),
        ("Standard_NV32as_v4", "amd", "Radeon Instinct MI25"),
        ("Standard_ND96isr_MI300X_v5", "amd", "Instinct MI300X"),
        ("standard_nc6s_v3", "nvidia", "V100"),
    ],
)
def test_azure_gpu_vm_sizes(vm_size: str, vendor: str, model: str) -> None:
    acc = azure_vm_accelerator(vm_size)
    assert acc is not None and (acc.vendor, acc.model) == (vendor, model)


@pytest.mark.parametrize("vm_size", ["Standard_D4s_v5", "Standard_E8s_v5", "Standard_B2s", "Standard_L8s_v3", ""])
def test_azure_non_gpu_vm_sizes(vm_size: str) -> None:
    assert azure_vm_accelerator(vm_size) is None


@pytest.mark.parametrize(
    ("family", "cloud", "model", "count"),
    [
        ("GPU_NV_S", "aws", "A10G", 1),
        ("GPU_NV_M", "aws", "A10G", 4),
        ("GPU_NV_L", "aws", "A100", 8),
        ("GPU_NV_XS", "azure", "T4", 1),
        ("GPU_NV_SL", "azure", "A100", 4),
        ("GPU_GCP_NV_L4_4_24G", "gcp", "L4", 4),
        ("gpu_nv_s", "aws", "A10G", 1),
    ],
)
def test_snowflake_gpu_instance_families(family: str, cloud: str, model: str, count: int) -> None:
    acc = snowflake_instance_family_accelerator(family)
    assert acc is not None and (acc.vendor, acc.model, acc.count, acc.cloud) == ("nvidia", model, count, cloud)


def test_snowflake_unknown_gpu_family_is_gpu_with_unknown_model() -> None:
    acc = snowflake_instance_family_accelerator("GPU_NV_FUTURE")
    assert acc is not None and acc.vendor == "nvidia" and acc.model == "" and acc.count is None


@pytest.mark.parametrize("family", ["CPU_X64_XS", "HIGHMEM_X64_M", "GEN_X64_G2_4", ""])
def test_snowflake_cpu_families(family: str) -> None:
    assert snowflake_instance_family_accelerator(family) is None


def test_databricks_node_type_prefers_reported_gpu_count() -> None:
    acc = databricks_node_accelerator("g5.xlarge", reported_gpus=1)
    assert acc is not None and (acc.vendor, acc.model, acc.count) == ("nvidia", "A10G", 1)
    azure = databricks_node_accelerator("Standard_NC6s_v3", reported_gpus=None)
    assert azure is not None and azure.model == "V100"
    gcp = databricks_node_accelerator("a2-highgpu-1g", reported_gpus=None)
    assert gcp is not None and gcp.count == 1
    assert databricks_node_accelerator("i3.xlarge", reported_gpus=0) is None
    unknown = databricks_node_accelerator("custom-node", reported_gpus=2)
    assert unknown is not None and unknown.count == 2 and unknown.model == ""
