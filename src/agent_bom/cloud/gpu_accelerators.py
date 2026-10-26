"""Provider-specific GPU accelerator classification of machine types.

Each provider names accelerated capacity differently, so each has its own
table and none is applied to another provider's names:

- AWS EC2 accelerated-computing families (P, G, Inf, Trn) from the EC2
  instance-type documentation.
- GCP accelerator-optimized machine series (A2, A3, A4, G2) bundle GPUs into the
  machine type; other series attach GPUs through ``accelerators`` instead.
- Azure GPU VM sizes are the N-series (NC, ND, NV, NG); the size name encodes
  the GPU generation.
- Snowflake Snowpark Container Services GPU instance families (``GPU_*``) from
  the CREATE COMPUTE POOL reference.

A family whose per-size GPU count is not tabled keeps ``count=None`` rather
than a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Accelerator:
    vendor: str
    model: str
    count: int | None = None
    cloud: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"vendor": self.vendor, "model": self.model, "count": self.count, **({"cloud": self.cloud} if self.cloud else {})}


# family -> (vendor, model, {size: count})
_AWS_FAMILIES: dict[str, tuple[str, str, dict[str, int]]] = {
    "p2": ("nvidia", "K80", {"xlarge": 1, "8xlarge": 8, "16xlarge": 16}),
    "p3": ("nvidia", "V100", {"2xlarge": 1, "8xlarge": 4, "16xlarge": 8}),
    "p3dn": ("nvidia", "V100", {"24xlarge": 8}),
    "p4d": ("nvidia", "A100", {"24xlarge": 8}),
    "p4de": ("nvidia", "A100", {"24xlarge": 8}),
    "p5": ("nvidia", "H100", {"4xlarge": 1, "48xlarge": 8}),
    "p5e": ("nvidia", "H200", {"48xlarge": 8}),
    "p5en": ("nvidia", "H200", {"48xlarge": 8}),
    "p6-b200": ("nvidia", "B200", {"48xlarge": 8}),
    "g3": ("nvidia", "M60", {"4xlarge": 1, "8xlarge": 2, "16xlarge": 4}),
    "g3s": ("nvidia", "M60", {"xlarge": 1}),
    "g4dn": ("nvidia", "T4", {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 1, "16xlarge": 1, "12xlarge": 4, "metal": 8}),
    "g4ad": ("amd", "Radeon Pro V520", {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 2, "16xlarge": 4}),
    "g5": (
        "nvidia",
        "A10G",
        {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 1, "16xlarge": 1, "12xlarge": 4, "24xlarge": 4, "48xlarge": 8},
    ),
    "g5g": ("nvidia", "T4G", {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 1, "16xlarge": 2, "metal": 2}),
    "g6": (
        "nvidia",
        "L4",
        {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 1, "16xlarge": 1, "12xlarge": 4, "24xlarge": 4, "48xlarge": 8},
    ),
    "g6e": (
        "nvidia",
        "L40S",
        {"xlarge": 1, "2xlarge": 1, "4xlarge": 1, "8xlarge": 1, "16xlarge": 1, "12xlarge": 4, "24xlarge": 4, "48xlarge": 8},
    ),
    "gr6": ("nvidia", "L4", {"4xlarge": 1, "8xlarge": 1}),
    "inf1": ("aws-neuron", "Inferentia", {"xlarge": 1, "2xlarge": 1, "6xlarge": 4, "24xlarge": 16}),
    "inf2": ("aws-neuron", "Inferentia2", {"xlarge": 1, "8xlarge": 1, "24xlarge": 6, "48xlarge": 12}),
    "trn1": ("aws-neuron", "Trainium", {"2xlarge": 1, "32xlarge": 16}),
    "trn1n": ("aws-neuron", "Trainium", {"32xlarge": 16}),
    "trn2": ("aws-neuron", "Trainium2", {"48xlarge": 16}),
}


def aws_instance_accelerator(instance_type: str) -> Accelerator | None:
    """Accelerator for an EC2 instance type (``g5.xlarge``), or ``None``."""
    family, _, size = str(instance_type or "").strip().lower().partition(".")
    entry = _AWS_FAMILIES.get(family)
    if entry is None or not size:
        return None
    vendor, model, counts = entry
    return Accelerator(vendor, model, counts.get(size))


# series prefix -> (model, explicit count or None to parse "-<n>g")
_GCP_SERIES: tuple[tuple[str, str, int | None], ...] = (
    ("a2-highgpu-", "A100 40GB", None),
    ("a2-megagpu-", "A100 40GB", None),
    ("a2-ultragpu-", "A100 80GB", None),
    ("a3-highgpu-", "H100 80GB", None),
    ("a3-megagpu-", "H100 80GB", None),
    ("a3-edgegpu-", "H100 80GB", None),
    ("a3-ultragpu-", "H200 141GB", None),
    ("a4-highgpu-", "B200", None),
)
_G2_COUNTS = {"4": 1, "8": 1, "12": 1, "16": 1, "32": 1, "24": 2, "48": 4, "96": 8}


def gcp_machine_accelerator(machine_type: str) -> Accelerator | None:
    """GPUs bundled into a GCP accelerator-optimized machine type, or ``None``.

    N1 and other general-purpose series carry GPUs only through attached
    ``accelerators``; those are read from the node pool / instance config.
    """
    machine = str(machine_type or "").strip().lower().rsplit("/", 1)[-1]
    if machine.startswith("g2-standard-"):
        return Accelerator("nvidia", "L4", _G2_COUNTS.get(machine.removeprefix("g2-standard-")))
    for prefix, model, count in _GCP_SERIES:
        if machine.startswith(prefix):
            match = re.fullmatch(r"([0-9]+)g", machine.removeprefix(prefix))
            return Accelerator("nvidia", model, count or (int(match[1]) if match else None))
    return None


def gke_accelerator_vendor(accelerator_type: str) -> str:
    """Vendor of a GKE ``accelerator_type`` (``nvidia-l4``); TPUs are not GPUs."""
    return "nvidia" if str(accelerator_type or "").strip().lower().startswith("nvidia-") else ""


# Ordered: the first matching pattern wins.
_AZURE_SIZES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"standard_nd\d+is?r?_mi300x_v5"), "amd", "Instinct MI300X"),
    (re.compile(r"standard_nv\d+as_v4"), "amd", "Radeon Instinct MI25"),
    (re.compile(r"standard_ng\d+ads_v620_v1"), "amd", "Radeon Pro V620"),
    (re.compile(r"standard_n[cd]\d+[a-z]*_h100_v5|standard_nd\d+isr_h100_v5"), "nvidia", "H100"),
    (re.compile(r"standard_nd\d+isr_h200_v5"), "nvidia", "H200"),
    (re.compile(r"standard_nc\d+ads_a100_v4|standard_nd\d+a[ms]?sr_(?:a100_)?v4"), "nvidia", "A100"),
    (re.compile(r"standard_nc\d+as_t4_v3"), "nvidia", "T4"),
    (re.compile(r"standard_nv\d+ads_a10_v5"), "nvidia", "A10"),
    (re.compile(r"standard_nc\d+r?s_v3|standard_nd\d+rs_v2"), "nvidia", "V100"),
    (re.compile(r"standard_nc\d+r?s_v2|standard_nd\d+r?s"), "nvidia", "P100/P40"),
    (re.compile(r"standard_nv\d+s_v3|standard_nv\d+"), "nvidia", "M60"),
    (re.compile(r"standard_nc\d+r?"), "nvidia", "K80"),
)


def azure_vm_accelerator(vm_size: str) -> Accelerator | None:
    """Accelerator for an Azure N-series VM size, or ``None`` for other series."""
    size = str(vm_size or "").strip().lower()
    if not re.match(r"standard_n[cdvg]\d", size):
        return None
    for pattern, vendor, model in _AZURE_SIZES:
        if pattern.fullmatch(size):
            return Accelerator(vendor, model)
    return Accelerator("nvidia", "")


_SNOWFLAKE_FAMILIES: dict[str, Accelerator] = {
    "GPU_NV_S": Accelerator("nvidia", "A10G", 1, "aws"),
    "GPU_NV_M": Accelerator("nvidia", "A10G", 4, "aws"),
    "GPU_NV_L": Accelerator("nvidia", "A100", 8, "aws"),
    "GPU_NV_XS": Accelerator("nvidia", "T4", 1, "azure"),
    "GPU_NV_SM": Accelerator("nvidia", "A10", 1, "azure"),
    "GPU_NV_2M": Accelerator("nvidia", "A10", 2, "azure"),
    "GPU_NV_3M": Accelerator("nvidia", "A100", 2, "azure"),
    "GPU_NV_SL": Accelerator("nvidia", "A100", 4, "azure"),
    "GPU_GCP_NV_L4_1_24G": Accelerator("nvidia", "L4", 1, "gcp"),
    "GPU_GCP_NV_L4_4_24G": Accelerator("nvidia", "L4", 4, "gcp"),
    "GPU_GCP_NV_A100_8_40G": Accelerator("nvidia", "A100", 8, "gcp"),
}


def snowflake_instance_family_accelerator(instance_family: str) -> Accelerator | None:
    """Accelerator for a Snowpark Container Services instance family, or ``None``."""
    family = str(instance_family or "").strip().upper()
    if not family.startswith("GPU_"):
        return None
    return _SNOWFLAKE_FAMILIES.get(family) or Accelerator("nvidia", "")


def databricks_node_accelerator(node_type_id: str, *, reported_gpus: int | None) -> Accelerator | None:
    """Accelerator for a Databricks node type; ``reported_gpus`` is ``NodeType.num_gpus``.

    The workspace's node-type listing is authoritative for the count; the
    cloud-specific machine name only adds the GPU model.
    """
    name = str(node_type_id or "").strip()
    by_name = aws_instance_accelerator(name) or azure_vm_accelerator(name) or gcp_machine_accelerator(name)
    if reported_gpus is not None and reported_gpus <= 0:
        return None
    if by_name is None:
        return Accelerator("unknown", "", reported_gpus) if reported_gpus else None
    return Accelerator(by_name.vendor, by_name.model, reported_gpus or by_name.count)
