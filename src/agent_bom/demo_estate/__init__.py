"""Demo estate bootstrap and showcase graph helpers."""

from agent_bom.core.settings import TRUTHY, env_str


def demo_estate_enabled() -> bool:
    """Read the existing opt-in without importing the seeding implementation."""
    return env_str("AGENT_BOM_DEMO_ESTATE", "").lower() in TRUTHY
