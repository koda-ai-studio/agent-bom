"""MITRE ATLAS vocabulary and source-backed weakness applicability.

Catalog membership is not detection coverage. A package, credential reference,
or declared tool capability does not prove jailbreak, poisoning, exfiltration,
attacker tool invocation, or business impact.

The scanner joins advisory CWEs to the local official CAPEC/ATT&CK bridge and
then to explicit ATLAS ``attck_reference`` relationships. The resulting tags
are weakness applicability associations in AI inventory, not observed behavior.
The label vocabulary also serves other evidence-producing finding types.

Sources: https://atlas.mitre.org/ and https://github.com/mitre-atlas/atlas-data
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# Technique labels are a supported vocabulary, not a static detection count.
# The full source catalog ships in data/mitre_atlas_catalog.json.

ATLAS_TECHNIQUES: dict[str, str] = {
    # Reconnaissance
    "AML.T0000": "Search Open Technical Databases",
    "AML.T0001": "Search Open AI Vulnerability Analysis",
    "AML.T0004": "Search Application Repositories",
    "AML.T0006": "Active Scanning",
    "AML.T0007": "Discover AI Artifacts",
    # Resource Development
    "AML.T0008": "Acquire Infrastructure",
    "AML.T0016": "Obtain Capabilities",
    "AML.T0017": "Develop Capabilities",
    # Initial Access
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.001": "AI Software",
    "AML.T0010.002": "Data",
    "AML.T0010.003": "Model",
    "AML.T0010.004": "Container Registry",
    "AML.T0011": "User Execution",
    "AML.T0011.001": "Malicious Package",
    "AML.T0012": "Valid Accounts",
    "AML.T0049": "Exploit Public-Facing Application",
    # Execution
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0053": "AI Agent Tool Invocation",
    # Persistence / Defense Evasion
    "AML.T0018": "Manipulate AI Model",
    "AML.T0018.000": "Poison AI Model",
    "AML.T0018.001": "Modify AI Model Architecture",
    "AML.T0018.002": "Embed Malware",
    "AML.T0074": "Masquerading",
    # Credential Access
    "AML.T0055": "Unsecured Credentials",
    # Discovery
    "AML.T0013": "Discover AI Model Ontology",
    "AML.T0014": "Discover AI Model Family",
    "AML.T0040": "AI Model Inference API Access",
    "AML.T0063": "Discover AI Model Outputs",
    "AML.T0064": "Gather RAG-Indexed Targets",
    "AML.T0069": "Discover LLM System Information",
    # Collection
    "AML.T0035": "AI Artifact Collection",
    "AML.T0036": "Data from Information Repositories",
    "AML.T0037": "Data from Local System",
    # ML Attack Staging
    "AML.T0002": "Acquire Public AI Artifacts",
    "AML.T0005": "Create Proxy AI Model",
    "AML.T0015": "Evade AI Model",
    "AML.T0019": "Publish Poisoned Datasets",
    "AML.T0020": "Poison Training Data",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0043.004": "Insert Backdoor Trigger",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    # LLM / AI Agent Exploitation
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "Direct Prompt Injection",
    "AML.T0051.001": "Indirect Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    # Exfiltration
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0024.001": "Invert AI Model",
    "AML.T0024.002": "Extract AI Model",
    "AML.T0025": "Exfiltration via Cyber Means",
    # Impact
    "AML.T0029": "Denial of AI Service",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0046": "Spamming AI System with Chaff Data",
    "AML.T0048": "External Harms",
    # Social Engineering
    "AML.T0052": "Phishing",
    "AML.T0052.000": "Spearphishing via Social Engineering LLM",
    "AML.T0073": "Impersonation",
}


def _weakness_references(cwe_ids: list[str], attack: dict[str, Any]) -> dict[str, set[str]]:
    cwe_map = attack.get("cwe_to_attack", {})
    if not isinstance(cwe_map, dict):
        return {}
    attack_to_cwes: dict[str, set[str]] = {}
    for raw in cwe_ids:
        if not isinstance(raw, str):
            continue
        cwe = raw.strip().upper()
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        techniques = cwe_map.get(cwe, [])
        if not isinstance(techniques, list):
            continue
        for technique in techniques:
            if isinstance(technique, str):
                attack_to_cwes.setdefault(technique, set()).add(cwe)

    return attack_to_cwes


def blast_radius_technique_evidence(br: BlastRadius) -> dict[str, dict[str, Any]]:
    """Join explicit catalog relationships; abstain without a supported chain."""
    if not br.vulnerability.cwe_ids:
        return {}
    from agent_bom.models import AgentType, ServerSurface

    ai_context = any(agent.agent_type != AgentType.CUSTOM for agent in br.affected_agents) or any(
        server.is_mcp_surface or server.surface == ServerSurface.AI_INVENTORY for server in br.affected_servers
    )
    # Generic image/SBOM wrappers reuse Agent/MCPServer storage models. Names
    # (including an AI-looking package name) are not proof of an AI context.
    if not ai_context:
        return {}

    from agent_bom.atlas_fetch import build_catalog as atlas_catalog
    from agent_bom.mitre_fetch import build_catalog as attack_catalog

    attack = attack_catalog()
    attack_to_cwes = _weakness_references(br.vulnerability.cwe_ids, attack)

    if not attack_to_cwes:
        return {}
    atlas = atlas_catalog()
    for catalog in (attack, atlas):
        digest = catalog.get("normalized_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            return {}
    techniques = atlas.get("techniques", {})
    if not isinstance(techniques, dict):
        return {}
    receipts: dict[str, dict[str, Any]] = {}
    for technique, metadata in techniques.items():
        if not isinstance(metadata, dict):
            continue
        reference = metadata.get("attck_reference")
        if technique not in ATLAS_TECHNIQUES or not isinstance(reference, str) or reference not in attack_to_cwes:
            continue
        receipts[technique] = {
            "basis": "catalog_weakness_association",
            "cwe_ids": sorted(attack_to_cwes[reference]),
            "attack_reference": reference,
            "execution_proven": False,
            "atlas_catalog_sha256": atlas.get("normalized_sha256", ""),
            "atlas_version": atlas.get("atlas_version", "unknown"),
            "attack_catalog_sha256": attack.get("normalized_sha256", ""),
            "technique_url": f"https://atlas.mitre.org/techniques/{technique}",
        }
    return dict(sorted(receipts.items()))


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return catalog-backed applicability; inventory context alone adds no tags."""
    return list(blast_radius_technique_evidence(br))


def atlas_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'AML.T0010 AI Supply Chain Compromise'."""
    name = ATLAS_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def atlas_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATLAS technique IDs."""
    return [atlas_label(t) for t in technique_ids]


def upstream_catalog() -> dict:
    """Return the bundled (or synced) full upstream ATLAS catalog.

    Catalog counts describe reference vocabulary, not detection coverage.
    Package associations require exact source relationships and are bounded
    by the supported labels in :data:`ATLAS_TECHNIQUES`.
    """
    from agent_bom.atlas_fetch import load_catalog

    return load_catalog()


def upstream_total() -> int:
    """Return the count of techniques in the upstream ATLAS reference catalog."""
    return len(upstream_catalog().get("techniques", {}))


def curated_total() -> int:
    """Return the count of techniques in the curated tag surface."""
    return len(ATLAS_TECHNIQUES)
