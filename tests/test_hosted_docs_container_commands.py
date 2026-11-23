"""Commands the hosted runbooks run inside a container must exist in the runtime image.

The runtime image copies the installed package, not the repository's scripts/
directory, so a documented ``docker compose ... exec api python scripts/...``
fails on a published image even though it works from a source checkout.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "site-docs" / "deployment" / "authenticated-hosted-instance.md",
    ROOT / "docs" / "HOSTED_POC.md",
]
FENCE = re.compile(r"```(?:bash|sh|shell)?\n(.*?)```", re.S)
IN_CONTAINER = re.compile(r"docker compose\b.*?\b(?:exec|run)\b(?P<rest>.*)")


def _container_commands(text: str) -> list[str]:
    commands = []
    for block in FENCE.findall(text):
        for line in block.replace("\\\n", " ").splitlines():
            match = IN_CONTAINER.search(line)
            if not match:
                continue
            tokens = match.group("rest").split()
            # Skip compose flags (-e KEY=VAL, -f file, --rm, -T ...) up to the service name.
            i = 0
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 2 if tokens[i] in {"-e", "--env", "-u", "--user", "-w", "--workdir", "-f"} else 1
            if i + 1 < len(tokens):
                commands.append(" ".join(tokens[i + 1 :]))
    return commands


def test_runtime_image_does_not_copy_repository_scripts() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"^COPY\s+(?:--\S+\s+)*scripts/", dockerfile, re.M), "update this guard if scripts/ ships in the image"


def test_hosted_runbooks_only_run_packaged_commands_in_containers() -> None:
    found = []
    for doc in DOCS:
        for command in _container_commands(doc.read_text(encoding="utf-8")):
            found.append(command)
            where = doc.relative_to(ROOT)
            assert command.split()[0] == "agent-bom", f"{where} runs `{command}` in a container; only the packaged CLI ships there"
            assert "scripts/" not in command, f"{where} references the source checkout inside a container: `{command}`"
    assert found, "the runbooks no longer show an in-container command; the guard parses nothing"


def test_runbooks_use_the_packaged_admin_bootstrap() -> None:
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        assert "agent-bom auth mint-admin-key" in text, f"{doc.relative_to(ROOT)} lost the packaged admin bootstrap"
