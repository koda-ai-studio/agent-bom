"""Release-pinned links and local credential detection for `agent-bom connect`.

A pip install carries none of the repository's provisioning recipes or
Terraform modules, so the guidance points at the tagged source instead of
repository-relative paths. Detection reads only the presence of standard
provider login files; it never opens them or calls a cloud API.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from agent_bom import __version__
from agent_bom.core.settings import env_opt
from agent_bom.output.next_steps import REPO_URL

_RELEASE = re.compile(r"\d+\.\d+\.\d+")

# Files the provider SDKs read after a normal CLI login, with the variables that relocate them.
_LOGIN_FILES: dict[str, tuple[tuple[str | None, str], ...]] = {
    "aws": (("AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials"), ("AWS_CONFIG_FILE", ".aws/config")),
    "azure": (("AZURE_CONFIG_DIR", ".azure/azureProfile.json"),),
    "gcp": (("CLOUDSDK_CONFIG", ".config/gcloud/application_default_credentials.json"),),
}


def release_ref() -> str:
    """The tag matching this install, or ``main`` for a development build."""
    return f"v{__version__}" if _RELEASE.fullmatch(__version__) else "main"


def source_link(path: str) -> str:
    kind = "blob" if Path(path).suffix else "tree"
    return f"{REPO_URL}/{kind}/{release_ref()}/{path}"


def terraform_command(module: str) -> str:
    """Init a connect module straight from the tagged source into an empty directory.

    A shallow clone: a plain GitHub source fetches the whole history, which took minutes.
    """
    source = f"git::{REPO_URL}.git//{module}?ref={release_ref()}&depth=1"
    return f'terraform init -from-module="{source}" && terraform apply'


def _login_file(variable: str | None, default: str) -> Path:
    override = env_opt(variable) if variable else None
    if not override:
        return Path.home() / default
    path = Path(override)
    # Directory overrides keep the provider's own file name under them.
    return path / Path(default).name if variable in {"AZURE_CONFIG_DIR", "CLOUDSDK_CONFIG"} else path


def detected_login_files(provider: str) -> list[str]:
    """Standard login files present for ``provider``, shown with ``~`` for the home directory."""
    found = []
    for variable, default in _LOGIN_FILES.get(provider, ()):
        path = _login_file(variable, default)
        if path.is_file():
            home = str(Path.home())
            shown = str(path)
            found.append("~" + shown[len(home) :] if shown.startswith(home + os.sep) else shown)
    return found
