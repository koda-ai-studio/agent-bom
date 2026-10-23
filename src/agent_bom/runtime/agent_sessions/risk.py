"""Risky actions an agent performed, classified from redacted span evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|k|da|fi)?sh\b")
_RM_RF = re.compile(
    r"(?:^|[\s;&|(])rm\s+(?:-[A-Za-z]*(?:r[A-Za-z]*f|f[A-Za-z]*r)[A-Za-z]*|(?:-[rRf]\s+){1}-[rRf]|--recursive\s+--force|--force\s+--recursive)\s+(\S+)"
)
_ROOTISH = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "*", ".", "./", "..", "/home", "/Users"}
_FORCE_PUSH = re.compile(r"\bgit\s+push\b[^\n;&|]*\s(?:--force(?!-with-lease)\b|-f\b|\+\S+)")
_RESET_HARD = re.compile(r"\bgit\s+reset\s+[^\n;&|]*--hard\b")
_CLEAN_FORCE = re.compile(r"\bgit\s+clean\s+-[A-Za-z]*f")
_READ_SECRET = re.compile(r"\b(?:cat|less|more|head|tail|source|bat|strings|base64)\s+([^\s;&|]+)")

_SECRET_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", ".npmrc", ".pypirc", ".netrc", ".pgpass", "kubeconfig"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")
_SECRET_PARTS = ("/.aws/credentials", "/.docker/config.json", "/.kube/config", "/.ssh/", "/.gnupg/")
_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
_SENSITIVE_WRITE = ("/etc/", "~/.ssh/", "~/.aws/", "~/.zshrc", "~/.bashrc", "~/.profile", "~/.bash_profile", "~/.gitconfig")


@dataclass(frozen=True)
class Risk:
    category: str
    severity: str
    evidence: str


def is_secret_path(path: str) -> bool:
    text = path.strip().strip("'\"")
    base = text.rstrip("/").rsplit("/", 1)[-1]
    if base in _ENV_TEMPLATES or base.endswith(".pub"):
        return False
    if base == ".env" or base.startswith(".env."):
        return True
    return base in _SECRET_NAMES or base.endswith(_SECRET_SUFFIXES) or any(part in "/" + text.lstrip("~") for part in _SECRET_PARTS)


def classify_command(command: str) -> list[Risk]:
    risks: list[Risk] = []
    if _PIPE_TO_SHELL.search(command):
        risks.append(Risk("pipe_to_shell", "high", command))
    for match in _RM_RF.finditer(command):
        risks.append(Risk("destructive_command", "high" if match.group(1).strip("'\"") in _ROOTISH else "medium", command))
        break
    if _FORCE_PUSH.search(command):
        risks.append(Risk("destructive_command", "high", command))
    elif _RESET_HARD.search(command) or _CLEAN_FORCE.search(command):
        risks.append(Risk("destructive_command", "medium", command))
    for match in _READ_SECRET.finditer(command):
        if is_secret_path(match.group(1)):
            risks.append(Risk("secret_file_read", "medium", match.group(1)))
            break
    return risks


def write_severity(path: str) -> str:
    return "high" if path.startswith(_SENSITIVE_WRITE) else "medium"


def outside_root(path: str, root: str) -> bool:
    """True only for an absolute (or home-relative) path that is not inside ``root``."""
    if not root or not path.startswith(("/", "~")):
        return False
    root = root.rstrip("/") or "/"
    return not (path == root or path.startswith(root + "/"))
