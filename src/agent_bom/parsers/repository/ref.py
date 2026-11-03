"""Read a local Git ref without subprocesses, external gitdirs or repository config."""

import re

from agent_bom.parsers.repository.artifacts import RepositoryReader


def repository_ref(reader: RepositoryReader) -> dict:
    unknown = {"ref": "unrecorded", "revision": None, "ref_status": "unavailable"}
    directory = reader.root / ".git"
    if not directory.is_dir() or directory.is_symlink():
        return unknown
    head = (reader.read(".git/HEAD", max_bytes=1024) or "").strip()
    if re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", head):
        return {"ref": f"detached:{head.lower()}", "revision": head.lower(), "ref_status": "recorded"}
    ref = head.removeprefix("ref: ")
    if not ref.startswith("refs/heads/") or not re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", ref):
        return unknown
    if any(part in {"", ".", ".."} for part in ref.split("/")):
        return unknown
    revision = (reader.read(f".git/{ref}", max_bytes=1024) or "").strip()
    if not revision:
        packed = reader.read(".git/packed-refs") or ""
        revision = next((line.split(" ")[0] for line in packed.splitlines() if line.endswith(" " + ref)), "")
    if not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", revision):
        return unknown
    return {"ref": ref, "revision": revision.lower(), "ref_status": "recorded"}
