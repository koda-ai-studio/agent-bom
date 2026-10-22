"""Dependency-free scoped identity contract shared by collection and projection."""

import hashlib
import json

MAX_RECORDS = 2000


def directory_node_id(provider: str, account: str, kind: str, native: str) -> str:
    return f"{kind}:{provider}:" + hashlib.sha256(json.dumps([account, native]).encode()).hexdigest()
