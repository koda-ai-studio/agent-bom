"""Import expressions for Python and JavaScript SDK discovery."""

import re

__all__ = ["py_import", "js_import"]


def py_import(module: str) -> str:
    """Python import pattern: import X / from X import ..."""
    escaped = re.escape(module)
    return rf"(?:^|\n)\s*(?:import\s+{escaped}(?!\w)|from\s+{escaped}(?:\.\w+)*\s+import)"


def js_import(module: str) -> str:
    """JS/TS import/require pattern."""
    escaped = re.escape(module)
    # SDKs commonly publish subpath exports (for example
    # ``@modelcontextprotocol/sdk/server/mcp.js``). Requiring the quote directly
    # after the package root missed the imports real servers use.
    subpath = r"(?:/[^'\"]+)?"
    return rf"""(?:import\s+.*?from\s+['"](?:@[^/]+/)?{escaped}{subpath}['"]|require\s*\(\s*['"](?:@[^/]+/)?{escaped}{subpath}['"]\s*\))"""
