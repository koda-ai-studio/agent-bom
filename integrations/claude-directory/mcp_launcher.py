"""Start the pinned local MCP server from this plugin's committed uv lock."""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    os.execvp(
        "uv",
        [
            "uv",
            "run",
            "--frozen",
            "--isolated",
            "--project",
            str(Path(__file__).resolve().parent),
            "agent-bom",
            "mcp",
            "server",
            *sys.argv[1:],
        ],
    )
