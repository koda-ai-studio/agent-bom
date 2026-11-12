"""Start the pinned local MCP server from this plugin's committed uv lock."""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    # Claude exports the project root to stdio servers; absent means no extra roots.
    os.environ["AGENT_BOM_MCP_WORKSPACE_ROOTS"] = os.environ.get("CLAUDE_PROJECT_DIR", "")
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
