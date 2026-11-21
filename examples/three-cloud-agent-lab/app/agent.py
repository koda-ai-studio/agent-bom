"""A minimal stand-in AI agent: reads its model key and MCP config, then idles."""

import json
import os
import sys
import time
from pathlib import Path

config = json.loads(Path("/app/mcp.json").read_text())
sys.stdout.write(f"agent up: {len(config['mcpServers'])} MCP servers, model key set: {bool(os.environ.get('OPENAI_API_KEY'))}\n")
sys.stdout.flush()
while True:
    time.sleep(3600)
