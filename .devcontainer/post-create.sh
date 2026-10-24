#!/usr/bin/env bash
set -euo pipefail

python -m pip install --user --quiet uv==0.10.9
export PATH="$HOME/.local/bin:$PATH"

uv sync --extra dev
uv tool install --quiet pre-commit
pre-commit install
uv run agent-bom --version

echo "Ready. Try: uv run agent-bom scan --demo --offline"
