"""The suite's scan-analytics mirror resolves inside the isolated state dir, never the account's real home."""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from agent_bom.db import local_analytics
from agent_bom.db.local_analytics import local_analytics_path


def test_local_analytics_path_resolves_under_the_isolated_state_dir() -> None:
    state_dir = Path(os.environ["AGENT_BOM_STATE_DIR"]).resolve()
    resolved = local_analytics_path().resolve()

    assert resolved.is_relative_to(state_dir), resolved
    assert resolved.name == local_analytics.DEFAULT_LOCAL_ANALYTICS_FILENAME


def test_local_analytics_path_never_points_at_the_real_home() -> None:
    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    resolved = local_analytics_path().resolve()

    assert not resolved.is_relative_to(real_home / ".agent-bom"), resolved
    assert not os.environ.get("AGENT_BOM_LOCAL_ANALYTICS_DB", "").startswith(str(real_home))
