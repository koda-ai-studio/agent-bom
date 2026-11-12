"""Domain-verification token for a directory listing of a remote MCP server.

The plugin directory checks that the MCP host is controlled by the submitter by
fetching ``/.well-known/openai-apps-challenge`` and expecting the exact token
from the portal as plain text. The token is not a secret, but it is
deployment configuration, so it comes only from the environment. When it is
unset or malformed the route answers 404, and the response never varies with
the request.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from starlette.responses import PlainTextResponse, Response

from agent_bom.core.settings import env_str

OPENAI_APPS_CHALLENGE_ENV = "AGENT_BOM_OPENAI_APPS_CHALLENGE"
OPENAI_APPS_CHALLENGE_PATH = "/.well-known/openai-apps-challenge"
_TOKEN_PATTERN = re.compile(r"[\x21-\x7e]{1,512}")

logger = logging.getLogger(__name__)


def challenge_token() -> str | None:
    """The configured token, or None when unset or not one printable ASCII word."""
    value = env_str(OPENAI_APPS_CHALLENGE_ENV)
    return value if _TOKEN_PATTERN.fullmatch(value) else None


def attach_challenge_route(mcp: Any) -> None:
    if env_str(OPENAI_APPS_CHALLENGE_ENV) and challenge_token() is None:
        logger.warning("%s is set but is not 1-512 printable ASCII characters without spaces; serving 404", OPENAI_APPS_CHALLENGE_ENV)

    @mcp.custom_route(OPENAI_APPS_CHALLENGE_PATH, methods=["GET"])
    async def openai_apps_challenge_route(request):
        token = challenge_token()
        if token is None:
            return Response(status_code=404)
        return PlainTextResponse(token, headers={"cache-control": "no-store", "x-content-type-options": "nosniff"})
