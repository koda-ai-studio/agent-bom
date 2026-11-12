"""HTTP routes projecting MCP catalog metadata and live schemas."""

from collections.abc import Callable
from typing import Any

from agent_bom.mcp_tools.openai_challenge import attach_challenge_route


def attach_metadata_routes(
    mcp: Any,
    *,
    auth_required: bool,
    tool_metrics_snapshot: Callable[[], dict[str, Any]],
    profile: str = "full",
    oauth: bool = False,
    anonymous_tools: list[str] | None = None,
) -> None:
    """``anonymous_tools`` is the public read-only tier's tool list, or None when the tier is off."""
    from agent_bom.mcp_server_metadata import build_health_payload, build_root_metadata, build_server_card

    public_fields = {"public_readonly": anonymous_tools is not None, "anonymous_tools": list(anonymous_tools or [])}
    attach_challenge_route(mcp)

    @mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
    async def server_card_route(request):
        from starlette.responses import JSONResponse

        card = build_server_card(auth_required=auth_required, profile=profile, oauth=oauth, anonymous_tools=anonymous_tools)
        # The static metadata catalog owns descriptions and capability classes;
        # the live FastMCP registry owns exact JSON input/output schemas. Serve
        # the latter here so marketplaces never index a hand-maintained schema.
        live_tools = await mcp.list_tools()
        metadata_by_name = {str(tool["name"]): tool for tool in card["tools"]}
        rendered_tools: list[dict[str, Any]] = []
        for tool in live_tools:
            payload = tool.model_dump(by_alias=True, exclude_none=True)
            metadata = metadata_by_name.get(str(payload.get("name")), {})
            if metadata.get("capability_classes"):
                payload["capability_classes"] = list(metadata["capability_classes"])
            rendered_tools.append(payload)
        card["tools"] = rendered_tools
        card["prompts"] = [prompt.model_dump(by_alias=True, exclude_none=True) for prompt in await mcp.list_prompts()]
        card["resources"] = [resource.model_dump(mode="json", by_alias=True, exclude_none=True) for resource in await mcp.list_resources()]
        card["capabilities"]["read_only"] = all(tool.get("annotations", {}).get("readOnlyHint") is True for tool in rendered_tools)
        return JSONResponse(card)

    @mcp.custom_route("/", methods=["GET"])
    async def root_metadata_route(request):
        from starlette.responses import JSONResponse

        return JSONResponse({**build_root_metadata(auth_required=auth_required), "profile": profile, **public_fields})

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request):
        from starlette.responses import JSONResponse

        metrics = tool_metrics_snapshot()["summary"]
        payload = build_health_payload(auth_required=auth_required, tool_metrics_summary=metrics)
        payload.update(profile=profile, tool_count=len(await mcp.list_tools()), **public_fields)
        return JSONResponse(payload)
