"""Synthetic refund agent: fake data only, never execute this fixture."""

import os

from langchain.agents import create_agent
from langchain.tools import tool

PROVIDER_KEY = os.getenv("ANTHROPIC_API_KEY")


@tool
def issue_refund(order_id: str, amount: float) -> str:
    """Issue a sample refund."""
    return order_id


@tool
def update_order(order_id: str, status: str) -> str:
    """Update a sample order."""
    return order_id


refund_agent = create_agent("anthropic:claude-sonnet-4-5", tools=[issue_refund, update_order], name="refund_agent")
