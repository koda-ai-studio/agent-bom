"""Synthetic support agent: fake data only, never execute this fixture."""

import os

from langchain.agents import create_agent
from langchain.tools import tool

MODEL = "openai:gpt-4o-mini"
PROVIDER_KEY = os.getenv("OPENAI_API_KEY")


@tool
def send_email(to: str, body: str) -> str:
    """Send a sample email."""
    return to


@tool
def delete_ticket(ticket_id: str) -> str:
    """Delete a sample ticket."""
    return ticket_id


support_agent = create_agent(MODEL, tools=[send_email, delete_ticket], name="support_agent")
