"""Synthetic LangGraph team: fake data only, never execute this fixture."""

import os
from typing import Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph

MODEL = "openai:gpt-4o-mini"
PROVIDER_KEY = os.getenv("OPENAI_API_KEY")


@tool
def lookup_ticket(ticket_id: str) -> str:
    """Return a sample ticket summary."""
    return ticket_id


@tool
def draft_reply(summary: str) -> str:
    """Draft a sample reply."""
    return summary


triage_agent = create_agent(MODEL, tools=[lookup_ticket], system_prompt="Summarize the sample ticket.", name="triage_agent")
reply_agent = create_agent(MODEL, tools=[draft_reply], system_prompt="Draft a sample reply.", name="reply_agent")


def supervisor(state: MessagesState):
    return state


def route(state: MessagesState) -> Literal["triage_agent", "reply_agent", "__end__"]:
    return state.get("next", END)


builder = StateGraph(MessagesState)
builder.add_node("supervisor", supervisor)
builder.add_node("triage_agent", triage_agent)
builder.add_node("reply_agent", reply_agent)
builder.add_edge(START, "supervisor")
builder.add_conditional_edges("supervisor", route, {"triage_agent": "triage_agent", "reply_agent": "reply_agent", "__end__": END})
builder.add_edge("triage_agent", "supervisor")
builder.add_edge("reply_agent", "supervisor")
graph = builder.compile()
