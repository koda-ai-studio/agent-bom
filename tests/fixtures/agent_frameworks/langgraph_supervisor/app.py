"""Synthetic LangGraph supervisor: fake data only, nothing runs."""

from typing import Literal

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command


def supervisor(state):
    return state


def route(state) -> Literal["research", "writer", "__end__"]:
    if state.get("needs_research"):
        return "research"
    if state.get("ready"):
        return "writer"
    return END


def search(state):
    return state


def summarize(state):
    return state


research_builder = StateGraph(dict)
research_builder.add_node("search", search)
research_builder.add_node("summarize", summarize)
research_builder.add_edge(START, "search")
research_builder.add_edge("search", "summarize")
research_builder.add_edge("summarize", END)


def writer(state):
    return state


def review(state) -> Command[Literal["writer"]]:
    return Command(goto="writer", update={"reviewed": True})


def decide(state):
    return state["next"]


builder = StateGraph(dict)
builder.add_node("supervisor", supervisor)
builder.add_node("research", research_builder.compile())
builder.add_node("writer", writer)
builder.add_node(review)
builder.add_edge(START, "supervisor")
builder.add_conditional_edges("supervisor", route, {"research": "research", "writer": "writer", "__end__": END})
builder.add_edge("research", "supervisor")
builder.add_conditional_edges("review", decide)
builder.set_finish_point("writer")
graph = builder.compile()
