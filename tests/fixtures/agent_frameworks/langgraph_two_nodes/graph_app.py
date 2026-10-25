from langgraph.graph import StateGraph


def planner(state):
    return state


def writer(state):
    return state


builder = StateGraph(dict)
builder.add_node("planner", planner)
builder.add_node("writer", writer)
builder.add_edge("planner", "writer")
graph = builder.compile()
