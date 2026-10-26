# LangGraph supervisor fixture

A tiny, synthetic LangGraph project for the framework-topology tests. A
supervisor routes work to two sub-agents through a conditional edge, one
sub-agent is itself a compiled subgraph, and one node hands off with
`Command(goto=...)`. Nothing here runs: there are no API keys, endpoints,
real names or network calls, and the node functions only return their state.

Constructs covered, in `app.py`:

| Construct | Line of interest |
|---|---|
| `add_node(name, fn)` and `add_node(fn)` (name inferred) | research / writer / `review` |
| `add_edge(START, "supervisor")` and `set_finish_point("writer")` | entry and finish points |
| `add_conditional_edges("supervisor", route, {...})` | labelled branches, one to `END` |
| `add_conditional_edges("review", decide)` with no path map | unresolved dynamic route |
| `add_node("research", research_builder.compile())` | subgraph nested under its node |
| `return Command(goto="writer")` | declared handoff |

The dependency manifest is written by the tests at run time (see the parent
README), so the repository self-scan never treats this folder as a real
project.
