# LangGraph tool team fixture

A supervisor `StateGraph` routes to two `create_agent` workers, each with one
`@tool`, and both workers return to the supervisor. Synthetic names only; the
provider key is an env-var name. The tests write the pinned manifest at run
time, so nothing here is a real dependency declaration. Never execute it.
