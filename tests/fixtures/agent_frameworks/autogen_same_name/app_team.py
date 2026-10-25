from autogen_agentchat.agents import AssistantAgent


def team_lookup(query: str) -> str:
    return query


assistant = AssistantAgent(name="assistant", model_client=None, tools=[team_lookup])
