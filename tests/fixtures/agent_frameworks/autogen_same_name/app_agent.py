from autogen_agentchat.agents import AssistantAgent


def weather_tool(city: str) -> str:
    return city


assistant = AssistantAgent(name="assistant", model_client=None, tools=[weather_tool])
