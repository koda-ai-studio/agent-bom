from agents import Agent


def build_billing():
    return Agent(name="helper", instructions="billing")


def build_support():
    return Agent(name="helper", instructions="support")
