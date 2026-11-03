"""Synthetic declarations for passive scanning; never execute this fixture."""

from crewai import Agent, Crew, Process, Task


def read_evidence(text):
    return text


def format_report(text):
    return text


manager = Agent(role="Review Manager", goal="Coordinate a sample review", backstory="Synthetic coordinator", allow_delegation=True)
reader = Agent(role="Evidence Reader", goal="Read supplied sample text", backstory="Synthetic reader", tools=[read_evidence])
writer = Agent(role="Report Writer", goal="Format sample notes", backstory="Synthetic writer", tools=[format_report])
review = Task(description="Review supplied sample text", expected_output="Sample notes", agent=reader)
report = Task(description="Format sample notes", expected_output="Sample report", agent=writer, context=[review])
crew = Crew(agents=[reader, writer], tasks=[review, report], process=Process.hierarchical, manager_agent=manager)
