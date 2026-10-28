import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { ActivityWindow } from "@/app/gateway/GatewayActivityWindow";
import { activity } from "./fixtures/gateway-activity";

it("separates identical agent names by reported origin and drills into exactly that group", () => {
  const events = [
    { ...activity(1), source_id: "east", session_id: "session-east" },
    { ...activity(2), source_id: "west", session_id: "session-west", decision: "deny" },
  ];
  render(<ActivityWindow events={events} onFreeze={vi.fn()} />);
  const groups = screen.getByRole("region", { name: "Reported activity groups" });
  const rows = within(groups).getAllByRole("button");
  expect(rows).toHaveLength(2);
  expect(rows[0]).toHaveTextContent("west");
  expect(rows[0]).toHaveTextContent("1 blocked");
  fireEvent.click(rows[0]!);
  expect(screen.getAllByTestId("gateway-activity-row")).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: /Inspect/ }));
  expect(within(screen.getByRole("dialog")).getByText("west")).toBeInTheDocument();
  expect(within(screen.getByRole("dialog")).getByText("session-west")).toBeInTheDocument();
});

it("keeps warning groups ahead of repetitive allows without hiding the allowed events", () => {
  const events = Array.from({ length: 80 }, (_, i) => ({ ...activity(i), source_id: "allowed-origin", session_id: "a" }));
  events.push({ ...activity(100), source_id: "warning-origin", session_id: "w", decision: "warn", event_type: "gateway.runtime_profile.warned" });
  render(<ActivityWindow events={events} onFreeze={vi.fn()} />);
  const rows = within(screen.getByRole("region", { name: "Reported activity groups" })).getAllByRole("button");
  expect(rows).toHaveLength(2);
  expect(rows[0]).toHaveTextContent("warning-origin");
  expect(rows[0]).toHaveTextContent("1 warning");
  expect(rows[1]).toHaveTextContent("80 events");
  expect(screen.getByText(/not a verified unique-agent count/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Events" }));
  expect(screen.getAllByTestId("gateway-activity-row")).toHaveLength(50);
  expect(screen.getByText("1–50 of 81 matching events")).toBeInTheDocument();
});

it("does not merge missing origins, distinct collector principals, sessions or profiles", () => {
  const base = { ...activity(1), source_id: "collector", session_id: "session" };
  const events = [
    { ...activity(100), source_id: "", session_id: "" }, { ...activity(101), source_id: "", session_id: "" }, base,
    { ...base, event_id: "session2", session_id: "other" },
    { ...base, event_id: "profile2", profile_id: "other" },
    { ...base, event_id: "principal2", submission_provenance: { submitter_principal_id: "operator-other" } },
    { ...base, event_id: "reported2", submission_provenance: { reported_source_id: "other" } },
  ];
  render(<ActivityWindow events={events} onFreeze={vi.fn()} />);
  expect(within(screen.getByRole("region", { name: "Reported activity groups" })).getAllByRole("button")).toHaveLength(7);
  expect(screen.getAllByText("Origin not recorded")).toHaveLength(2);
});
