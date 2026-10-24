import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { RemediationCardList } from "@/components/remediation-mobile-cards";
import type { RemediationItem } from "@/lib/api";

const item = {
  package: "langchain", current_version: "0.0.150", fixed_version: "0.0.325", severity: "critical", is_kev: true, impact_score: 8.4,
  vulnerabilities: ["CVE-2023-36258", "CVE-2023-29374", "CVE-2023-36188"], affected_agents: ["a", "b"], exposed_credentials: ["OPENAI_API_KEY"],
  owasp_tags: ["LLM05"], atlas_tags: ["AML.T0010"], risk_narrative: "Agent reaches a code execution path.", command: "pip install langchain==0.0.325",
  verify_command: "pip show langchain", reachable_tools: ["run_python"], ecosystem: "pypi",
} as unknown as RemediationItem;

it("stacks every table column into one card per package, nothing clipped behind a scroll", () => {
  const onCreateTicket = vi.fn();
  render(<RemediationCardList items={[item]} ticketFor={() => undefined} onCreateTicket={onCreateTicket} />);
  const card = screen.getByTestId("remediation-card");
  for (const text of ["langchain", "current 0.0.150", "critical", "KEV", "Fix 0.0.325", "Risk 8.4", "2 agents", "1 credential exposed", "CVE-2023-36258", "+1", "LLM05"]) {
    expect(card).toHaveTextContent(text);
  }
  fireEvent.click(within(card).getByRole("button", { name: /Ticket/ }));
  expect(onCreateTicket).toHaveBeenCalledWith(item);
  fireEvent.click(within(card).getByRole("button", { name: /Details/ }));
  expect(card).toHaveTextContent("pip install langchain==0.0.325");
  expect(card).toHaveTextContent("pip show langchain");
});

it("says when a package has no fixed version", () => {
  render(<RemediationCardList items={[{ ...item, fixed_version: null } as unknown as RemediationItem]} ticketFor={() => undefined} onCreateTicket={vi.fn()} />);
  expect(screen.getByTestId("remediation-card")).toHaveTextContent("No fixed version");
});

it("shows the credentials the servers hold beside exposure by impact, and nothing when not recorded", () => {
  const held = { ...item, server_credentials: ["AWS_ROLE", "OPENAI_API_KEY", "STRIPE_KEY"], server_credential_count: 3 } as unknown as RemediationItem;
  const { unmount } = render(<RemediationCardList items={[held]} ticketFor={() => undefined} onCreateTicket={vi.fn()} />);
  const cell = within(screen.getByTestId("remediation-card")).getByText("3 credentials on server");
  expect(cell.getAttribute("title")).toMatch(/hosting servers hold.*not filtered by this advisory's impact/);
  unmount();
  render(<RemediationCardList items={[{ ...item, server_credential_count: null } as unknown as RemediationItem]} ticketFor={() => undefined} onCreateTicket={vi.fn()} />);
  expect(screen.getByTestId("remediation-card")).not.toHaveTextContent("on server");
});
