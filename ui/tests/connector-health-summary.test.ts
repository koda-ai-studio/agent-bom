import { describe, expect, it } from "vitest";

import { connectorHealthSummary } from "@/lib/connector-health-summary";

const row = (connector: string, state: string) => ({ connector, state, message: "", api_version: null });

describe("connectorHealthSummary", () => {
  it("says the probe is not enabled instead of reporting 0 healthy", () => {
    const summary = connectorHealthSummary([row("jira", "disabled"), row("slack", "disabled")]);
    expect(summary.value).toBe("Not enabled");
    expect(summary.allHealthy).toBe(false);
  });

  it("counts only probed connectors and names the ones not enabled", () => {
    const summary = connectorHealthSummary([row("jira", "healthy"), row("slack", "disabled"), row("servicenow", "auth_failed")]);
    expect(summary.value).toBe("1/2");
    expect(summary.hint).toBe("1 not enabled");
    expect(summary.allHealthy).toBe(false);
  });

  it("reports all healthy when every probed connector is healthy", () => {
    const summary = connectorHealthSummary([row("jira", "healthy")]);
    expect(summary).toEqual({ value: "1/1", hint: undefined, allHealthy: true });
  });

  it("reports nothing loaded", () => {
    expect(connectorHealthSummary([]).value).toBe("Not reported");
  });
});
