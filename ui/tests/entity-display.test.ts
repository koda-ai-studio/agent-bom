import { describe, expect, it } from "vitest";

import {
  formatExposureEntityDisplay,
  formatExposurePathSequence,
} from "@/lib/entity-display";

describe("entity-display", () => {
  it("formats agent and server labels for executive-readable attack paths", () => {
    expect(formatExposureEntityDisplay("claude-desktop", "agent", { agent_type: "claude-desktop" })).toEqual({
      title: "Claude Desktop",
      subtitle: "Claude Desktop",
    });
    expect(formatExposureEntityDisplay("github", "server", { transport: "stdio", protocol: "mcp" })).toEqual({
      title: "GitHub",
      subtitle: "stdio MCP server",
    });
    expect(formatExposureEntityDisplay("github-enterprise MCP", "server", { transport: "sse", protocol: "mcp" })).toEqual({
      title: "github-enterprise MCP",
      subtitle: "sse MCP server",
    });
  });

  it("splits package coordinates into name and version subtitle", () => {
    expect(formatExposureEntityDisplay("form-data@4.0.0", "package", { ecosystem: "npm" })).toEqual({
      title: "form-data",
      subtitle: "v4.0.0 · NPM",
    });
  });

  it("builds arrow-separated path titles", () => {
    expect(
      formatExposurePathSequence([
        { label: "claude-desktop", role: "agent", attributes: { agent_type: "claude-desktop" } },
        { label: "github", role: "server" },
        { label: "form-data@4.0.0", role: "package" },
        { label: "CVE-2025-7783", role: "finding" },
      ]),
    ).toBe("Claude Desktop → GitHub → form-data → CVE-2025-7783");
  });
});

it("entity kinds do not assert reachability or secret exposure without assessment", () => {
  expect(formatExposureEntityDisplay("CVE-fixture", "finding").subtitle).toBe("Vulnerability finding");
  expect(formatExposureEntityDisplay("TOKEN_REF", "credential").subtitle).toBe("Credential reference");
});

it("requires structured protocol evidence before calling a generic server MCP", () => {
  expect(formatExposureEntityDisplay("internal-api", "server").subtitle).toBe("Server");
  expect(formatExposureEntityDisplay("MCP production", "server", { transport: "http" }).subtitle).toBe("http server");
});

it("shows identifiers exactly as recorded, never re-cased", () => {
  expect(formatExposureEntityDisplay("project:agent-a1157c3d9e", "agent").title).toBe("project:agent-a1157c3d9e");
  expect(formatExposureEntityDisplay("OPENAI_API_KEY", "credential").title).toBe("OPENAI_API_KEY");
  expect(formatExposureEntityDisplay("arn:aws:eks:us-east-1:111122223333:cluster/prod", "cluster").title).toBe("arn:aws:eks:us-east-1:111122223333:cluster/prod");
  expect(formatExposureEntityDisplay("staging-eu", "environment").title).toBe("Staging Eu");
});
