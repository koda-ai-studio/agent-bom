import { describe, expect, it } from "vitest";

import { uniqueCredentialNames } from "@/app/agents/agent-display";
import { formatInventoryAgentLabel, topologyAgentDisplayName } from "@/lib/agent-topology-graph";
import { agentDisplayName, entityIdHint, formatEntityId, serverDisplayName } from "@/lib/display-name";
import { formatExposureEntityTitle } from "@/lib/entity-display";
import { formatFrameworkCoverage, frameworkCoverageCounts } from "@/lib/framework-coverage";
import type { Agent } from "@/lib/api";

describe("one display name per entity", () => {
  it("formats the id the same way on every surface", () => {
    const id = "langchain-service";
    const expected = "LangChain Service";
    expect(agentDisplayName(id)).toBe(expected);
    expect(formatInventoryAgentLabel(id)).toBe(expected);
    expect(formatExposureEntityTitle(id, "agent")).toBe(expected);
    expect(topologyAgentDisplayName({ name: id, mcp_servers: [] } as unknown as Agent)).toBe(expected);
  });

  it("never invents words for servers", () => {
    expect(serverDisplayName("pharmacy-gateway-05")).toBe("Pharmacy Gateway 05");
    expect(formatExposureEntityTitle("pharmacy-gateway-05", "server")).toBe("Pharmacy Gateway 05");
    expect(formatExposureEntityTitle("github", "server")).toBe("GitHub");
  });

  it("prefers the recorded display name and keeps the id as a hint", () => {
    expect(agentDisplayName("langchain-service", "LangChain Service Agent")).toBe("LangChain Service Agent");
    expect(agentDisplayName("langchain-service", "  ")).toBe("LangChain Service");
    expect(entityIdHint("langchain-service", "LangChain Service")).toBe("langchain-service");
    expect(entityIdHint("Support Copilot", "Support Copilot")).toBeUndefined();
    expect(formatEntityId("Cursor First-Run Workspace")).toBe("Cursor First-Run Workspace");
    expect(agentDisplayName("")).toBe("Unknown agent");
  });
});

describe("credentials count once per name", () => {
  it("does not double-count a credential two agents share", () => {
    const server = (env: Record<string, string>, named: string[] = []) => ({ name: "s", env, credential_env_vars: named, packages: [] });
    const agents = [
      { name: "a", mcp_servers: [server({ OPENAI_API_KEY: "***", LOG_LEVEL: "info" })] },
      { name: "b", mcp_servers: [server({ OPENAI_API_KEY: "***" }, ["GITHUB_TOKEN"])] },
    ] as unknown as Agent[];
    expect([...uniqueCredentialNames(agents)].sort()).toEqual(["GITHUB_TOKEN", "OPENAI_API_KEY"]);
  });
});

describe("one definition of frameworks covered", () => {
  const frameworks = [
    { kind: "scored" as const, pass: 2, warn: 0, fail: 20 },
    { kind: "scored" as const, pass: 0, warn: 0, fail: 0 },
    { kind: "applicability" as const, pass: 0, warn: 0, fail: 0 },
    { kind: "applicability" as const, pass: 0, warn: 0, fail: 0, disabled: true },
  ];

  it("splits control frameworks from risk mappings and skips disabled ones", () => {
    expect(frameworkCoverageCounts(frameworks)).toEqual({
      tracked: 3,
      controlFrameworks: 2,
      evaluatedControlFrameworks: 1,
      riskMappings: 1,
    });
    expect(formatFrameworkCoverage(frameworkCoverageCounts(frameworks))).toBe("2 control frameworks · 1 risk mapping");
  });
});
