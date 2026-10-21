import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { agentDisplayName, agentRecordDisplayName } from "@/lib/display-name";

const constants = readFileSync(resolve(__dirname, "../../src/agent_bom/demo_estate/showcase_constants.py"), "utf8");
const block = constants.match(/SHOWCASE_AGENTS: dict\[str, str\] = \{([\s\S]*?)\n\}/)?.[1] ?? "";
const agents = [...block.matchAll(/"([^"]+)":\s*"([^"]+)"/g)].map(([, id, label]) => [id!, label!] as const);

describe("one agent display name", () => {
  it("parses the showcase agents", () => {
    expect(agents.length).toBeGreaterThanOrEqual(5);
  });

  it.each(agents)("%s is recorded under the name every id-only surface formats", (id, label) => {
    expect(agentDisplayName(id)).toBe(label);
    expect(agentDisplayName(id, label)).toBe(label);
  });
});

const shared = JSON.parse(
  readFileSync(resolve(__dirname, "../../tests/fixtures/contracts/agent_display_names.json"), "utf8"),
) as { cases: { id: string; recorded: string | null; expected: string }[] };

describe("the API and UI share one agent display-name rule", () => {
  it("reads the shared case table", () => {
    expect(shared.cases.length).toBeGreaterThanOrEqual(10);
  });

  it.each(shared.cases.map((c) => [c.id, c.recorded, c.expected] as const))("%j / %j -> %j", (id, recorded, expected) => {
    expect(agentDisplayName(id, recorded)).toBe(expected);
  });

  it("prefers the API's resolved display_name over re-deriving it", () => {
    expect(agentRecordDisplayName({ name: "laptop-7f3a", display_name: "Finance laptops" })).toBe("Finance laptops");
    expect(agentRecordDisplayName({ name: "laptop-7f3a", display_name: "  ", enrollment_name: "Fleet" })).toBe("Fleet");
    expect(agentRecordDisplayName({ name: "langchain-service" })).toBe("LangChain Service");
  });
});
