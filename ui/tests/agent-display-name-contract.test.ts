import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { agentDisplayName } from "@/lib/display-name";

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
