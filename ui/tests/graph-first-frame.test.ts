import { describe, expect, it } from "vitest";

import { graphFirstFramePending } from "@/lib/graph-first-frame";

const base = { awaitingAutoFocus: true, graphLoaded: true, queueSettled: true, agentCount: 0 };

describe("graphFirstFramePending", () => {
  it("holds the canvas until the graph page and the path queue have both arrived", () => {
    expect(graphFirstFramePending({ ...base, graphLoaded: false })).toBe(true);
    expect(graphFirstFramePending({ ...base, queueSettled: false })).toBe(true);
  });

  it("holds a frame that the agent auto-focus is about to replace", () => {
    // The findings-only page merged with queued agents would flash, then refocus.
    expect(graphFirstFramePending({ ...base, agentCount: 3 })).toBe(true);
  });

  it("renders once nothing will replace the frame", () => {
    expect(graphFirstFramePending(base)).toBe(false);
    expect(graphFirstFramePending({ ...base, awaitingAutoFocus: false, agentCount: 3, queueSettled: false })).toBe(false);
  });
});
