import { describe, expect, it } from "vitest";
import { selectAttackPathQueue } from "@/lib/attack-path-queue";
import type { AttackPath } from "@/lib/graph-schema";
import { representativeAttackPaths } from "@/lib/attack-path-queue";

const path = (source: string, risk: number): AttackPath => ({
  source, target: "data", hops: [source, "data"], edges: ["can_access"],
  composite_risk: risk, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [],
});

describe("representative loaded-path preview", () => {
  it("includes different CVEs before repeating a family without mutating server order", () => {
    const repeated = Array.from({ length: 12 }, (_, i) => ({ ...path(`asset-${i}`, 99-i), vuln_ids: ["CVE-2025-1000"] }));
    const other = { ...path("different", 20), vuln_ids: ["CVE-2025-2000"] };
    const queue = [...repeated, other];
    const preview = representativeAttackPaths(queue, new Map(), 5);
    expect(preview[0]).toBe(queue[0]);
    expect(preview[1]).toBe(other);
    expect(preview).toHaveLength(5);
    expect(queue).toEqual([...repeated, other]);
    expect(new Set(preview).size).toBe(5);
  });

  it("keeps credential and tool exposure families distinct, without inventing paths", () => {
    const credential = { ...path("same", 80), credential_exposure: ["TOKEN_REF"] };
    const repeat = { ...credential, target: "another" };
    const tool = { ...path("same", 50), tool_exposure: ["shell"] };
    expect(representativeAttackPaths([credential, repeat, tool], new Map(), 2)).toEqual([credential, tool]);
  });

  it("is deterministic, bounded and retains the sole family when no alternative is loaded", () => {
    const queue = [path("a", 90), path("b", 80), path("c", 70)];
    expect(representativeAttackPaths(queue, new Map(), 2)).toEqual(queue.slice(0, 2));
    expect(representativeAttackPaths(queue, new Map(), 0)).toEqual([]);
    expect(representativeAttackPaths([], new Map(), 5)).toEqual([]);
  });
});

describe("canonical investigation queue", () => {
  it("preserves evidence-first server order despite higher-risk enrichment cards", () => {
    const witnessed = path("witnessed", 30), conditional = path("conditional", 95), extra = path("other", 99);
    expect(selectAttackPathQueue([witnessed, conditional], [extra, conditional], new Map(), {})).toEqual([witnessed, conditional]);
  });
  it("does not refill an authoritative empty page with out-of-scope cards", () => {
    expect(selectAttackPathQueue([], [path("other", 99)], new Map(), {})).toEqual([]);
  });
  it("keeps campaign filtering in the same authoritative order", () => {
    const first = path("first", 30), second = path("second", 95);
    expect(selectAttackPathQueue([first, second], [], new Map(), {}, ["second->data", "first->data"])).toEqual([first, second]);
  });
});
