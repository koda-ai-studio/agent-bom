import { expect, it } from "vitest";
import { investigationPathRows } from "@/lib/investigation-path-rows";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

it("keeps authoritative queue rank when a later path is chosen for the preview", () => {
  const paths = ["a", "b", "c"].map(source => ({ source, target: "finding", hops: [source, "finding"], edges: ["vulnerable_to"], composite_risk: 50, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2026-1000"] } satisfies AttackPath));
  const nodes = new Map(["a", "b", "c", "finding"].map(id => [id, { id, entity_type: id === "finding" ? "vulnerability" : "server", label: id, attributes: {}, dimensions: {}, severity: "high" } as UnifiedNode]));
  const rows = investigationPathRows([paths[0]!, paths[2]!], [], nodes, paths);
  expect(rows.map(row => row.rank)).toEqual([1, 3]);
  expect(rows[1]?.title).toBe("C → finding");
  expect(rows.every(row => row.cve === "CVE-2026-1000")).toBe(true);
});
