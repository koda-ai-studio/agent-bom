import { describe, expect, it } from "vitest";

import { labelSegments } from "@/lib/graph-label-breaks";

describe("graph label line breaks", () => {
  it("offers a break only after a separator, never inside a token", () => {
    expect(labelSegments("GCS_SERVICE_ACCOUNT_KEY")).toEqual(["GCS_", "SERVICE_", "ACCOUNT_", "KEY"]);
    expect(labelSegments("SNOWFLAKE_PASSWORD")).toEqual(["SNOWFLAKE_", "PASSWORD"]);
    // A version number reads as one token: "cryptography@" / "39.0.0", never "39." / "0.0".
    expect(labelSegments("pillow@9.0.0")).toEqual(["pillow@", "9.0.0"]);
    expect(labelSegments("cryptography@39.0.0")).toEqual(["cryptography@", "39.0.0"]);
    expect(labelSegments("github-enterprise MCP")).toEqual(["github-", "enterprise ", "MCP"]);
    expect(labelSegments("services/research-mcp")).toEqual(["services/", "research-", "mcp"]);
  });

  it("keeps the full text when nothing is too long to fit a line", () => {
    for (const label of ["etl-server", "Data Pipeline", "CVE-2023-4863", "requests@2.28.0"]) {
      expect(labelSegments(label).join("")).toBe(label);
    }
  });

  it("ends an unbreakable token too long for one line with an ellipsis instead of splitting it", () => {
    const token = "Supercalifragilisticexpialidocious";
    const segments = labelSegments(`${token}_KEY`, 18);
    expect(segments[0]).toBe(`${token.slice(0, 17)}…`);
    expect(segments[0]!.length).toBe(18);
    expect(segments.slice(1)).toEqual(["KEY"]);
  });

  it("returns nothing for an empty label", () => {
    expect(labelSegments("")).toEqual([]);
  });
});
