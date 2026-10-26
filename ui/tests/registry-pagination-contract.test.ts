import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("MCP catalog pagination", () => {
  it("renders one 25-row page of the filtered catalog, never the whole list", () => {
    const source = readFileSync(path.join(process.cwd(), "app/registry/page.tsx"), "utf8");
    expect(source).toContain("const REGISTRY_PAGE_SIZE = 25;");
    expect(source).not.toMatch(/filtered\??\.map\(/);
    expect(source.match(/visible\.map\(/g)).toHaveLength(2);
    expect(source).toContain("<PaginationBar");
  });
});
