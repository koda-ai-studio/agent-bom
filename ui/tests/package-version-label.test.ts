import { describe, expect, it } from "vitest";

import { packageVersionLabel } from "@/lib/package-version-label";

describe("package version label", () => {
  it("never doubles a version the package label already carries", () => {
    expect(packageVersionLabel({ packages: ["pillow@9.0.0"], current_version: "9.0.0" })).toBe("pillow@9.0.0");
  });

  it("joins a bare name with its version", () => {
    expect(packageVersionLabel({ packages: ["pillow"], current_version: "9.0.0" })).toBe("pillow@9.0.0");
    expect(packageVersionLabel({ packages: ["@scope/pkg"], current_version: "1.2.3" })).toBe("@scope/pkg@1.2.3");
  });

  it("keeps the label as-is without a version, and a scoped package's leading @ is not a version", () => {
    expect(packageVersionLabel({ packages: ["pillow"], current_version: undefined })).toBe("pillow");
    expect(packageVersionLabel({ packages: ["@scope/pkg@1.2.3"], current_version: "1.2.3" })).toBe("@scope/pkg@1.2.3");
    expect(packageVersionLabel({ packages: [], current_version: "1" })).toBe("");
  });
});
