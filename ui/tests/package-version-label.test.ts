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

  it("names the version count when an issue spans more than one installed version", () => {
    expect(packageVersionLabel({ packages: ["ws@8.5.0"], current_version: "8.5.0", package_versions: ["8.17.0", "8.5.0"] })).toBe("ws · 2 versions");
    expect(packageVersionLabel({ packages: ["@scope/pkg@1.0.0"], current_version: "1.0.0", package_versions: ["1.0.0", "2.0.0"], package_version_count: 3 })).toBe("@scope/pkg · 3 versions");
    expect(packageVersionLabel({ packages: ["ws@8.5.0"], current_version: "8.5.0", package_versions: ["8.5.0"] })).toBe("ws@8.5.0");
  });
});
