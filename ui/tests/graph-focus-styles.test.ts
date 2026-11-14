import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const UI_ROOT = path.resolve(__dirname, "..");
const CSS = ["app/globals.css", "app/graph-motion.css"]
  .map((file) => readFileSync(path.join(UI_ROOT, file), "utf8"))
  .join("\n");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return /\.(tsx|ts)$/.test(entry) ? [full] : [];
  });
}

describe("graph focus and dimming styles", () => {
  it("live in the global stylesheets", () => {
    expect(CSS).toMatch(/\.lineage-node-dim\s*\{[^}]*opacity:\s*0\.15/);
    expect(CSS).toMatch(/\.lineage-node-focus\s*\{[^}]*z-index:\s*5/);
    expect(CSS).toMatch(/\.lineage-node-focus \.graph-entity-glyph,[\s\S]*?outline:\s*2px solid var\(--accent\)/);
    expect(CSS).toMatch(/\.node-critical-pulse \.graph-entity-glyph,[\s\S]*?box-shadow:/);
    expect(CSS).toMatch(/\.cluster-pill-pulse\s*\{[^}]*box-shadow:/);
  });

  it("do not pull the styled-jsx runtime into client pages", () => {
    const offenders = ["app", "components", "lib"]
      .flatMap((dir) => sourceFiles(path.join(UI_ROOT, dir)))
      .filter((file) => /<style\s+jsx/.test(readFileSync(file, "utf8")))
      .map((file) => path.relative(UI_ROOT, file));
    expect(offenders).toEqual([]);
  });
});
