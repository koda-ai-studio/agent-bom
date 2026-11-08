import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const UI_ROOT = process.cwd();
const SCAN_DIRS = ["app", "components", "lib", "hooks"];
// Set at runtime through inline styles or next/font, not in a stylesheet.
const RUNTIME_PREFIXES = ["--graph-", "--font-geist-", "--tw-"];

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out = out.concat(walk(full));
    else if (/\.(tsx?|css)$/.test(entry)) out.push(full);
  }
  return out;
}

describe("design token references", () => {
  it("only reads custom properties that a stylesheet or the same file defines", () => {
    const files = SCAN_DIRS.flatMap((dir) => walk(path.join(UI_ROOT, dir)));
    const defined = new Set<string>();
    for (const file of files.filter((name) => name.endsWith(".css"))) {
      for (const match of readFileSync(file, "utf8").matchAll(/(--[\w-]+)\s*:/g)) defined.add(match[1]!);
    }
    const undefinedRefs: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(/var\((--[\w-]+)/g)) {
        const name = match[1]!;
        if (name.endsWith("-") || defined.has(name)) continue;
        if (RUNTIME_PREFIXES.some((prefix) => name.startsWith(prefix))) continue;
        if (source.includes(`"${name}"`) || source.includes(`'${name}'`) || source.includes(`${name}:`)) continue;
        undefinedRefs.push(`${path.relative(UI_ROOT, file)}: ${name}`);
      }
    }
    // An undefined color token silently inherits, e.g. near-white text on a light accent button.
    expect([...new Set(undefinedRefs)]).toEqual([]);
  });
});
