import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

// A 50-200 chromatic text shade is near-white: unreadable on the light theme's
// pale surfaces. It needs a dark: variant chain, or a class string that pins an
// always-dark background (a *-900/950 chip).
const PALE_TEXT =
  /(?:^|[\s"'`([{])((?:[\w.&>[\]-]+:)*)!?text-(?:amber|yellow|emerald|red|sky|orange|rose|green|blue|violet|cyan|teal|lime|indigo|purple|fuchsia|pink)-(?:50|100|200)(?:\/\d+)?(?![\w-])/g;
const ALWAYS_DARK_BACKGROUND = /(?:^|\s)bg-(?:[a-z]+)-(?:900|950)(?:\/(?:[4-9]\d|100))?(?=\s|$)/;
const CLASS_STRING = /["'`]([^"'`\n]*)["'`]/g;

const UI_ROOT = process.cwd();

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out = out.concat(walk(full));
    else if (/\.(tsx?|jsx?)$/.test(entry)) out.push(full);
  }
  return out;
}

export function paleTextViolations(source: string): string[] {
  const violations: string[] = [];
  for (const [, classes = ""] of source.matchAll(CLASS_STRING)) {
    if (ALWAYS_DARK_BACKGROUND.test(classes)) continue;
    for (const match of classes.matchAll(PALE_TEXT)) {
      if (!(match[1] ?? "").includes("dark:")) violations.push(match[0].trim());
    }
  }
  return violations;
}

describe("pale text light-theme guard", () => {
  it("flags pale text without a dark: variant and allows it on always-dark chips", () => {
    expect(paleTextViolations('<p className="text-sm text-amber-100/90">')).toEqual(["text-amber-100/90"]);
    expect(paleTextViolations('<p className="text-amber-900 dark:text-amber-100/90">')).toEqual([]);
    expect(paleTextViolations('<span className="bg-sky-950/80 text-sky-100">')).toEqual([]);
    expect(paleTextViolations('<span className="bg-sky-950/20 text-sky-100">')).toEqual(["text-sky-100"]);
  });

  it("has no light-invisible pale text anywhere in the UI source", () => {
    const violations = ["app", "components", "lib", "hooks"].flatMap((dir) => {
      const base = path.join(UI_ROOT, dir);
      let files: string[] = [];
      try {
        files = walk(base);
      } catch {
        return [];
      }
      return files.flatMap((file) =>
        paleTextViolations(readFileSync(file, "utf8")).map((hit) => `${path.relative(UI_ROOT, file)}: ${hit}`),
      );
    });
    expect(violations).toEqual([]);
  });
});
