import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { PAGE_LANE_META } from "@/lib/page-lanes";

const css = readFileSync(path.join(process.cwd(), "app/globals.css"), "utf8");
const LIGHT_START = css.indexOf(':root[data-theme="light"]');

type Rgba = [number, number, number, number];

function block(theme: "dark" | "light"): Record<string, string> {
  const start = theme === "light" ? LIGHT_START : css.indexOf(":root {");
  const body = css.slice(start, css.indexOf("\n}", start));
  const vars: Record<string, string> = {};
  for (const match of body.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)) vars[match[1]!] = match[2]!.trim();
  return vars;
}

const THEMES = { dark: block("dark"), light: { ...block("dark"), ...block("light") } };

function resolve(theme: keyof typeof THEMES, token: string): Rgba {
  let value = THEMES[theme][token];
  for (let hops = 0; value?.startsWith("var("); hops += 1) {
    if (hops > 5) throw new Error(`${token} does not resolve`);
    value = THEMES[theme][value.slice(4, -1).trim()];
  }
  if (!value) throw new Error(`${token} is not defined for ${theme}`);
  const hex = value.match(/^#([0-9a-f]{6})$/i);
  if (hex) {
    const n = parseInt(hex[1]!, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  const rgba = value.match(/^rgba?\(([^)]+)\)$/);
  if (!rgba) throw new Error(`${token}: unsupported colour ${value}`);
  const [r, g, b, a = "1"] = rgba[1]!.split(",").map((part) => part.trim());
  return [Number(r), Number(g), Number(b), Number(a)];
}

function over(top: Rgba, bottom: Rgba): Rgba {
  const a = top[3];
  return [0, 1, 2].map((i) => top[i]! * a + bottom[i]! * (1 - a)).concat(1) as Rgba;
}

function luminance([r, g, b]: Rgba): number {
  const channel = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(theme: keyof typeof THEMES, fg: string, ...layers: string[]): number {
  const base = resolve(theme, "--background");
  const bg = layers.reduceRight<Rgba>((acc, layer) => over(resolve(theme, layer), acc), base);
  const text = over(resolve(theme, fg), bg);
  const [hi, lo] = [luminance(text), luminance(bg)].sort((a, b) => b - a);
  return (hi! + 0.05) / (lo! + 0.05);
}

const SURFACES = ["--background", "--surface-panel", "--surface", "--surface-elevated"];
const LABEL_TOKENS = [
  "--text-secondary",
  "--text-tertiary",
  "--accent",
  "--accent-strong",
  "--status-success",
  "--status-warn",
  "--status-danger",
];
const LANE_TOKENS = [...new Set(Object.values(PAGE_LANE_META).map((meta) => meta.accent.slice(4, -1)))];

describe.each(["dark", "light"] as const)("%s theme label contrast", (theme) => {
  it.each([...LABEL_TOKENS, ...LANE_TOKENS])("%s reads at 4.5:1 on every surface", (token) => {
    for (const surface of SURFACES) {
      expect(contrast(theme, token, surface), `${token} on ${surface}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each(["success", "warn", "danger"])("status-%s text reads at 4.5:1 on its own tinted chip", (tone) => {
    for (const surface of SURFACES) {
      expect(contrast(theme, `--status-${tone}`, `--status-${tone}-bg`, surface)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps lane accents legible inside the lane scope chip", () => {
    // The chip tints its own background with the lane hue at 8%; the label
    // must still clear 4.5:1 on that tint over the page background.
    for (const token of LANE_TOKENS) {
      const tinted = [...resolve(theme, token).slice(0, 3), 0.08] as Rgba;
      THEMES[theme]["--lane-chip-probe"] = `rgba(${tinted.join(", ")})`;
      expect(contrast(theme, token, "--lane-chip-probe"), token).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps filled accent actions and the selected segment legible", () => {
    expect(contrast(theme, "--accent-contrast", "--accent")).toBeGreaterThanOrEqual(4.5);
    expect(contrast(theme, "--accent-contrast", "--accent-strong")).toBeGreaterThanOrEqual(4.5);
    expect(contrast(theme, "--accent-strong", "--accent-soft", "--surface-muted")).toBeGreaterThanOrEqual(4.5);
  });

  it("gives form-field boundaries 3:1 against the surfaces they sit on", () => {
    for (const surface of SURFACES) {
      expect(contrast(theme, "--border-strong", surface), surface).toBeGreaterThanOrEqual(3);
    }
  });
});

describe("page lane accents", () => {
  it("come from theme tokens, never a fixed hex", () => {
    for (const [lane, meta] of Object.entries(PAGE_LANE_META)) {
      expect(meta.accent, lane).toMatch(/^var\(--[a-z0-9-]+\)$/);
    }
  });
});
