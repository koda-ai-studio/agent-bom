import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { SEVERITY_RING_CLASSES, type RingSeverity } from "@/lib/graph-node-badges";

const CSS = readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8");
const SEVERITIES: RingSeverity[] = ["critical", "high", "medium", "low"];

function token(block: string, name: string): string {
  const match = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(block);
  if (!match) throw new Error(`missing ${name}`);
  return match[1]!;
}

function themeBlock(selector: string): string {
  const start = CSS.indexOf(`${selector} {`);
  return CSS.slice(start, CSS.indexOf("\n}", start));
}

const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
const luminance = (hex: string) => {
  const [r, g, b] = rgb(hex).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
};
const contrast = (a: string, b: string) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
};
const hue = (hex: string) => {
  const [r, g, b] = rgb(hex) as [number, number, number];
  const max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min;
  if (d === 0) return 0;
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
};
const hueGap = (a: number, b: number) => Math.min(Math.abs(a - b), 360 - Math.abs(a - b));

const THEMES = {
  dark: { block: themeBlock(":root"), canvas: /:root \{ --graph-canvas: (#[0-9a-f]{6}); \}/i.exec(CSS)![1]! },
  light: { block: themeBlock(':root[data-theme="light"]'), canvas: /\[data-theme="light"\] \{ --graph-canvas: (#[0-9a-f]{6}); \}/i.exec(CSS)![1]! },
};

describe("severity ring tokens", () => {
  it("maps the four severities to four distinct ring tokens, reserved for finding rings", () => {
    const rings = SEVERITIES.map((severity) => SEVERITY_RING_CLASSES[severity]);
    expect(new Set(rings).size).toBe(4);
    for (const severity of SEVERITIES) {
      expect(SEVERITY_RING_CLASSES[severity]).toContain(`var(--severity-ring-${severity})`);
    }
  });

  it.each(Object.entries(THEMES))("keeps every ring at least 3:1 against the %s canvas and apart in hue", (_, theme) => {
    const colors = SEVERITIES.map((severity) => token(theme.block, `--severity-ring-${severity}`));
    for (const color of colors) expect(contrast(color, theme.canvas), color).toBeGreaterThanOrEqual(3);
    for (let i = 0; i < colors.length; i += 1) for (let j = i + 1; j < colors.length; j += 1) {
      expect(hueGap(hue(colors[i]!), hue(colors[j]!)), `${SEVERITIES[i]} vs ${SEVERITIES[j]}`).toBeGreaterThanOrEqual(18);
    }
  });
});
