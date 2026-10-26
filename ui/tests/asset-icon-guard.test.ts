import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { ASSET_KINDS } from "@/lib/asset-icon-registry";
import { ENTITY_ICONS } from "@/lib/entity-icons";
import { EntityType } from "@/lib/graph-schema";

const UI_ROOT = path.resolve(__dirname, "..");
const REGISTRY = path.join("lib", "asset-icon-registry.ts");

const ENTITY_KEYS = new Set<string>([
  ...Object.keys(ASSET_KINDS), ...Object.keys(ENTITY_ICONS), ...Object.values(EntityType),
  "cve", "data", "identity", "secret", "bucket", "function", "image", "workload",
]);

function sourceFiles(dir: string): string[] {
  return readdirSync(path.join(UI_ROOT, dir), { withFileTypes: true }).flatMap((entry) => {
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(relative);
    return /\.(ts|tsx)$/.test(entry.name) && !/\.(test|spec|stories)\./.test(entry.name) ? [relative] : [];
  });
}

function lucideImports(source: string): Set<string> {
  const names = new Set<string>();
  for (const match of source.matchAll(/import\s*\{([^}]*)\}\s*from\s*"lucide-react"/g)) {
    for (const part of match[1]!.split(",")) {
      const name = part.replace(/^\s*type\s+/, "").split(/\s+as\s+/).pop()!.trim();
      if (/^[A-Z]/.test(name)) names.add(name);
    }
  }
  return names;
}

/** `vulnerability: Bug`, `cve: { icon: Bug }`, `{ type: "agent", icon: Bot }` and `=== "vulnerability" ? Bug`. */
export function directEntityIconMaps(file: string, source: string): string[] {
  const icons = lucideImports(source);
  if (icons.size === 0) return [];
  const glyph = [...icons].join("|");
  const patterns = [
    new RegExp(String.raw`(?:^|[\s{,])"?([A-Za-z_]+)"?\s*:\s*(?:\{\s*icon\s*:\s*)?(${glyph})\b`, "gm"),
    new RegExp(String.raw`(?:^|[\s{,])"?([A-Za-z_]+)"?\s*:\s*\{[^{}\n]*?\bicon\s*:\s*(${glyph})\b`, "gm"),
    new RegExp(String.raw`type\s*:\s*"([A-Za-z_]+)"[^\n]*?icon\s*:\s*(${glyph})\b`, "g"),
    new RegExp(String.raw`===\s*"([A-Za-z_]+)"\s*\?\s*(${glyph})\b`, "g"),
  ];
  const hits: string[] = [];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (ENTITY_KEYS.has(match[1]!)) hits.push(`${file}: ${match[1]} → ${match[2]}`);
    }
  }
  return [...new Set(hits)];
}

describe("asset icon guard", () => {
  it("resolves entity glyphs only through the asset icon registry", () => {
    const files = ["app", "components", "lib", "hooks"].flatMap((dir) => sourceFiles(dir)).filter((file) => file !== REGISTRY);
    const hits = files.flatMap((file) => directEntityIconMaps(file, readFileSync(path.join(UI_ROOT, file), "utf8")));
    expect(hits).toEqual([]);
  });

  it("draws packages in shared components only with the registry package glyph", () => {
    const files = ["components", "lib", "hooks"].flatMap((dir) => sourceFiles(dir)).filter((file) => file !== REGISTRY);
    const importers = files.filter((file) => lucideImports(readFileSync(path.join(UI_ROOT, file), "utf8")).has("Package"));
    expect(importers).toEqual([]);
  });

  it("catches each direct-map shape it guards against", () => {
    const source = `import { Bug, Bot, Database } from "lucide-react";
const A = { vulnerability: Bug };
const B = { cve: { icon: Bug, tint: "" } };
const C = [{ type: "agent", label: "Agents", icon: Bot }];
const D = kind === "data_store" ? Database : Bot;
const E = { server: { label: "Server", icon: Database, tint: "" } };`;
    expect(directEntityIconMaps("x.tsx", source)).toEqual([
      "x.tsx: vulnerability → Bug", "x.tsx: cve → Bug", "x.tsx: server → Database", "x.tsx: agent → Bot",
      "x.tsx: data_store → Database",
    ]);
  });
});
