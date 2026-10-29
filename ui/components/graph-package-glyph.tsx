"use client";

import { useState, type ReactNode } from "react";
import { ASSET_BASE } from "@/lib/asset-base";

const ECOSYSTEM_MARKS = new Map([
  ["pypi", { asset: "python", label: "Python package", monochrome: false }],
  ["npm", { asset: "npm", label: "npm package", monochrome: true }],
  ["golang", { asset: "go", label: "Go package", monochrome: true }],
  ["cargo", { asset: "rust", label: "Rust package", monochrome: true }],
  ["nuget", { asset: "nuget", label: "NuGet package", monochrome: true }],
  ["gem", { asset: "rubygems", label: "RubyGems package", monochrome: true }],
  ["composer", { asset: "packagist", label: "Packagist package", monochrome: true }],
]);

/** Recorded ecosystem only; the separate badge retains the registry name. */
export function GraphPackageGlyph({ ecosystem, fallback }: {
  ecosystem?: string | undefined;
  fallback: ReactNode;
}) {
  const [failedAsset, setFailedAsset] = useState<string | null>(null);
  const mark = ECOSYSTEM_MARKS.get(ecosystem ?? "");
  if (!mark || failedAsset === mark.asset) return fallback;
  // Attributed marks are bundled locally; rendering makes no registry request.
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={`${ASSET_BASE}/logos/${mark.asset}.svg`} alt={mark.label}
    style={{ width: "var(--graph-node-icon-size, 32px)", height: "var(--graph-node-icon-size, 32px)" }}
    className={`h-8 w-8 object-contain${mark.monochrome ? " dark:invert" : ""}`} onError={() => setFailedAsset(mark.asset)} />;
}
