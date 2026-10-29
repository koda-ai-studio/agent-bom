"use client";

import { useState, type ReactNode } from "react";
import { ASSET_BASE } from "@/lib/asset-base";

/** The language symbol follows the recorded ecosystem; the badge names PyPI. */
export function GraphPackageGlyph({ ecosystem, fallback }: {
  ecosystem?: string | undefined;
  fallback: ReactNode;
}) {
  const [failed, setFailed] = useState(false);
  if (ecosystem !== "pypi" || failed) return fallback;
  // The attributed mark is bundled locally; rendering makes no registry request.
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={`${ASSET_BASE}/logos/python.svg`} alt="Python package"
    style={{ width: "var(--graph-node-icon-size, 32px)", height: "var(--graph-node-icon-size, 32px)" }}
    className="h-8 w-8 object-contain" onError={() => setFailed(true)} />;
}
