"use client";

import { useState, type ReactNode } from "react";
import { ASSET_BASE } from "@/lib/asset-base";

/** Registry identity comes from the same recorded ecosystem as the text badge. */
export function GraphPackageGlyph({ ecosystem, fallback }: {
  ecosystem?: string | undefined;
  fallback: ReactNode;
}) {
  const [failed, setFailed] = useState(false);
  if (ecosystem !== "pypi" || failed) return fallback;
  // The attributed mark is bundled locally; rendering makes no registry request.
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={`${ASSET_BASE}/logos/pypi.svg`} alt="PyPI package"
    style={{ width: "var(--graph-node-icon-size, 32px)", height: "var(--graph-node-icon-size, 32px)" }}
    className="h-8 w-8 object-contain" onError={() => setFailed(true)} />;
}
