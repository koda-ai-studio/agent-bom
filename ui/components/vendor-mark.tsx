"use client";

import { GraphProviderMark } from "@/components/graph-provider-mark";
import { vendorSourceFor } from "@/lib/agent-source";

/** A recorded vendor id as its canonical inline mark; vendors without a bundled mark get a labelled monogram. */
export function VendorMark({ vendor, className = "h-4 w-4" }: { vendor: string; className?: string }) {
  const source = vendorSourceFor(vendor) ?? {
    id: vendor, label: vendor, src: null, monogram: vendor.slice(0, 2).toUpperCase(), accent: "#70809c",
  };
  return <GraphProviderMark source={source} attributes={{ cloud_provider: vendor }} className={`graph-provider-mark-inline ${className}`} />;
}
