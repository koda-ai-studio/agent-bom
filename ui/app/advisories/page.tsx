"use client";

import { Suspense } from "react";

import { AdvisoriesWorkspace } from "@/components/advisories/advisories-workspace";
import { PageLoadingState } from "@/components/states/page-state";

export default function AdvisoriesPage() {
  return (
    <Suspense fallback={<PageLoadingState title="Loading advisories" detail="Reading the advisory workspace." />}>
      <AdvisoriesWorkspace />
    </Suspense>
  );
}
