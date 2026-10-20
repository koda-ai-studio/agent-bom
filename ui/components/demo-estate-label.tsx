"use client";

import Link from "next/link";
import { FlaskConical } from "lucide-react";

import { useCaptureMode, useReferenceEvidenceLabMode } from "@/lib/use-capture-mode";

function hasDemoSeedSources(scanSources: string[] | undefined): boolean {
  if (!scanSources?.length) return false;
  return scanSources.some((source) => source.includes("demo"));
}

export function DemoEstateLabel({ scanSources }: { scanSources?: string[] | undefined }) {
  const captureMode = useCaptureMode();
  const referenceEvidenceLab = useReferenceEvidenceLabMode();
  const visible = captureMode || hasDemoSeedSources(scanSources);

  if (!visible) return null;

  // The chip sits in a size container so large text swaps to a short label instead of clipping to one letter.
  return (
    <div className="@container min-w-[30px] flex-[1_1000_7.5rem]">
    <Link
      href={referenceEvidenceLab
        ? "/security-graph?lens=attack-path&scan=reference-evidence-correlation-v1"
        : "/demo-estate"}
      id="demo-estate-watermark"
      className={`flex w-fit min-w-0 max-w-full items-center truncate rounded-full border border-emerald-500/40 bg-[color:var(--surface-elevated)]/95 px-3 py-1 @max-[4.5em]:px-[5px] font-medium uppercase tracking-[0.1em] text-emerald-700 shadow-md shadow-black/20 transition hover:border-emerald-500/70 hover:text-emerald-800 dark:text-emerald-200 dark:hover:text-emerald-100 ${
        referenceEvidenceLab
          ? "max-w-[min(32rem,calc(100vw-1.5rem))]"
          : "max-w-[min(18rem,calc(100vw-1.5rem))]"
      } text-xs`}
      aria-label={referenceEvidenceLab
        ? "Open the reference evidence lab modeled local infrastructure"
        : "Open the synthetic enterprise demo story"}
    >
      {referenceEvidenceLab
        ? <>
          <FlaskConical aria-hidden="true" className="h-4 w-4 shrink-0 @min-[4.5em]:hidden" />
          <span className="hidden @min-[4.5em]:inline @min-[10.5em]:hidden">Lab</span>
          <span className="hidden @min-[10.5em]:inline @min-[20em]:hidden">Reference lab</span>
          <span className="hidden @min-[20em]:inline @min-[35em]:hidden">Reference lab — modeled local</span>
          <span className="hidden @min-[35em]:inline">Reference evidence lab — modeled local infrastructure</span>
        </>
        : <>
          <FlaskConical aria-hidden="true" className="h-4 w-4 shrink-0 @min-[4.5em]:hidden" />
          <span className="hidden @min-[4.5em]:inline @min-[7.5em]:hidden">Demo</span>
          <span className="hidden @min-[7.5em]:inline @min-[22em]:hidden">Demo data</span>
          <span className="hidden @min-[22em]:inline">Demo data — sample environment</span>
        </>}
    </Link>
    </div>
  );
}
