import { INTERNET_LAND } from "@/lib/internet-land.generated";

/** Decorative geographic anchor. Exposure semantics belong to the node and links. */
export function GraphInternetGlobe() {
  return <svg viewBox="0 0 100 100" aria-hidden="true" data-internet-globe className="h-full w-full">
    <circle cx="50" cy="50" r="47" className="fill-sky-100 dark:fill-slate-900" />
    <g className="fill-emerald-200 stroke-emerald-700 dark:fill-emerald-900 dark:stroke-emerald-400" strokeWidth="0.8" strokeLinejoin="round">
      {INTERNET_LAND.map((d, index) => <path key={index} d={d} />)}
    </g>
    <circle cx="50" cy="50" r="47" fill="none" className="stroke-sky-700 dark:stroke-sky-400" strokeWidth="1.3" />
  </svg>;
}
