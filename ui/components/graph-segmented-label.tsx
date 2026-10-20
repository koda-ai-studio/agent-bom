import { Fragment } from "react";
import { canvasNodeLabel } from "@/lib/graph-occurrence-role";

const ADVISORY_ID = /((?:CVE|PYSEC|RUSTSEC|GO|GSD|OSV|MAL)-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3})/i;
const NAME_BREAK = /(?<=[_/-])|(?<=.)(?=@)/;

/** Split a label into wrap segments; an advisory id is always one segment. */
export function labelSegments(text: string): { part: string; atomic: boolean }[] {
  return canvasNodeLabel(text)
    .split(ADVISORY_ID)
    .flatMap((chunk, index) => {
      if (!chunk) return [];
      if (index % 2 === 1) return [{ part: chunk, atomic: true }];
      return chunk.split(NAME_BREAK).filter(Boolean).map((part) => ({ part, atomic: false }));
    });
}

/**
 * Wrap after `-`, `_` or `/`, or before a non-leading `@` so `@version` stays
 * whole, and balance the lines, so a name never splits mid-word and a short
 * tail ("bucket") is not left alone on line two. An advisory id (CVE, GHSA,
 * PYSEC, …) never wraps: it ellipsizes with the full id as its tooltip.
 */
export function SegmentedLabel({ text, className = "", style }: { text: string; className?: string; style?: React.CSSProperties }) {
  return (
    <p className={`break-words [text-wrap:balance] ${className}`} style={style}>
      {labelSegments(text).map(({ part, atomic }, index) => (
        <Fragment key={index}>
          {index > 0 && <wbr />}
          {atomic
            ? <span title={part} className="inline-block max-w-full overflow-hidden text-ellipsis whitespace-nowrap align-bottom">{part}</span>
            : <span>{part}</span>}
        </Fragment>
      ))}
    </p>
  );
}
