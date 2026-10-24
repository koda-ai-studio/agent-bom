import { Fragment } from "react";
import { canvasNodeLabel } from "@/lib/graph-occurrence-role";

const ADVISORY_ID = /((?:CVE|PYSEC|RUSTSEC|GO|GSD|OSV|MAL)-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3})/i;
const NAME_BREAK = /(?<=[_/-])|(?<=.)(?=@)/;

/** Split a label into wrap segments; an advisory id is always one segment. */
type Segment = { part: string; atomic: boolean };

export function labelSegments(text: string): Segment[] {
  return canvasNodeLabel(text)
    .split(ADVISORY_ID)
    .flatMap((chunk, index): Segment[] => {
      if (!chunk) return [];
      if (index % 2 === 1) return [{ part: chunk, atomic: true }];
      return chunk.split(NAME_BREAK).filter(Boolean).map((part) => ({ part, atomic: false }));
    });
}

/**
 * Wrap after `-`, `_` or `/`, or before a non-leading `@` so `@version` stays
 * whole, and balance the lines, so a name never splits mid-word and a short
 * tail ("bucket") is not left alone on line two. An advisory id (CVE, GHSA,
 * PYSEC, …) never wraps: it shrinks to the caption width so the whole id
 * stays readable, and ellipsizes only below that, with the id as its tooltip.
 */
// Semibold uppercase and digits average under 0.66em per character.
export function atomicFontSize(part: string): string {
  return `min(1em, calc(100cqi / ${(part.length * 0.66).toFixed(2)}))`;
}

export function SegmentedLabel({ text, className = "", style }: { text: string; className?: string; style?: React.CSSProperties }) {
  return (
    <p className={`break-words [container-type:inline-size] [text-wrap:balance] ${className}`} style={style}>
      {labelSegments(text).map(({ part, atomic }, index) => (
        <Fragment key={index}>
          {index > 0 && <wbr />}
          {atomic
            ? <span title={part} data-advisory-id="true" style={{ fontSize: atomicFontSize(part) }}
                className="inline-block max-w-full overflow-hidden text-ellipsis whitespace-nowrap align-bottom">{part}</span>
            : <span>{part}</span>}
        </Fragment>
      ))}
    </p>
  );
}

/**
 * Inline prose (a path title, a caption) breaks only between words: an
 * advisory id stays one token so "CVE-2025-" never ends a line, and wraps
 * before the id instead.
 */
export function AdvisoryIdText({ text }: { text: string }) {
  return <>{text.split(ADVISORY_ID).map((chunk, index) => index % 2 === 1
    ? <span key={index} title={chunk} data-advisory-id="true" className="whitespace-nowrap">{chunk}</span>
    : chunk)}</>;
}
