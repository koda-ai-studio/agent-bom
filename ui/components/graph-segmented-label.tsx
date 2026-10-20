import { Fragment } from "react";
import { canvasNodeLabel } from "@/lib/graph-occurrence-role";

/**
 * Wrap after `-`, `_` or `/`, or before a non-leading `@` so `@version` stays
 * whole, and balance the lines, so a name never splits mid-word and a short
 * tail ("bucket") is not left alone on line two.
 */
export function SegmentedLabel({ text, className = "", style }: { text: string; className?: string; style?: React.CSSProperties }) {
  return (
    <p className={`break-words [text-wrap:balance] ${className}`} style={style}>
      {canvasNodeLabel(text).split(/(?<=[_/-])|(?<=.)(?=@)/).map((part, index) => <Fragment key={index}>{index > 0 && <wbr />}<span>{part}</span></Fragment>)}
    </p>
  );
}
