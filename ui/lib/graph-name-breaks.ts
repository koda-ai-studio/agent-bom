import { captionGeometry, type NamePiece } from "@/lib/graph-caption-geometry";

export type { NamePiece };

/** Where an ordinary name may break, by the caption model's own rules: after a hyphen or underscore, which stays
 * at the end of its line. A finding id, a digest, or a version after "@" is one piece that never breaks. */
export function nameBreaks(word: string): NamePiece[] {
  return captionGeometry({ name: word }).words[0] ?? [{ text: word, breakAfter: false, protect: false }];
}
