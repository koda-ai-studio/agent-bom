/** Characters after which a name may wrap: identifiers, package coordinates and paths read as their parts. */
const SEPARATOR = /[_\-./@:\s]/;
/** About one line of a 168px node name at the canvas type size. */
export const LABEL_LINE_CHARS = 18;

/**
 * The name in pieces that may each start a new line, so a wrap never lands
 * inside a token ("GCS_SERVICE_" / "ACCOUNT_KEY", never "GCS_SERVICE_ACCO" /
 * "UNT_KEY"). A token longer than a line ends with an ellipsis instead of
 * being split; the full name stays in the element's title and aria-label.
 */
export function labelSegments(label: string, lineChars = LABEL_LINE_CHARS): string[] {
  const segments: string[] = [];
  let current = "";
  const chars = [...label];
  chars.forEach((char, index) => {
    current += char;
    // A dot between digits belongs to a version number, which reads as one token.
    const versionDot = char === "." && /\d/.test(chars[index - 1] ?? "") && /\d/.test(chars[index + 1] ?? "");
    if (SEPARATOR.test(char) && !versionDot) { segments.push(current); current = ""; }
  });
  if (current) segments.push(current);
  return segments.map(segment => {
    const token = segment.replace(/\s+$/, "");
    return token.length > lineChars ? `${token.slice(0, lineChars - 1)}…` : segment;
  });
}
