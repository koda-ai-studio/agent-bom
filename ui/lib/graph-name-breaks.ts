/** Identifiers that are read as one token: finding ids and image digest tails. */
const PROTECTED_TOKEN = /^(CVE|GHSA|CWE)-|^[0-9a-f]{8,}$/i;

export type NamePiece = { text: string; breakAfter: boolean; protect: boolean };

/** Where an ordinary name may break: after a hyphen or underscore, which stays at the end of its line.
 * A finding id, a digest, or a version after "@" is one piece that never breaks. */
export function nameBreaks(word: string): NamePiece[] {
  if (PROTECTED_TOKEN.test(word)) return [{ text: word, breakAfter: false, protect: true }];
  const at = word.indexOf("@", 1);
  const base = at > 0 ? word.slice(0, at) : word, version = at > 0 ? word.slice(at) : "";
  const parts = base.match(/[^-_]+[-_]*|[-_]+/g) ?? [base];
  const pieces = parts.map((text, index) => ({ text, breakAfter: /[-_]$/.test(text) && index < parts.length - 1, protect: false }));
  if (version) pieces.push({ text: version, breakAfter: false, protect: true });
  return pieces;
}
