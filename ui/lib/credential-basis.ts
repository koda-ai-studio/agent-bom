// Two credential counts reach the UI and must never share a label:
// exposure the advisory's impact asserts (blast `exposed_credentials`) and
// credentials the hosting servers hold (`all_server_credentials`, the exploit story).
const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

export const EXPOSED_BY_IMPACT = "Credentials exposed by impact";
export const HELD_ON_SERVER = "Credentials on server";

export const EXPOSED_BY_IMPACT_NOTE =
  "Credentials this advisory's impact can reach. The exploit story counts every credential the hosting servers hold.";
export const HELD_ON_SERVER_NOTE =
  "Credentials the hosting servers hold, reached through graph edges; not filtered by this advisory's impact.";

export function exposedByImpactLabel(count: number): string {
  return `${plural(count, "credential")} exposed by impact`;
}

export function heldOnServerLabel(count: number): string {
  return `${plural(count, "credential")} on server`;
}
