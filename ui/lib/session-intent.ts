/** Browser intent only. Authorization and revocation always remain server-side. */
const KEY = "agent-bom-signed-out";
export const SESSION_INTENT_EVENT = "agent-bom-session-intent";
let unavailableStorageIntent: "1" | "confirmed" | null | undefined;

export function isExplicitlySignedOut(): boolean {
  if (typeof window === "undefined") return false;
  if (unavailableStorageIntent !== undefined) return unavailableStorageIntent !== null;
  try { return ["1", "confirmed"].includes(localStorage.getItem(KEY) ?? ""); } catch { return false; }
}

export function isSignOutConfirmed(): boolean {
  if (unavailableStorageIntent !== undefined) return unavailableStorageIntent === "confirmed";
  try { return localStorage.getItem(KEY) === "confirmed"; } catch { return false; }
}

export function setExplicitlySignedOut(value: boolean, confirmed = false): void {
  unavailableStorageIntent = value ? confirmed ? "confirmed" : "1" : null;
  try {
    if (value) localStorage.setItem(KEY, confirmed ? "confirmed" : "1");
    else localStorage.removeItem(KEY);
    unavailableStorageIntent = undefined;
  } catch { /* Keep this tab locked when storage is blocked. */ }
  window.dispatchEvent(new Event(SESSION_INTENT_EVENT));
}
