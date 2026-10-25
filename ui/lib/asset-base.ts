/** Prefix for files in public/ when the UI is exported under a sub-path (the static demo). */
export const ASSET_BASE = (process.env.NEXT_PUBLIC_BASE_PATH ?? "").replace(/\/$/, "");
