/** Flat, query-free file name for a recorded demo response; shared by the UI and the generator. */
export function staticDemoDataKey(apiPath) {
  const pathname = String(apiPath).split("?")[0].split("#")[0];
  return pathname.replace(/^\/+/, "").replace(/[^A-Za-z0-9.-]/g, "_").replace(/\.{2,}/g, "_");
}

function fnv1a(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/** File name for one exact query of a path (parameter order ignored), or null without a query. */
export function staticDemoQueryKey(apiPath) {
  const query = String(apiPath).split("#")[0].split("?")[1];
  if (!query) return null;
  const params = new URLSearchParams(query);
  params.sort();
  return `${staticDemoDataKey(apiPath)}__q${fnv1a(params.toString())}`;
}
