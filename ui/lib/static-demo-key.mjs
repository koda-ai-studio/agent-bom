/** Flat, query-free file name for a recorded demo response; shared by the UI and the generator. */
export function staticDemoDataKey(apiPath) {
  const pathname = String(apiPath).split("?")[0].split("#")[0];
  return pathname.replace(/^\/+/, "").replace(/[^A-Za-z0-9.-]/g, "_").replace(/\.{2,}/g, "_");
}
