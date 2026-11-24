/** Aborted API reads during a product-proof capture.
 *
 * A page supersedes a pending read when its inputs change (an AbortController
 * cancels the older request). That abort is benign only when a read of the same
 * endpoint then succeeded; an endpoint whose every request was aborted never
 * delivered its data, which stays a capture failure. */
export function isApiRead(url) {
  const pathname = new URL(url).pathname;
  return pathname.startsWith("/v1/") || pathname === "/health" || pathname === "/version";
}

/** The aborted API reads whose endpoint never answered successfully. */
export function unresolvedAbortedReads(aborted, successfulPaths) {
  return aborted.filter(url => !successfulPaths.has(new URL(url).pathname));
}
