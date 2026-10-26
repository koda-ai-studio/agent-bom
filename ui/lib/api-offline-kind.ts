import { ApiAuthError, ApiForbiddenError, isApiBusyError } from "./api-errors";

/**
 * Why a page could not load its data: the API is unreachable, the request was
 * unauthenticated or under-privileged, or the running API shed the read
 * under load and the page should retry rather than show setup guidance.
 */
export type ApiOfflineKind = "network" | "auth" | "forbidden" | "busy";

export function classifyApiOfflineKind(err: unknown): ApiOfflineKind {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  if (isApiBusyError(err)) return "busy";
  return "network";
}
