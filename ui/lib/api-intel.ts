import type {
  IntelSourcesResponse,
  IntelAdvisoryResponse,
  IntelMatchPackageInput,
  IntelMatchResponse,
  IntelDailyBriefResponse,
} from "./api-types";
import { get, post } from "./api-transport";

export const intelApi = {

  // ── Operations & Integrations: threat intel ──
  /** Canonical threat-intel source and feed-run metadata. */
  getIntelSources: () => get<IntelSourcesResponse>("/v1/intel/sources", { ttlMs: 0 }),

  /** Look up one CVE/GHSA/OSV advisory from local intel. */
  getIntelAdvisory: (advisoryId: string) =>
    get<IntelAdvisoryResponse>(`/v1/intel/advisories/${encodeURIComponent(advisoryId)}`, { ttlMs: 0 }),

  /** Match inventory package coordinates to local advisory intel. */
  matchIntelPackages: (packages: IntelMatchPackageInput[], limit = 100) =>
    post<IntelMatchResponse>("/v1/intel/match", { packages, limit }),

  /** Local analyst threat brief from governed intel sources. */
  getIntelDailyBrief: (body: Record<string, unknown> = {}) =>
    post<IntelDailyBriefResponse>("/v1/intel/daily-brief", body),
};
