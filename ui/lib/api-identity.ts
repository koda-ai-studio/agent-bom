import type {
  IdentitiesResponse,
  JITGrantsResponse,
  ConditionalAccessResponse,
  CredentialExpiryReport,
  AccessReviewsResponse,
  NhiDiscoveryResponse,
} from "./api-types";
import { get, post } from "./api-transport";

export const identityApi = {

  // ── Identity / access-governance cockpit ──
  listIdentities: (includeInactive = false, limit = 200) =>
    get<IdentitiesResponse>(`/v1/identities?include_inactive=${includeInactive}&limit=${limit}`),

  listJitGrants: (includeInactive = false, limit = 200) =>
    get<JITGrantsResponse>(`/v1/identity-jit-grants?include_inactive=${includeInactive}&limit=${limit}`),

  listConditionalAccessPolicies: (includeDisabled = false, limit = 200) =>
    get<ConditionalAccessResponse>(`/v1/conditional-access-policies?include_disabled=${includeDisabled}&limit=${limit}`),


  // ── NHI / identity governance: credential expiry, access reviews, discovery ──
  /** Non-secret credential expiry / rotation governance posture */
  getCredentialExpiry: () =>
    get<CredentialExpiryReport>("/v1/auth/secrets/credential-expiry"),

  /** Access-review / recertification campaigns over discovered NHIs */
  listAccessReviews: (limit = 200) =>
    get<AccessReviewsResponse>(`/v1/identities/access-reviews?limit=${limit}`),

  /** Read-only NHI discovery summary (gated by *_DISCOVERY env flags) */
  discoverNonHumanIdentities: (providers?: string[]) =>
    post<NhiDiscoveryResponse>("/v1/identities/discover", providers ? { providers } : {}),
};
