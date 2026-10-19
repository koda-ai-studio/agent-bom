import type {
  HealthResponse,
  VersionInfo,
  AuthDebugResponse,
  AuthMeResponse,
  AuthPolicyResponse,
  ListKeysResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  RotateApiKeyRequest,
  RotateApiKeyResponse,
  TenantQuotaUpdateRequest,
} from "./api-types";
import { get, post, postVoid, put, del, _sessionChange, BOOTSTRAP_TIMEOUT_MS } from "./api-transport";

export const authApi = {
  health: () => get<HealthResponse>("/health", { ttlMs: 0, timeoutMs: BOOTSTRAP_TIMEOUT_MS }),

  version: () => get<VersionInfo>("/version", { timeoutMs: BOOTSTRAP_TIMEOUT_MS }),

  getAuthMe: () => get<AuthMeResponse>("/v1/auth/me", { ttlMs: 0, timeoutMs: BOOTSTRAP_TIMEOUT_MS }),

  getAuthDebug: () => get<AuthDebugResponse>("/v1/auth/debug"),

  getAuthPolicy: () => get<AuthPolicyResponse>("/v1/auth/policy"),

  getTenantQuota: () => get<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota"),

  updateTenantQuota: (body: TenantQuotaUpdateRequest) =>
    put<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota", body),

  resetTenantQuota: () => del("/v1/auth/quota"),

  createDevAuthSession: (resume = false) => _sessionChange(() => postVoid("/v1/auth/dev-session", {}, resume ? { "X-Agent-Bom-Session-Resume": "true" } : {})),

  createAuthSession: (apiKey: string) => _sessionChange(() => postVoid("/v1/auth/session", { api_key: apiKey })),

  deleteAuthSession: () => _sessionChange(() => del("/v1/auth/session")),

  reportClientError: (body: { message: string; digest?: string | undefined; path?: string | undefined; component?: string | undefined }) =>
    post<{ ok: boolean }>("/v1/ui/errors", body),

  listKeys: () => get<ListKeysResponse>("/v1/auth/keys"),

  createKey: (body: CreateApiKeyRequest) => post<CreateApiKeyResponse>("/v1/auth/keys", body),

  rotateKey: (keyId: string, body: RotateApiKeyRequest) =>
    post<RotateApiKeyResponse>(`/v1/auth/keys/${encodeURIComponent(keyId)}/rotate`, body),

  deleteKey: (keyId: string) => del(`/v1/auth/keys/${encodeURIComponent(keyId)}`),
};
