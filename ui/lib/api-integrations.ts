import type {
  WebhookSubscriptionsResponse,
  WebhookCreateRequest,
  WebhookCreateResponse,
  WebhookMutationResponse,
  WebhookOutboxResponse,
  SiemConnectorsResponse,
  SiemFormatsResponse,
  SiemTestResponse,
} from "./api-types";
import { get, post, del } from "./api-transport";

export const integrationsApi = {

  // ── Operations & Integrations: webhook subscriptions ──
  /** List governance webhook subscriptions for the active tenant. */
  listWebhookSubscriptions: (includeDisabled = true, limit = 200) =>
    get<WebhookSubscriptionsResponse>(
      `/v1/webhooks?include_disabled=${includeDisabled}&limit=${limit}`,
      { ttlMs: 0 },
    ),

  /** Register a governance webhook destination. Returns the signing secret once. */
  createWebhookSubscription: (body: WebhookCreateRequest) =>
    post<WebhookCreateResponse>("/v1/webhooks", body),

  /** Enable a disabled subscription. */
  enableWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/enable`, {}),

  /** Disable a subscription without deleting it. */
  disableWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/disable`, {}),

  /** Delete a subscription. */
  deleteWebhookSubscription: (id: string) => del(`/v1/webhooks/${encodeURIComponent(id)}`),

  /** Enqueue a synthetic test delivery to this destination. */
  testWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/test`, {}),

  /** Recent webhook outbox deliveries (observability of the shipped outbox). */
  listWebhookOutbox: (status?: "pending" | "delivered" | "dead_letter", limit = 50) =>
    get<WebhookOutboxResponse>(
      `/v1/posture/webhooks/outbox?limit=${limit}${status ? `&status=${status}` : ""}`,
      { ttlMs: 0 },
    ),


  // ── Operations & Integrations: SIEM connectors ──
  /** List available SIEM connector types. */
  listSiemConnectors: () => get<SiemConnectorsResponse>("/v1/siem/connectors"),

  /** List supported SIEM event formats. */
  listSiemFormats: () => get<SiemFormatsResponse>("/v1/siem/formats"),

  /** Test SIEM connectivity. The token (if any) is sent via header, never persisted. */
  testSiemConnection: (siemType: string, url: string, token?: string) =>
    post<SiemTestResponse>(
      `/v1/siem/test?siem_type=${encodeURIComponent(siemType)}&url=${encodeURIComponent(url)}`,
      {},
      token ? { "X-Siem-Token": token } : {},
    ),
};
