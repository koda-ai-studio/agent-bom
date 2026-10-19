import type {
  ConnectorsResponse,
  ConnectorHealthResponse,
  DiscoveryProvidersResponse,
  SourceRecord,
  SourcesResponse,
  SourceCreateRequest,
  SourceCheckResponse,
  SourceRunResponse,
  ScanSchedule,
  ScheduleCreateRequest,
} from "./api-types";
import { get, post, put, del } from "./api-transport";

export const connectorsApi = {
  listConnectors: () => get<ConnectorsResponse>("/v1/connectors"),

  getConnectorHealth: (name: string) => get<ConnectorHealthResponse>(`/v1/connectors/${encodeURIComponent(name)}/health`),

  listDiscoveryProviders: () => get<DiscoveryProvidersResponse>("/v1/discovery/providers"),

  listSources: () => get<SourcesResponse>("/v1/sources"),

  createSource: (body: SourceCreateRequest) => post<SourceRecord>("/v1/sources", body),

  deleteSource: (sourceId: string) => del(`/v1/sources/${encodeURIComponent(sourceId)}`),

  testSource: (sourceId: string) => post<SourceCheckResponse>(`/v1/sources/${encodeURIComponent(sourceId)}/test`, {}),

  runSource: (sourceId: string) => post<SourceRunResponse>(`/v1/sources/${encodeURIComponent(sourceId)}/run`, {}),

  listSchedules: () => get<ScanSchedule[]>("/v1/schedules"),

  createSchedule: (body: ScheduleCreateRequest) => post<ScanSchedule>("/v1/schedules", body),

  toggleSchedule: (scheduleId: string) => put<ScanSchedule>(`/v1/schedules/${scheduleId}/toggle`, {}),

  deleteSchedule: (scheduleId: string) => del(`/v1/schedules/${scheduleId}`),
};
