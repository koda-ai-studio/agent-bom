import { getConfiguredApiUrl } from "./runtime-config";
import { isStaticDemo } from "./static-demo";
import type {
  JobListItem,
  JobStatus,
  ScanRequest,
  SSEEvent,
  ScanJob,
  ScanJobStatus,
  GraphExportFormat,
  JobsResponse,
} from "./api-types";
import type {
  DatasetCardsRequest,
  DatasetCardsResponse,
  TrainingPipelinesRequest,
  TrainingPipelinesResponse,
  BrowserExtensionsRequest,
  BrowserExtensionsResponse,
  ModelProvenanceRequest,
  ModelProvenanceResponse,
  PromptScanRequest,
  PromptScanResponse,
  ModelFilesRequest,
  ModelFilesResponse,
} from "./ai-scan";
import type { AgentLifecycleRecord, AgentLifecyclePage } from "./api-contracts";
import { get, post, del, getBlob, mutationIdempotencyKey } from "./api-transport";

export const scansApi = {

  /** Start a scan — returns immediately with job_id */
  startScan: (req: ScanRequest) =>
    post<ScanJob>("/v1/scan", req, { "Idempotency-Key": mutationIdempotencyKey("ui-scan") }),


  /** Poll scan status + results */
  getScan: (jobId: string, signal?: AbortSignal) => get<ScanJob>(`/v1/scan/${jobId}`, signal ? { signal } : {}),


  /** Poll scan status without loading large result payloads */
  getScanStatus: (jobId: string, signal?: AbortSignal) => get<ScanJobStatus>(`/v1/scan/${jobId}/status`, signal ? { signal } : {}),


  /** Export a completed scan graph in a graph-native format. */
  downloadScanGraph: (jobId: string, format: GraphExportFormat = "json") =>
    getBlob(`/v1/scan/${encodeURIComponent(jobId)}/graph-export?format=${encodeURIComponent(format)}`),


  /** Export composition for exactly one recorded agent; never select by name. */
  downloadScanAgentBom: (jobId: string, agentId: string) =>
    getBlob(`/v1/scan/${encodeURIComponent(jobId)}/agent-bom?agent_id=${encodeURIComponent(agentId)}`),


  captureAgentSnapshot: (jobId: string, agentId: string) =>
    post<AgentLifecycleRecord>("/v1/agent-lifecycle/snapshots", { scan_id: jobId, agent_id: agentId }),

  agentLifecycleHistory: (agentId: string, offset = 0) =>
    get<AgentLifecyclePage>(`/v1/agent-lifecycle/history?agent_id=${encodeURIComponent(agentId)}&limit=20&offset=${offset}`),

  compareAgentSnapshots: (before: string, after: string) =>
    get<{ composition_changed: boolean; snapshot_changed: boolean }>(`/v1/agent-lifecycle/snapshots/compare?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`),


  /** Delete a job record */
  deleteScan: (jobId: string) => del(`/v1/scan/${jobId}`),


  // ── AI / ML supply-chain scans (synchronous; results returned inline) ──
  /** Scan directories for HuggingFace dataset cards, DVC files, and lineage. */
  scanDatasetCards: (body: DatasetCardsRequest) =>
    post<DatasetCardsResponse>("/v1/scan/dataset-cards", body),

  /** Scan directories for MLflow / W&B / Kubeflow training + serving artifacts. */
  scanTrainingPipelines: (body: TrainingPipelinesRequest) =>
    post<TrainingPipelinesResponse>("/v1/scan/training-pipelines", body),

  /** Scan installed browser extensions for dangerous permissions + AI host access. */
  scanBrowserExtensions: (body: BrowserExtensionsRequest) =>
    post<BrowserExtensionsResponse>("/v1/scan/browser-extensions", body),

  /** Check HuggingFace / Ollama model provenance (format, digest, gating, card). */
  scanModelProvenance: (body: ModelProvenanceRequest) =>
    post<ModelProvenanceResponse>("/v1/scan/model-provenance", body),

  /** Scan prompt files for injection, hardcoded secrets, and unsafe instructions. */
  scanPrompts: (body: PromptScanRequest) =>
    post<PromptScanResponse>("/v1/scan/prompt-scan", body),

  /** Scan directories for model files and assess serialization safety. */
  scanModelFiles: (body: ModelFilesRequest) =>
    post<ModelFilesResponse>("/v1/scan/model-files", body),


  /** List all jobs */
  listJobs: (options?: {
    includeDetails?: boolean;
    limit?: number;
    offset?: number;
    query?: string | undefined;
    status?: JobStatus | undefined;
  }, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    if (options?.includeDetails) params.set("include_details", "true");
    if (typeof options?.limit === "number") params.set("limit", String(options.limit));
    if (typeof options?.offset === "number") params.set("offset", String(options.offset));
    if (options?.query?.trim()) params.set("q", options.query.trim());
    if (options?.status) params.set("status", options.status);
    const qs = params.toString();
    return get<JobsResponse>(`/v1/jobs${qs ? `?${qs}` : ""}`, signal ? { signal } : {});
  },


  /** Fetch every server-filtered job page for a complete JSON export. */
  exportJobs: async (options?: { query?: string | undefined; status?: JobStatus | undefined }) => {
    const limit = 1000;
    let offset = 0;
    let total = Number.POSITIVE_INFINITY;
    const jobs: JobListItem[] = [];
    while (offset < total) {
      const params = new URLSearchParams();
      params.set("include_details", "true");
      params.set("limit", String(limit));
      params.set("offset", String(offset));
      if (options?.query?.trim()) params.set("q", options.query.trim());
      if (options?.status) params.set("status", options.status);
      const page = await get<JobsResponse>(`/v1/jobs?${params.toString()}`);
      jobs.push(...page.jobs);
      total = page.total ?? jobs.length;
      if (page.jobs.length === 0) break;
      offset += page.jobs.length;
    }
    return jobs;
  },


  /** Connect to SSE stream for real-time progress */
  streamScan: (jobId: string, onMessage: (data: SSEEvent) => void, onDone: () => void) => {
    if (isStaticDemo()) {
      onDone();
      return () => undefined;
    }
    const es = new EventSource(`${getConfiguredApiUrl()}/v1/scan/${jobId}/stream`, { withCredentials: true });
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data as string);
        onMessage(data);
        if (data.type === "done") {
          es.close();
          onDone();
        }
      } catch {
        // ignore parse errors
      }
    };
    es.onerror = () => {
      es.close();
      onDone();
    };
    return () => es.close(); // cleanup fn
  },
};
