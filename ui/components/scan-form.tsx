"use client";
import { ConnectedAccountPanel,ContainerTargetPanel,ListInput,RelatedLink,RepoSurfaceCatalog,ScanAccessNotice,ScanWorkspacePanel,ScheduledSourcePanel,type FormMode } from "@/components/scan/scan-form-panels";

import {
ArrowRight,
Bot,
CalendarClock,
ChevronDown,
Cloud,
Container,
Link2,
Loader2,
Server,
Sparkles
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect,useMemo,useRef,useState } from "react";

import { AiScanPanel } from "@/components/ai-scan-panel";
import { useAuthState } from "@/components/auth-provider";

import { useDeploymentContext } from "@/hooks/use-deployment-context";
import {
api,
type CloudConnectionRecord,
type ScanRequest,
type SourceRecord,
} from "@/lib/api";
import { sourceSupportsDirectRun } from "@/lib/connections-sources";
import { deploymentModeLabel } from "@/lib/deployment-context";
import {
adhocScopeChips,
cloudConnectionScopeChips,
isScannableConnection,
scheduledSourceScopeChips,
type AdhocScanTarget,
type ScanScopeChip
} from "@/lib/scan-scope";

type ScanFormProps = {
  initialConnectionId?: string | undefined;
  /**
   * Optional preset carried in the URL (``/scan?preset=enterprise``) by the
   * in-product "Run introspection scan" actions. It pre-fills the form to the
   * enrichment portion of ``agent-bom scan --introspect --preset enterprise``.
   * The operator still selects an explicit mounted-project path inside the configured
   * API scan root; the browser never implies ambient server-host discovery.
   */
  initialPreset?: string | undefined;
};

/** ``enterprise`` pre-fills CVSS/EPSS/KEV enrichment. */
function isEnterprisePreset(preset: string | undefined): boolean {
  return preset === "enterprise";
}

/** Client-side guard: accept only well-formed ``http(s)://<host>`` repo URLs
 * before enabling submit. Server-side validation remains authoritative. */
function isHttpRepoUrl(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  return Boolean(parsed.hostname) && parsed.hostname.includes(".");
}

export function ScanForm({ initialConnectionId, initialPreset }: ScanFormProps) {
  const router = useRouter();
  const { session, loading: authLoading, hasCapability } = useAuthState();
  const { counts } = useDeploymentContext();
  const deploymentMode = counts?.deployment_mode ?? "local";
  const enterprisePreset = isEnterprisePreset(initialPreset);
  const [scanMode, setScanMode] = useState<FormMode>(
    initialConnectionId
      ? "connected"
      : enterprisePreset
        ? "adhoc"
        : deploymentMode === "local"
          ? "adhoc"
          : "connected",
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionsError, setConnectionsError] = useState("");
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [sourcesUnavailable, setSourcesUnavailable] = useState(false);
  const [selectedConnectionId, setSelectedConnectionId] = useState(initialConnectionId ?? "");
  const [selectedSourceId, setSelectedSourceId] = useState("");
  const [target, setTarget] = useState<AdhocScanTarget>(
    deploymentMode === "local" ? "workstation" : "workstation",
  );
  const [form, setForm] = useState<ScanRequest>({
    enrich: enterprisePreset,
    format: "json",
    k8s: false,
    images: [],
    tf_dirs: [],
    agent_projects: [],
  });
  const [imageInput, setImageInput] = useState("");
  const [showBulkImages, setShowBulkImages] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [tfInput, setTfInput] = useState("");
  const [apInput, setApInput] = useState("");
  const [repoUrlInput, setRepoUrlInput] = useState("");

  useEffect(() => {
    let mounted = true;
    api
      .listCloudConnections()
      .then((response) => {
        if (!mounted) return;
        setConnections(response.connections ?? []);
        setConnectionsError("");
        setConnectionsLoading(false);
        const loaded = response.connections ?? [];
        setSelectedConnectionId((current) => {
          if (initialConnectionId && loaded.some((connection) => connection.id === initialConnectionId)) {
            return initialConnectionId;
          }
          if (current && loaded.some((connection) => connection.id === current)) {
            return current;
          }
          return loaded[0]?.id ?? "";
        });
        if (initialConnectionId) {
          setScanMode("connected");
        }
      })
      .catch((err: Error) => {
        if (!mounted) return;
        setConnectionsError(err.message);
        setConnectionsLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [initialConnectionId]);

  useEffect(() => {
    let mounted = true;
    api
      .listSources()
      .then((response) => {
        if (!mounted) return;
        const nextSources = response.sources ?? [];
        setSources(nextSources);
        setSourcesUnavailable(false);
        setSourcesLoading(false);
        setSelectedSourceId((current) => current || nextSources[0]?.source_id || "");
      })
      .catch(() => {
        if (!mounted) return;
        setSourcesUnavailable(true);
        setSourcesLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const deploymentLabel = deploymentModeLabel(deploymentMode);

  const selectedConnection = useMemo(
    () => connections.find((connection) => connection.id === selectedConnectionId) ?? null,
    [connections, selectedConnectionId],
  );
  const selectedSource = useMemo(
    () => sources.find((source) => source.source_id === selectedSourceId) ?? null,
    [sources, selectedSourceId],
  );
  const roleCanRunScans = hasCapability("scan.run");
  const managedTrialSession = Boolean(
    session?.managed_trial_mode || session?.auth_method === "managed_trial_oidc",
  );
  const routeEnvelopeAllowsScan = !managedTrialSession || scanMode === "connected";
  const canRunCurrentScan = roleCanRunScans && routeEnvelopeAllowsScan;

  const scopeChips = useMemo((): ScanScopeChip[] => {
    if (scanMode === "connected" && selectedConnection) {
      return cloudConnectionScopeChips(selectedConnection);
    }
    if (scanMode === "scheduled" && selectedSource) {
      return scheduledSourceScopeChips(selectedSource);
    }
    return adhocScopeChips(form, target);
  }, [form, scanMode, selectedConnection, selectedSource, target]);

  function addToList(key: "images" | "tf_dirs" | "agent_projects", value: string, reset: () => void) {
    if (!value.trim()) return;
    setForm((f) => ({ ...f, [key]: [...(f[key] ?? []), value.trim()] }));
    reset();
  }

  function removeFromList(key: "images" | "tf_dirs" | "agent_projects", idx: number) {
    setForm((f) => ({ ...f, [key]: (f[key] ?? []).filter((_, i) => i !== idx) }));
  }

  function parseBulkImages(text: string): string[] {
    return text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  }

  function applyBulk() {
    const parsed = parseBulkImages(bulkText);
    if (parsed.length === 0) return;
    setForm((f) => ({ ...f, images: [...(f.images ?? []), ...parsed] }));
    setBulkText("");
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const parsed = parseBulkImages(text);
      if (parsed.length > 0) {
        setForm((f) => ({ ...f, images: [...(f.images ?? []), ...parsed] }));
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  async function handleAdhocSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!roleCanRunScans || managedTrialSession) return;
    setLoading(true);
    setError("");
    try {
      const request: ScanRequest =
        target === "repository"
          ? {
              repo_url: repoUrlInput.trim(),
              enrich: form.enrich ?? false,
              format: form.format ?? "json",
            }
          : {
              ...form,
              agent_projects: (form.agent_projects ?? []).map((p) => p.trim()).filter(Boolean),
              tf_dirs: (form.tf_dirs ?? []).map((p) => p.trim()).filter(Boolean),
              gha_path: form.gha_path?.trim() || undefined,
              repo_url: undefined,
            };
      if (target === "repository" && !isHttpRepoUrl(repoUrlInput)) {
        setError("Enter a valid public repository URL (https://github.com/org/repo)");
        setLoading(false);
        return;
      }
      if (
        target !== "repository" &&
        !(request.agent_projects ?? []).length &&
        !(request.images ?? []).length &&
        !request.k8s &&
        !(request.tf_dirs ?? []).length &&
        !request.gha_path?.trim() &&
        !request.inventory?.trim() &&
        !request.sbom?.trim()
      ) {
        setError(
          "Choose a scan target: add a project path or image, enable Kubernetes, or add an advanced path.",
        );
        setLoading(false);
        return;
      }
      const job = await api.startScan(request);
      router.push(`/scan?id=${job.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  }

  async function handleCloudScan() {
    if (!roleCanRunScans || !selectedConnection || selectedConnection.status !== "active") return;
    setLoading(true);
    setError("");
    try {
      const result = await api.scanCloudConnection(selectedConnection.id);
      router.push(`/scan?id=${result.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start cloud scan");
      setLoading(false);
    }
  }

  async function handleSourceRun() {
    if (
      !roleCanRunScans ||
      managedTrialSession ||
      !selectedSource?.enabled ||
      !sourceSupportsDirectRun(selectedSource.kind) ||
      selectedSource.credential_mode === "reference"
    ) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.runSource(selectedSource.source_id);
      router.push(`/scan?id=${result.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run source");
      setLoading(false);
    }
  }

  const queuedImages = form.images ?? [];
  const cloudScanReady = Boolean(
    roleCanRunScans &&
      selectedConnection &&
      selectedConnection.status === "active" &&
      isScannableConnection(selectedConnection),
  );
  const sourceDirectRunSupported = Boolean(selectedSource && sourceSupportsDirectRun(selectedSource.kind));
  const sourceCredentialBlocksRun = Boolean(
    selectedSource && sourceDirectRunSupported && selectedSource.credential_mode === "reference",
  );
  const sourceRunReady = Boolean(
    roleCanRunScans &&
      !managedTrialSession &&
      selectedSource?.enabled &&
      sourceDirectRunSupported &&
      !sourceCredentialBlocksRun,
  );
  const sourceRunDisabledReason = !selectedSource
    ? "Select a source to run."
    : !sourceDirectRunSupported
      ? "Push and runtime sources receive evidence externally and cannot run directly."
      : sourceCredentialBlocksRun
        ? "Credential references are governance metadata and cannot execute this source. Detach the reference first."
        : !selectedSource.enabled
          ? "Enable this source before running it."
          : undefined;
  const repoUrlValid = isHttpRepoUrl(repoUrlInput);
  const repoUrlInvalid = target === "repository" && repoUrlInput.trim().length > 0 && !repoUrlValid;
  const repoScanReady = roleCanRunScans && !managedTrialSession && (target !== "repository" || repoUrlValid);

  return (
    <div className="max-w-[1180px]" data-testid="scan-form">
      <header className="mb-6 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">New Scan</h1>
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[10px] font-mono uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              {deploymentLabel}
            </span>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-[color:var(--text-secondary)]">
            Choose an evidence boundary, confirm coverage, and follow the job from collection to prioritized findings.
          </p>
        </div>
        <Link
          href="/connections"
          className="hidden shrink-0 items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] sm:inline-flex"
        >
          Connect account <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </header>

      <div className="overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <div
          role="tablist"
          aria-label="Scan source"
          className="grid grid-cols-2 border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-1 sm:flex"
        >
          {(
            [
              { id: "connected" as const, label: "Cloud account", icon: Cloud },
              { id: "adhoc" as const, label: "Ad-hoc", icon: Bot },
              { id: "scheduled" as const, label: "Data source", icon: CalendarClock },
              { id: "aiml" as const, label: "AI / ML", icon: Sparkles },
            ] as const
          ).map((option) => {
            const Icon = option.icon;
            const active = scanMode === option.id;
            return (
              <button
                key={option.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setScanMode(option.id)}
                className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                  active
                    ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                    : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {option.label}
              </button>
            );
          })}
        </div>

        {scanMode === "aiml" ? (
          <div className="p-6">
            {canRunCurrentScan ? (
              <AiScanPanel />
            ) : (
              <ScanAccessNotice
                authLoading={authLoading}
                managedTrialSession={managedTrialSession}
                roleCanRunScans={roleCanRunScans}
              />
            )}
          </div>
        ) : (
        <form
          onSubmit={scanMode === "adhoc" ? handleAdhocSubmit : (e) => e.preventDefault()}
          className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_360px]"
        >
          <div className="space-y-5 p-5 sm:p-6">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-800 dark:text-emerald-400">Configure</p>
              <h2 className="mt-1 text-base font-semibold text-[color:var(--foreground)]">
                {scanMode === "connected"
                  ? "Select a connected cloud boundary"
                  : scanMode === "scheduled"
                    ? "Run a registered evidence source"
                    : "Choose what the control plane can inspect"}
              </h2>
              <p className="mt-2 text-xs text-[color:var(--text-secondary)]">
                {scanMode === "connected"
                  ? "Runs inventory and implemented CIS checks for the selected connection and its configured scope. CIS benchmarks are one part of cloud security posture management."
                  : scanMode === "scheduled"
                    ? "Runs the selected source with its saved collection settings."
                    : "The selected target and options determine what runs; a scan does not enable every capability. Review the collection plan before starting."}
              </p>
            </div>
            {scanMode === "connected" && (
              <ConnectedAccountPanel
                connections={connections}
                connectionsLoading={connectionsLoading}
                connectionsError={connectionsError}
                selectedConnectionId={selectedConnectionId}
                onSelectConnection={setSelectedConnectionId}
                selectedConnection={selectedConnection}
              />
            )}

            {scanMode === "adhoc" && (
              <>
                <div role="tablist" aria-label="Ad-hoc target" className="flex flex-wrap gap-1.5">
                  {(
                    [
                      { id: "repository" as const, label: "Public repo", icon: Link2 },
                      { id: "workstation" as const, label: "Mounted project", icon: Bot },
                      { id: "containers" as const, label: "Containers", icon: Container },
                      { id: "kubernetes" as const, label: "Kubernetes", icon: Server },
                    ] as const
                  ).map((option) => {
                    const Icon = option.icon;
                    const active = target === option.id;
                    return (
                      <button
                        key={option.id}
                        type="button"
                        role="tab"
                        aria-selected={active}
                        onClick={() => {
                          setTarget(option.id);
                          setError("");
                        }}
                        className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                          active
                            ? "border-emerald-600/50 bg-emerald-500/10 text-[color:var(--foreground)]"
                            : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                        }`}
                      >
                        <Icon className="h-3.5 w-3.5" />
                        {option.label}
                      </button>
                    );
                  })}
                </div>

                {target === "repository" && (
                  <div className="space-y-3">
                    <input
                      type="url"
                      aria-label="Public repository URL"
                      placeholder="https://github.com/org/repo"
                      aria-invalid={repoUrlInvalid}
                      className={`w-full rounded-xl border bg-[color:var(--surface-muted)] px-4 py-3 font-mono text-sm text-[color:var(--foreground)] focus:outline-none ${
                        repoUrlInvalid
                          ? "border-red-600/70 focus:border-red-500"
                          : "border-[color:var(--border-subtle)] focus:border-emerald-600"
                      }`}
                      value={repoUrlInput}
                      onChange={(event) => {
                        const value = event.target.value;
                        setRepoUrlInput(value);
                        setForm((current) => ({ ...current, repo_url: value.trim() || undefined }));
                      }}
                    />
                    {repoUrlInvalid ? (
                      <p className="text-xs text-red-400">Enter a full http(s):// URL, e.g. https://github.com/org/repo</p>
                    ) : null}
                    <label className="block text-xs font-medium text-[color:var(--text-secondary)]">
                      Artifact after scan
                      <select
                        value={form.format ?? "json"}
                        onChange={(event) => setForm((current) => ({ ...current, format: event.target.value }))}
                        className="mt-1.5 w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                      >
                        <option value="json">AI-BOM JSON</option>
                        <option value="cyclonedx">CycloneDX SBOM</option>
                        <option value="spdx">SPDX 3 SBOM</option>
                      </select>
                    </label>
                    <RepoSurfaceCatalog />
                  </div>
                )}

                {target === "workstation" && (
                  <div className="space-y-3">
                    <ListInput
                      placeholder="projects/agent"
                      value={apInput}
                      onChange={setApInput}
                      onAdd={() => addToList("agent_projects", apInput, () => setApInput(""))}
                      items={form.agent_projects ?? []}
                      onRemove={(i) => removeFromList("agent_projects", i)}
                    />
                    <p className="text-sm text-ink-secondary">Use a project mounted on this control plane.</p>
                    <details className="text-xs leading-5 text-ink-secondary">
                      <summary className="w-fit cursor-pointer">Operator setup and path boundary</summary>
                      <p className="mt-2">Enter a path relative to <code className="font-mono">AGENT_BOM_API_SCAN_ROOT</code>, not a path on the browser machine or an absolute server path. An administrator must set <code className="font-mono">AGENT_BOM_API_LOCAL_PATH_SCANS=enabled</code> and mount the intended project inside that root.</p>
                    </details>
                  </div>
                )}

                {target === "containers" && (
                  <ContainerTargetPanel
                    imageInput={imageInput}
                    setImageInput={setImageInput}
                    onAdd={() => addToList("images", imageInput, () => setImageInput(""))}
                    queuedImages={queuedImages}
                    onRemove={(i) => removeFromList("images", i)}
                    showBulkImages={showBulkImages}
                    setShowBulkImages={setShowBulkImages}
                    bulkText={bulkText}
                    setBulkText={setBulkText}
                    applyBulk={applyBulk}
                    parseBulkImages={parseBulkImages}
                    fileInputRef={fileInputRef}
                    handleFileUpload={handleFileUpload}
                  />
                )}

                {target === "kubernetes" && (
                  <div className="space-y-3">
                    <label className="flex cursor-pointer items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-[color:var(--border-subtle)] text-emerald-500"
                        checked={form.k8s ?? false}
                        onChange={(e) => setForm((f) => ({ ...f, k8s: e.target.checked }))}
                      />
                      <span className="text-sm text-[color:var(--foreground)]">Scan pods in current kube context</span>
                    </label>
                    {form.k8s ? (
                      <input
                        id="k8s-namespace-filter"
                        aria-label="Namespace filter"
                        type="text"
                        placeholder="All namespaces"
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                        value={form.k8s_namespace ?? ""}
                        onChange={(e) => setForm((f) => ({ ...f, k8s_namespace: e.target.value || undefined }))}
                      />
                    ) : null}
                  </div>
                )}

                {target !== "repository" && (
                  <details className="group rounded-xl border border-[color:var(--border-subtle)]">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-xs font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
                      Advanced targets
                      <ChevronDown className="h-3.5 w-3.5 transition-transform group-open:rotate-180" />
                    </summary>
                    <div className="space-y-3 border-t border-[color:var(--border-subtle)] px-4 py-3">
                      <ListInput
                        placeholder="terraform/prod"
                        value={tfInput}
                        onChange={setTfInput}
                        onAdd={() => addToList("tf_dirs", tfInput, () => setTfInput(""))}
                        items={form.tf_dirs ?? []}
                        onRemove={(i) => removeFromList("tf_dirs", i)}
                      />
                      <input
                        type="text"
                        placeholder="repos/app"
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm"
                        value={form.gha_path ?? ""}
                        onChange={(e) => setForm((f) => ({ ...f, gha_path: e.target.value || undefined }))}
                      />
                    </div>
                  </details>
                )}
              </>
            )}

            {scanMode === "scheduled" && (
              <ScheduledSourcePanel
                sources={sources}
                sourcesLoading={sourcesLoading}
                sourcesUnavailable={sourcesUnavailable}
                selectedSourceId={selectedSourceId}
                onSelectSource={setSelectedSourceId}
              />
            )}

            {scanMode === "adhoc" && (
              <label className="flex items-center gap-2 text-xs text-[color:var(--text-secondary)]">
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-[color:var(--border-subtle)] text-emerald-500"
                  checked={form.enrich ?? false}
                  onChange={(e) => setForm((f) => ({ ...f, enrich: e.target.checked }))}
                />
                Enrich with CVSS / EPSS / KEV (slower)
              </label>
            )}

            {error ? (
              <p role="alert" className="rounded-lg border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] px-3 py-2 text-sm text-[color:var(--severity-critical)]">{error}</p>
            ) : null}

            <div className="border-t border-[color:var(--border-subtle)] pt-5">
              {!canRunCurrentScan ? (
                <ScanAccessNotice
                  authLoading={authLoading}
                  managedTrialSession={managedTrialSession}
                  roleCanRunScans={roleCanRunScans}
                />
              ) : null}
              {scanMode === "connected" ? (
                <button
                  type="button"
                  onClick={handleCloudScan}
                  disabled={authLoading || loading || !cloudScanReady}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto sm:min-w-48"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  {loading ? "Starting collectors…" : "Run cloud scan"} <ArrowRight className="h-4 w-4" />
                </button>
              ) : scanMode === "scheduled" ? (
                <button
                  type="button"
                  onClick={handleSourceRun}
                  disabled={authLoading || loading || !sourceRunReady}
                  title={sourceRunDisabledReason}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto sm:min-w-48"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  {loading ? "Starting source…" : "Run source"} <ArrowRight className="h-4 w-4" />
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={authLoading || loading || !repoScanReady}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto sm:min-w-48"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  {loading ? "Starting collectors…" : target === "repository" ? "Scan repository" : "Start scan"}
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}
              <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
                Progress, warnings, findings, and graph creation continue on this page.
              </p>
            </div>

          </div>

          <aside className="border-t border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 sm:p-5 lg:border-t-0 lg:border-l">
            <ScanWorkspacePanel
              chips={scopeChips}
              mode={scanMode}
              target={target}
              enrich={Boolean(form.enrich)}
            />
          </aside>
        </form>
        )}
      </div>

      <nav aria-label="Related" className="mt-4 flex flex-wrap gap-3 text-xs text-[color:var(--text-tertiary)]">
        <RelatedLink href="/connections">Cloud accounts</RelatedLink>
        <RelatedLink href="/sources">Data sources</RelatedLink>
        <RelatedLink href="/jobs">Scan jobs</RelatedLink>
      </nav>
    </div>
  );
}
