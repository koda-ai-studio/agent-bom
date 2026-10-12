"use client";

import { TraceCollectionPanel } from "@/components/trace-collection-panel";
import Link from "next/link";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { TraceConnectorPullResponse, TraceConnectorsResponse } from "@/lib/api-types";
import { useAuthState } from "@/components/auth-provider";

type Provider = "langfuse" | "langsmith";
const hosts = { langfuse: "https://cloud.langfuse.com", langsmith: "https://api.smith.langchain.com" };

export function TraceConnectorsPanel() {
  const { hasCapability, session } = useAuthState();
  const [provider, setProvider] = useState<Provider>("langfuse");
  const [host, setHost] = useState(hosts.langfuse);
  const [publicKey, setPublicKey] = useState("");
  const [secret, setSecret] = useState("");
  const [project, setProject] = useState("");
  const [screenContent, setScreenContent] = useState(false);
  const [connections, setConnections] = useState<NonNullable<TraceConnectorsResponse["connections"]>>([]);
  const [connectionId, setConnectionId] = useState("");
  const [manual, setManual] = useState(false);
  const [catalogError, setCatalogError] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const canPull = hasCapability("runtime.ingest");
  useEffect(() => {
    if (!canPull) return;
    let active = true;
    api.listTraceConnectors().then(data => { if (active) setConnections(data.connections ?? []); })
      .catch(() => { if (active) setCatalogError(true); })
      .finally(() => { if (active) setCatalogLoading(false); });
    return () => { active = false; };
  }, [canPull]);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<TraceConnectorPullResponse | null>(null);
  const [error, setError] = useState(false);
  const generation = useRef(0);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => { generation.current += 1; abort.current?.abort(); }, []);

  function changeProvider(next: Provider) {
    generation.current += 1; abort.current?.abort();
    setConnectionId(""); setProvider(next); setHost(hosts[next]); setPublicKey(""); setSecret(""); setProject("");
    setResult(null); setError(false); setPending(false); setScreenContent(false);
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending || !hasCapability("runtime.ingest")) return;
    const epoch = ++generation.current;
    const controller = new AbortController(); abort.current = controller;
    setPending(true); setError(false); setResult(null);
    if (!manual && !connectionId) { setPending(false); return; }
    const credentials = provider === "langfuse" ? { host, public_key: publicKey, secret_key: secret } : { api_url: host, api_key: secret, project };
    setSecret(""); setPublicKey("");
    try {
      const next = await api.pullTraceConnector(provider, { ...(manual ? { credentials } : { connection_id: connectionId }), limit: 50, screen_content: screenContent }, controller.signal);
      if (epoch === generation.current) setResult(next);
    } catch {
      if (epoch === generation.current) setError(true);
    } finally {
      if (epoch === generation.current) setPending(false);
    }
  }
  if (!hasCapability("runtime.ingest")) return <p className="text-sm text-[var(--text-secondary)]">Pulling platform traces requires runtime ingest permission. Ask an administrator for access.</p>;
  const inputClass = "mt-1 block w-full rounded-lg border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]";
  return <section aria-label="Trace platform connectors" className="grid gap-6 lg:grid-cols-2">
    <form onSubmit={submit} className="space-y-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-5">
      <h2 className="text-lg font-semibold">Connect trace evidence</h2>
      <p className="text-sm text-[var(--text-secondary)]">Pull a bounded sample of tool calls and match recorded tool, server and package identities against your tenant’s findings.</p>
      <label className="block text-sm">Platform<select value={provider} onChange={event => changeProvider(event.target.value as Provider)} className={inputClass}><option value="langfuse">Langfuse</option><option value="langsmith">LangSmith / LangChain / LangGraph</option></select></label>
      {!manual && <>
        <label className="block text-sm">Managed connection<select required value={connectionId} onChange={event => { setConnectionId(event.target.value); setResult(null); }} className={inputClass}>
          <option value="">{catalogLoading ? "Loading connections…" : "Choose a connection"}</option>
          {connections.filter(connection => connection.provider === provider).map(connection => <option key={connection.id} value={connection.id}>{connection.display_name}</option>)}
        </select></label>
        <p className="text-xs text-[var(--text-secondary)]">Use your existing Agent-Bom session. Your control plane supplies the configured credentials; keys stay out of the browser. Configured access is verified when you pull.</p>
        {catalogError ? <p role="alert" className="text-sm text-amber-800 dark:text-amber-200">Managed connections could not be loaded. Ask your operator to check configuration.</p> : !catalogLoading && !connections.some(connection => connection.provider === provider) && <p className="text-sm text-[var(--text-secondary)]">No managed connection is configured for this platform. Ask your operator to connect the project once.</p>}
      </>}
      <a href="https://github.com/koda-ai-studio/agent-bom/blob/main/docs/TRACE_CONNECTIONS.md" target="_blank" rel="noopener noreferrer" className="block text-sm underline text-emerald-800 dark:text-emerald-300">Managed connection setup</a>
      <details open={manual} onToggle={event => { const open = event.currentTarget.open; if (open !== manual) { generation.current += 1; abort.current?.abort(); setManual(open); setSecret(""); setPublicKey(""); setResult(null); setPending(false); } }}>
        <summary className="cursor-pointer text-sm text-[var(--text-secondary)]">Advanced: use temporary credentials</summary>
        {manual && <div className="mt-4 space-y-4">
      <label className="block text-sm">Public HTTPS endpoint<input required type="url" value={host} onChange={event => setHost(event.target.value)} className={inputClass} /></label>
      {provider === "langfuse" ? <label className="block text-sm">Public key<input required autoComplete="off" value={publicKey} onChange={event => setPublicKey(event.target.value)} className={inputClass} /></label> : <label className="block text-sm">Project name<input required value={project} onChange={event => setProject(event.target.value)} className={inputClass} /></label>}
      <label className="block text-sm">{provider === "langfuse" ? "Secret key" : "API key"}<input required type="password" autoComplete="off" value={secret} onChange={event => setSecret(event.target.value)} className={inputClass} /></label>
        <p className="text-xs text-[var(--text-secondary)]">These credentials are sent to your control plane for this request and are not saved by this form.</p>
        </div>}
      </details>
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={screenContent} onChange={event => setScreenContent(event.target.checked)} className="mt-1" />Screen returned tool outputs for sensitive content</label>
      <p className="text-xs text-[var(--text-secondary)]">Screening is off by default. Provider responses may still include content; it is excluded from correlation when screening is off. Only public HTTPS hosts are accepted. Private installations can send OTLP through their collector.</p>
      <button disabled={pending || (!manual && !connectionId)} className="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">{pending ? "Correlating…" : "Pull and correlate"}</button>
    </form>
    <div className="space-y-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-5">
      {!manual && provider === "langfuse" && connectionId && <TraceCollectionPanel key={JSON.stringify([session, connectionId])} connectionId={connectionId} />}
      <h2 className="text-lg font-semibold">Sample correlation result</h2>
      <p className="text-sm text-[var(--text-secondary)]">This request reviews up to 50 provider records. Results are not saved to the trace explorer; this is not continuous collection or a complete trace history.</p>
      {!result && !error && <p role="status" className="text-sm text-[var(--text-secondary)]">{pending ? "Waiting for the provider…" : "Select a platform and pull a sample to review security matches."}</p>}
      {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">Trace pull failed. Check access, project name, endpoint and provider availability. No successful result is available.</p>}
      {result && <>
        <p className="font-medium">{result.pulled_spans} tool calls reviewed · {result.attack_paths.length} finding matches</p>
        {result.pulled_spans === 0 ? <p className="text-sm text-amber-800 dark:text-amber-200">No tool-call evidence was parsed in this sample. This is not a clean security verdict.</p> : result.attack_paths.length === 0 && <p className="text-sm text-[var(--text-secondary)]">No matches to known vulnerable assets. This does not establish scan coverage or safety.</p>}
        <div className="space-y-3">{result.attack_paths.map((path, index) => <article key={`${path.span_id}:${path.vulnerability_id}:${index}`} className="rounded-lg border border-[var(--border-subtle)] p-3 text-sm">
          <Link className="text-emerald-800 underline dark:text-emerald-300" href={`/findings?cve=${encodeURIComponent(path.vulnerability_id)}`}>{path.vulnerability_id}</Link>
          <p className="mt-1 break-all">{path.tool_name} · {path.server_name || "Server not recorded"}</p>
          <p className="mt-1 break-all text-xs text-[var(--text-secondary)]">Trace {path.trace_id || "not recorded"} · span {path.span_id || "not recorded"}</p>
        </article>)}</div>
        {result.content_screened && <p className="text-sm">Content screening returned {result.content_findings.length} detections. Raw outputs are not displayed here.</p>}
      </>}
    </div>
  </section>;
}
