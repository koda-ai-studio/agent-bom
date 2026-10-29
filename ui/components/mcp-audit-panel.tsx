'use client';

import Link from 'next/link';
import type { ScanResult } from '@/lib/api-types';
import { buildFindingAssetHref } from '@/lib/finding-investigation-href';
import { mcpAuditFindings, proposedToolRestriction } from '@/lib/mcp-audit';
import { SeverityBadge } from '@/components/severity-badge';

export function McpAuditPanel({ result, scanId: jobId }: { result: ScanResult; scanId: string }) {
  const scanId = result.scan_id?.trim() || jobId;
  const coverage = result.enforcement?.coverage ?? [];
  const findings = mcpAuditFindings(result.findings);
  if (!coverage.length && !findings.length) return null;
  const servers = new Set(coverage.map(row => row.server_canonical_id || row.server_identity));
  const findingsHref = `/findings?${new URLSearchParams({ scan: scanId, window: '0' })}`;
  return (
    <section aria-label='MCP security audit' className='rounded-2xl border border-outline bg-surface p-5 sm:p-6 space-y-5'>
      <div className='flex flex-wrap items-start justify-between gap-3'>
        <div>
          <h2 className='text-lg font-semibold text-foreground'>MCP security audit</h2>
          <p className='text-sm text-ink-secondary'>{findings.length} {findings.length === 1 ? 'finding' : 'findings'} in inspected scope</p>
        </div>
        <Link href={findingsHref} className='text-sm font-medium text-blue-700 dark:text-blue-300 hover:underline'>Review scan findings →</Link>
      </div>
      <p className='text-sm text-ink-secondary'>Descriptor and configuration checks. Resource bodies, rendered prompts and authorization bypass are not assessed. Capability estimates do not prove operating-system permissions.</p>
      {coverage.length ? (
        <div className='space-y-3'>
          <p className='text-sm font-medium text-foreground'>{servers.size} recorded {servers.size === 1 ? 'server' : 'servers'} · {coverage.length} agent configurations</p>
          {coverage.map((row, index) => (
            <details key={`${row.server_identity}:${row.agent_name}:${index}`} className='rounded-xl border border-outline p-3'>
              <summary className='cursor-pointer text-sm font-medium text-foreground break-words'>{row.server_name} · {row.agent_name}</summary>
              <div className='mt-3 grid gap-3 sm:grid-cols-3'>
                {(['tools', 'resources', 'prompts'] as const).map(kind => {
                  const surface = row[kind];
                  return <div key={kind} className='rounded-lg bg-surface-elevated p-3 text-sm'>
                    <div className='font-medium capitalize text-foreground'>{kind}</div>
                    <div className={surface?.status === 'inspected' ? 'text-ink-secondary' : 'text-amber-800 dark:text-amber-300'}>{surface?.status || 'unknown'}</div>
                    <p className='text-ink-secondary'>{surface?.inspected ?? 'Unknown'} descriptor observations inspected</p>
                    {surface?.reason ? <p className='mt-1 text-xs text-ink-secondary'>{surface.reason}</p> : null}
                  </div>;
                })}
              </div>
              <p className='mt-3 break-all text-xs text-ink-tertiary'>Server identity: {row.server_canonical_id || row.server_identity}</p>
              {row.permission_scope ? <p className='mt-2 text-xs text-ink-secondary'>Permission scope: {row.permission_scope.status}. {row.permission_scope.reason}</p> : null}
            </details>
          ))}
        </div>
      ) : <p className='text-sm text-amber-800 dark:text-amber-300'>Coverage was not recorded for this scan. Re-run a scoped audit before interpreting an empty finding list.</p>}
      <div className='space-y-3'>
        {findings.slice(0, 8).map(finding => {
          const proposal = proposedToolRestriction(finding);
          const findingHref = `${findingsHref}&finding=${encodeURIComponent(finding.id)}`;
          return <article key={finding.id} className='rounded-xl bg-surface-elevated p-4 space-y-2'>
            <div className='flex flex-wrap items-center gap-2'><SeverityBadge severity={finding.severity} /><Link href={findingHref} className='text-sm font-medium text-foreground hover:underline'>{finding.title || 'MCP finding'}</Link></div>
            {finding.description ? <p className='text-sm text-ink-secondary break-words'>{finding.description}</p> : null}
            {finding.remediation_guidance ? <p className='text-sm text-foreground break-words'>{finding.remediation_guidance}</p> : null}
            {finding.node_id ? <Link className='inline-block text-sm text-blue-700 dark:text-blue-300 hover:underline' href={buildFindingAssetHref({ nodeId: finding.node_id, findingId: finding.id, scanId })}>Inspect asset</Link> : <p className='text-xs text-ink-tertiary'>No exact asset link recorded.</p>}
            {proposal ? <details className='pt-1'>
              <summary className='cursor-pointer text-sm font-medium text-foreground'>Proposed tool restriction</summary>
              <p className='mt-2 text-xs text-ink-secondary'>Draft only. Review application needs and bind a dedicated proxy to this recorded server before using this policy. Nothing has been activated.</p>
              <p className='mt-2 text-xs text-ink-secondary break-all'>Server: {String(finding.evidence?.server_canonical_id)}</p>
              <pre className='mt-2 max-h-60 overflow-auto rounded-lg border border-outline p-3 text-xs text-foreground'>{proposal}</pre>
            </details> : null}
          </article>;
        })}
      </div>
      {findings.length > 8 ? <p className='text-sm text-ink-secondary'>Showing 8 of {findings.length} MCP findings. Open scan findings for all findings.</p> : null}
      <p className='text-xs text-ink-secondary'>Review the descriptor or server configuration, make a scoped change, then re-run <code>agent-bom mcp audit . --format json --output mcp-audit.json</code>.</p>
    </section>
  );
}
