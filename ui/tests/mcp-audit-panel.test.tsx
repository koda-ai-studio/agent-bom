import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { McpAuditPanel } from '@/components/mcp-audit-panel';
import type { ScanResult } from '@/lib/api-types';

const finding = { id: 'issue-1', finding_class: 'misconfiguration' as const, source: 'MCP_SCAN', severity: 'medium', title: 'Excess tool capabilities', node_id: 'server:exact', evidence: { detector: 'mcp_enforcement', category: 'over_permission', affected_tools: ['execute_command'], server_canonical_id: 'server-id' } };
const result = { agents: [], blast_radius: [], findings: [finding, finding], enforcement: { coverage: [{ server_name: 'Files', server_identity: 'command:files', server_canonical_id: 'server-id', agent_name: 'Assistant', tools: { status: 'failed', discovered: 2, inspected: 2, reason: 'Live listing failed; retained descriptors inspected.' }, resources: { status: 'inspected', discovered: 0, inspected: 0 }, prompts: { status: 'unsupported', discovered: 0, inspected: 0 } }] } } as ScanResult;

describe('MCP audit panel', () => {
  it('deduplicates findings and exposes incomplete coverage without a clean verdict', () => {
    render(<McpAuditPanel result={result} scanId='historical scan' />);
    expect(screen.getByText('1 finding in inspected scope')).toBeInTheDocument();
    expect(screen.getByText('failed')).toBeInTheDocument();
    expect(screen.getByText(/Resource bodies, rendered prompts and authorization bypass are not assessed/)).toBeInTheDocument();
    expect(screen.queryByText(/all clear|passed|safe/i)).not.toBeInTheDocument();
  });
  it('uses recorded node and scan for drilldowns and keeps proposals inert', () => {
    render(<McpAuditPanel result={result} scanId='historical scan' />);
    const url = new URL(screen.getByRole('link', { name: 'Inspect asset' }).getAttribute('href')!, 'http://localhost');
    expect(url.searchParams.get('node')).toBe('server:exact');
    expect(url.searchParams.get('scan')).toBe('historical scan');
    expect(url.searchParams.get('finding')).toBe('issue-1');
    expect(screen.getByText(/Draft only/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /activate|apply/i })).not.toBeInTheDocument();
  });
  it('does not infer missing audit coverage or invent graph links', () => {
    render(<McpAuditPanel result={{ agents: [], blast_radius: [], findings: [{...finding, node_id: null}] }} scanId='scan' />);
    expect(screen.getByText(/Coverage was not recorded/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Inspect asset' })).not.toBeInTheDocument();
  });
  it('retains imported snapshot identity instead of the dispatch job id', () => {
    render(<McpAuditPanel result={{ ...result, scan_id: 'imported-snapshot' }} scanId='dispatch-job' />);
    const href = new URL(screen.getByRole('link', { name: 'Inspect asset' }).getAttribute('href')!, 'http://localhost');
    expect(href.searchParams.get('scan')).toBe('imported-snapshot');
    expect(href.searchParams.get('finding_scan')).toBe('imported-snapshot');
  });
  it('does not count dependency vulnerabilities as descriptor audit findings', () => {
    const dependency = { ...finding, id: 'dependency', evidence: {}, title: 'Package vulnerability' };
    render(<McpAuditPanel result={{ ...result, findings: [finding, dependency] }} scanId='scan' />);
    expect(screen.getByText('1 finding in inspected scope')).toBeInTheDocument();
    expect(screen.queryByText('Package vulnerability')).not.toBeInTheDocument();
  });
});
