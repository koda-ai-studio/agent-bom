import { expect, test } from '@playwright/test';

for (const scenario of [
  { theme: 'light', width: 1440, height: 1000 },
  { theme: 'dark', width: 1440, height: 1000 },
  { theme: 'light', width: 390, height: 844 },
] as const) {
  test(`MCP audit coverage and review ${scenario.theme} ${scenario.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize(scenario);
    await page.addInitScript(theme => localStorage.setItem('agent-bom-theme', theme), scenario.theme);
    const finding = { id: 'audit-1', source: 'MCP_SCAN', severity: 'medium', title: 'Excess tool capabilities', finding_class: 'misconfiguration', description: 'A read-only workflow advertises command execution.', remediation_guidance: 'Review the required capabilities and restrict unnecessary tools.', node_id: 'server:files', evidence: { detector: 'mcp_enforcement', category: 'over_permission', server_canonical_id: 'mcp-server:files', affected_tools: ['execute_command'] } };
    const job = { job_id: 'audit-scan', status: 'done', created_at: '2026-10-12T00:00:00Z', result: { agents: [], blast_radius: [], findings: [finding, finding], enforcement: { coverage: [{ server_name: 'Files MCP', server_identity: 'command:files', server_canonical_id: 'mcp-server:files', agent_name: 'Research assistant', tools: { status: 'inspected', inspected: 2 }, resources: { status: 'failed', inspected: 0, reason: 'Live listing failed; resource coverage is incomplete.' }, prompts: { status: 'unsupported', inspected: 0 }, permission_scope: { status: 'inspected', reason: 'Operator supplied a read-only capability profile.' } }] } } };
    await page.route('**/v1/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path.startsWith('/v1/auth/')) return route.fulfill({ json: { authenticated: true, tenant_id: 'fixture', role: 'analyst', permissions: ['read'] } });
      if (path === '/v1/scan/audit-scan' || path === '/v1/scan/audit-scan/status') return route.fulfill({ json: job });
      return route.fulfill({ status: 503, json: { detail: 'Outside audit fixture' } });
    });
    await page.goto('/scan?id=audit-scan');
    const panel = page.getByRole('region', { name: 'MCP security audit' });
    await expect(panel).toBeVisible();
    await expect(panel.getByText('1 finding in inspected scope')).toBeVisible();
    await panel.getByText('Files MCP · Research assistant', { exact: true }).click();
    await expect(panel.getByText('failed', { exact: true })).toBeVisible();
    await panel.getByText('Proposed tool restriction', { exact: true }).click();
    await expect(panel.getByText(/Nothing has been activated/)).toBeVisible();
    const asset = new URL(await panel.getByRole('link', { name: 'Inspect asset' }).getAttribute('href') ?? '', 'http://localhost');
    expect(asset.searchParams.get('scan')).toBe('audit-scan');
    expect(asset.searchParams.get('node')).toBe('server:files');
    expect(asset.searchParams.get('finding')).toBe('audit-1');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await panel.screenshot({ path: testInfo.outputPath(`mcp-audit-${scenario.theme}-${scenario.width}.png`) });
  });
}
