"use client";

export type ConnectionScope = "account" | "organization";

const scopes: Record<string, { label: string; single: string; multiple: string; grant: string }> = {
  aws: { label: "AWS", single: "Single account", multiple: "Whole organization", grant: "Deploy the read-only member roles before scanning the organization." },
  azure: { label: "Azure", single: "Single subscription", multiple: "Discovered subscriptions", grant: "Use a read-only identity with management-group discovery and Reader access on the intended subscriptions. A grant on one subscription does not grant access to its siblings." },
  gcp: { label: "GCP", single: "Single project", multiple: "Discovered organization projects", grant: "Use a read-only identity with organization/folder discovery and Viewer access on the intended projects. A grant on one project does not grant access to its siblings." },
};

export function ConnectionScopePicker({ provider, value, restricted, onChange }: {
  provider: string; value: ConnectionScope; restricted: boolean; onChange: (scope: ConnectionScope) => void;
}) {
  const config = scopes[provider];
  if (!config) return null;
  return <section className="space-y-2 rounded-xl border border-outline bg-surface-elevated p-4">
    <h3 className="text-sm font-medium">Collection scope</h3>
    <div role="group" aria-label={`${config.label} onboarding scope`} className="grid gap-2 sm:grid-cols-2">
      {(restricted ? ["account"] as const : ["account", "organization"] as const).map(scope => <button
        key={scope} type="button" aria-pressed={value === scope} onClick={() => onChange(scope)}
        className={`rounded-lg border px-3 py-2 text-left text-sm ${value === scope ? "border-emerald-500 bg-emerald-500/10 text-foreground" : "border-outline text-ink-secondary"}`}
      >{scope === "account" ? config.single : config.multiple}</button>)}
    </div>
    {value === "organization" && provider === "aws" && <p className="text-xs leading-5 text-ink-secondary">{config.grant}</p>}
  </section>;
}

export function OrganizationScopeSetup({ provider, workload }: { provider: string; workload: boolean }) {
  return <section aria-label="Organization setup" className="space-y-3 rounded-xl border border-outline p-4 text-sm">
    <h3 className="font-medium">Connect the existing read-only identity once</h3>
    <p>{scopes[provider]?.grant}</p>
    <p>Inventory and CIS checks cover only the scopes returned by discovery, within the configured collection limits. Missing permissions and collection failures are not proof that the rest of the organization is clean.</p>
    {workload ? <p>The operator binding must authorize organization scope and match this connection’s identity and anchor subscription or project. An account-only binding will be rejected.</p> : <p>Enter the identity and an anchor subscription or project in Details. Existing permissions determine what discovery can read; creating this connection does not grant access.</p>}
    <p className="text-ink-secondary">Verify credentials after saving, then run a scan and inspect the recorded scope and coverage. No scan starts until requested.</p>
  </section>;
}
