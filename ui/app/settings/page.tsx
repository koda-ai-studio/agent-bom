"use client";

import Link from "next/link";
import { ArrowRight, KeyRound, Monitor, Plug, ScrollText, ShieldCheck, UserRound } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { ThemePreferenceControl } from "@/components/theme-toggle";
import { sessionPresentation } from "@/lib/session-presentation";

function MetadataRow({ label, value }: { label: string; value: string }) {
  return <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-outline py-3 last:border-b-0">
    <dt className="text-sm text-ink-secondary">{label}</dt>
    <dd className="max-w-[70%] break-words text-right text-sm font-medium text-foreground">{value}</dd>
  </div>;
}

export default function SettingsPage() {
  const { session, hasCapability, signOut } = useAuthState();
  const identity = sessionPresentation(session);
  const memberships = session?.memberships ?? [];
  const activeMembership = memberships.find(membership => membership.active);
  // AuthMembership.display_name is the role's UI label, not the organization name.
  const workspaceName = activeMembership?.tenant_id || session?.tenant_id || "Local report only";
  const status = !session ? "Offline report" : session.auth_required === false ? "Authentication disabled" : session.authenticated ? "Session active" : "Sign-in required";
  const destinations = [
    { href: "/connections", name: "Connections", description: "Connect sources and review collection status.", icon: Plug, visible: hasCapability("scan.run") },
    { href: "/audit#access", name: "Access & keys", description: "Review authentication policy and service keys.", icon: KeyRound, visible: hasCapability("keys.manage") },
    { href: "/audit", name: "Audit history", description: "Inspect recorded actions and attributable evidence.", icon: ScrollText, visible: hasCapability("audit.read") },
    { href: "/self-posture", name: "Control plane security", description: "Review this deployment's safeguards.", icon: ShieldCheck, visible: hasCapability("policy.manage") },
  ].filter(item => item.visible);

  return <div className="mx-auto max-w-6xl space-y-6 pb-10">
    <header className="border-b border-outline pb-5">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-ink-secondary">Account</p>
      <h1 className="mt-1 text-3xl font-semibold tracking-tight">Settings</h1>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-ink-secondary">Review how this browser accesses the workspace and adjust your local display preferences.</p>
    </header>

    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(20rem,0.8fr)]">
      <section aria-labelledby="access-heading" className="overflow-hidden rounded-xl border border-outline bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-outline px-5 py-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-outline bg-surface-muted text-ink-secondary"><UserRound className="h-4 w-4" aria-hidden="true" /></span>
            <div className="min-w-0"><h2 id="access-heading" className="font-semibold">Identity &amp; access</h2><p className="mt-0.5 truncate text-sm text-ink-secondary">{session ? identity.name : "Offline report"}</p></div>
          </div>
          <span className="inline-flex shrink-0 items-center gap-2 rounded-full border border-outline bg-surface-muted px-2.5 py-1 text-xs text-ink-secondary">
            <span className={`h-1.5 w-1.5 rounded-full ${session?.auth_required === false || !session ? "bg-amber-500" : session.authenticated ? "bg-emerald-500" : "bg-gray-400"}`} aria-hidden="true" />{status}
          </span>
        </div>
        <div className="px-5 py-2 sm:px-6">
          <dl>
            <MetadataRow label="Authentication" value={session ? identity.method : "No control-plane session"} />
            <MetadataRow label="Role" value={session?.role_summary?.display_name || session?.role || "Not available"} />
            <MetadataRow label="Active tenant" value={workspaceName} />
          </dl>
          {session && memberships.length > 1 && <details className="mb-3 rounded-lg border border-outline bg-surface-muted/20">
            <summary className="cursor-pointer px-3 py-2.5 text-sm font-medium marker:text-ink-secondary">Other workspace memberships <span className="ml-1 text-xs font-normal text-ink-secondary">{memberships.length - (activeMembership ? 1 : 0)}</span></summary>
            <ul className="space-y-1 border-t border-outline px-3 py-2">
              {memberships.filter(membership => !membership.active).map(membership => <li key={membership.tenant_id} className="flex flex-wrap items-center justify-between gap-2 py-1.5 text-sm"><span>{membership.tenant_id}</span><span className="text-xs text-ink-secondary">{membership.ui_role || membership.role}</span></li>)}
            </ul>
            <p className="border-t border-outline px-3 py-2 text-xs leading-5 text-ink-secondary">Memberships are supplied by the session. Workspace changes use your configured access workflow.</p>
          </details>}
          <p className="border-t border-outline py-3 text-xs leading-5 text-ink-secondary">{session ? identity.description : "No authenticated control-plane identity is available in offline mode."} Identity, role and tenant scope are read-only here; the tenant ID is the workspace label supplied by this session.</p>
          {identity.canSignOut && <div className="flex flex-wrap items-center justify-between gap-3 border-t border-outline py-3">
            <p className="max-w-lg text-xs leading-5 text-ink-secondary">Sign out ends this browser session; your identity provider or reverse proxy may remain signed in.</p>
            <button type="button" onClick={() => void signOut()} className="shrink-0 rounded-lg border border-outline px-3 py-1.5 text-sm font-medium hover:bg-surface-muted">Sign out</button>
          </div>}
        </div>
      </section>

      <section aria-labelledby="appearance-heading" className="rounded-xl border border-outline bg-surface p-5 sm:p-6">
        <div className="flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-full border border-outline bg-surface-muted text-ink-secondary"><Monitor className="h-4 w-4" aria-hidden="true" /></span><div><h2 id="appearance-heading" className="font-semibold">Appearance</h2><p className="mt-0.5 text-sm text-ink-secondary">Saved in this browser</p></div></div>
        <div className="mt-5"><ThemePreferenceControl /></div>
        <p className="mt-3 text-xs leading-5 text-ink-secondary">System follows your device’s color preference.</p>
      </section>
    </div>

    {destinations.length > 0 && <section aria-labelledby="workspace-tools-heading" className="pt-1">
      <div className="flex items-end justify-between gap-3"><div><h2 id="workspace-tools-heading" className="font-semibold">Workspace &amp; deployment</h2><p className="mt-1 text-sm text-ink-secondary">Controls available to your current role.</p></div></div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{destinations.map(item => <Link key={item.href} href={item.href} className="group rounded-xl border border-outline bg-surface p-4 transition-colors hover:border-outline-strong hover:bg-surface-muted/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500"><div className="flex items-center gap-2"><item.icon className="h-4 w-4 text-ink-secondary" aria-hidden="true" /><h3 className="text-sm font-medium">{item.name}</h3><ArrowRight className="ml-auto h-4 w-4 text-ink-secondary transition-transform group-hover:translate-x-0.5" aria-hidden="true" /></div><p className="mt-2 text-xs leading-5 text-ink-secondary">{item.description}</p></Link>)}</div>
    </section>}
  </div>;
}
