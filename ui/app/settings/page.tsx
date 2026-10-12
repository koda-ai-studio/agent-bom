"use client";

import Link from "next/link";
import { ArrowRight, KeyRound, Plug, ScrollText, ShieldCheck } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { ThemePreferenceControl } from "@/components/theme-toggle";
import { sessionPresentation } from "@/lib/session-presentation";

export default function SettingsPage() {
  const { session, hasCapability, signOut } = useAuthState();
  const identity = sessionPresentation(session);
  const destinations = [
    { href: "/connections", name: "Connections", description: "Connect sources, inspect collection status and review supported permissions.", icon: Plug, visible: hasCapability("scan.run") },
    { href: "/audit#access", name: "Access & keys", description: "Review authentication policy, create service keys and manage rotation.", icon: KeyRound, visible: hasCapability("keys.manage") },
    { href: "/audit", name: "Audit history", description: "Inspect recorded actions and export attributable evidence.", icon: ScrollText, visible: hasCapability("audit.read") },
    { href: "/self-posture", name: "Control plane security", description: "Inspect this deployment's authentication, storage and operational safeguards.", icon: ShieldCheck, visible: hasCapability("policy.manage") },
  ].filter(item => item.visible);
  return <div className="mx-auto max-w-5xl space-y-8">
    <header><p className="text-sm text-ink-secondary">Account &amp; deployment</p><h1 className="mt-1 text-3xl font-semibold tracking-tight">Settings</h1><p className="mt-2 text-ink-secondary">Your session, appearance and the controls available to your role.</p></header>
    <section aria-labelledby="profile-heading" className="rounded-xl border border-outline bg-surface p-5 sm:p-6">
      <h2 id="profile-heading" className="text-lg font-semibold">Profile &amp; session</h2>
      <dl className="mt-5 grid gap-5 text-sm sm:grid-cols-2">
        {[["Identity", session ? identity.name : "Offline report"], ["Authentication", identity.method], ["Role", session?.role_summary?.display_name || session?.role || "Not available"], ["Active scope", session?.tenant_id || "Local report only"]].map(([name, value]) => <div key={name}><dt className="text-ink-secondary">{name}</dt><dd className="mt-1 break-words font-medium">{value}</dd></div>)}
      </dl>
      <p className="mt-5 text-sm leading-6 text-ink-secondary">{session ? identity.description : "No authenticated control-plane identity is available in offline mode."}</p>
      <p className="mt-2 text-sm text-ink-secondary">Identity, role and scope are read-only here. Contact your administrator to change access.</p>
      {identity.canSignOut && <div className="mt-5 border-t border-outline pt-4"><button type="button" onClick={() => void signOut()} className="rounded-lg border border-outline px-4 py-2 text-sm font-medium hover:bg-surface-muted">Sign out</button><p className="mt-2 text-xs text-ink-secondary">Ends the local browser session. Your identity provider or reverse proxy may remain signed in.</p></div>}
    </section>
    <section aria-labelledby="appearance-heading" className="rounded-xl border border-outline bg-surface p-5 sm:p-6"><h2 id="appearance-heading" className="text-lg font-semibold">Appearance</h2><p className="mb-4 mt-2 text-sm text-ink-secondary">System follows this device's color preference. Your choice is saved in this browser.</p><ThemePreferenceControl /></section>
    {destinations.length > 0 && <section aria-labelledby="administration-heading"><h2 id="administration-heading" className="text-lg font-semibold">Deployment &amp; administration</h2><div className="mt-4 grid gap-4 sm:grid-cols-2">{destinations.map(item => <Link key={item.href} href={item.href} className="group rounded-xl border border-outline bg-surface p-5 hover:border-outline-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500"><div className="flex items-center gap-3"><item.icon className="h-5 w-5 text-ink-secondary" /><h3 className="font-medium">{item.name}</h3><ArrowRight className="ml-auto h-4 w-4" /></div><p className="mt-3 text-sm leading-6 text-ink-secondary">{item.description}</p></Link>)}</div></section>}
  </div>;
}
