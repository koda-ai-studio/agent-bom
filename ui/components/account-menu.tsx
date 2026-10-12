"use client";

import Link from "next/link";
import { useRef } from "react";
import { Building2, ChevronDown, LogOut, Settings, UserRound } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { ThemePreferenceControl } from "@/components/theme-toggle";
import { sessionPresentation } from "@/lib/session-presentation";

export function AccountMenu() {
  const { session, loading, signOut, hasCapability } = useAuthState();
  const panel = useRef<HTMLDetailsElement>(null);
  const trigger = useRef<HTMLElement>(null);
  const identity = sessionPresentation(session);
  const displayName = loading ? "Checking session…" : session ? identity.name : "Offline";
  const close = () => { if (panel.current) panel.current.open = false; };
  return <details ref={panel} className="relative shrink-0" onKeyDown={event => {
    if (event.key === "Escape") { close(); trigger.current?.focus(); }
  }} onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) close(); }}>
    <summary ref={trigger} aria-label={`Account menu: ${displayName}`} className="flex cursor-pointer list-none items-center gap-2 rounded-lg border border-outline bg-surface-muted px-2 py-2 text-sm md:px-3 text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500 [&::-webkit-details-marker]:hidden">
      <UserRound className="h-4 w-4" aria-hidden="true" /><span className="hidden max-w-40 truncate md:inline">{displayName}</span><ChevronDown className="hidden h-3 w-3 md:block" aria-hidden="true" />
    </summary>
    <div className="absolute right-0 top-full z-50 mt-2 max-h-[calc(100vh-6rem)] w-[24rem] max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl border border-outline bg-surface p-4 shadow-xl" aria-label="Account details">
      <section aria-labelledby="account-signed-in-label" className="border-b border-outline pb-4">
        <p id="account-signed-in-label" className="mb-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-secondary">{session?.authenticated ? "Signed in" : "Session"}</p>
        <div className="flex items-start gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-outline bg-surface-muted text-ink-secondary"><UserRound className="h-5 w-5" aria-hidden="true" /></span>
          <div className="min-w-0 flex-1">
            <p className="break-words text-sm font-semibold text-foreground">{session ? identity.name : "Offline report"}</p>
            <p className="mt-1 text-xs text-ink-secondary">{session ? identity.method : "No control-plane session"}{session?.role_summary?.display_name ? ` · ${session.role_summary.display_name}` : ""}</p>
            <span className="mt-2 inline-flex items-center rounded-full border border-outline bg-surface-muted px-2 py-0.5 text-[10px] font-medium text-ink-secondary">
              {!session ? "Offline" : session.auth_required === false ? "Unauthenticated access" : session.authenticated ? "Signed in" : "Sign-in required"}
            </span>
          </div>
        </div>
      </section>
      <section aria-labelledby="account-workspace-label" className="border-b border-outline py-4">
        <p id="account-workspace-label" className="mb-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-secondary">Organization</p>
        {session ? <div className="flex min-w-0 items-center gap-3">
          <Building2 className="h-5 w-5 shrink-0 text-ink-secondary" aria-hidden="true" />
          <span className="min-w-0 flex-1" title={session.tenant_id}><span className="block text-[10px] text-ink-secondary">Tenant ID</span><span className="block truncate text-sm font-medium">{session.tenant_id}</span></span>
          <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-600 dark:text-emerald-300">Active</span>
        </div> : <p className="text-xs text-ink-secondary">No active workspace is available in offline mode.</p>}
      </section>
      <section aria-labelledby="account-theme-label" className="border-b border-outline py-4">
        <p id="account-theme-label" className="mb-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-secondary">Theme</p>
        <ThemePreferenceControl />
      </section>
      <section aria-label="Account navigation" className="space-y-1 pt-4">
        <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-secondary">You</p>
        <Link href="/settings" onClick={close} className="flex items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-surface-muted"><Settings className="h-4 w-4" />Profile &amp; settings</Link>
        {hasCapability("keys.manage") && <Link href="/audit#access" onClick={close} className="block rounded-lg px-2 py-2 text-sm hover:bg-surface-muted">Access &amp; keys</Link>}
        {hasCapability("audit.read") && <Link href="/audit" onClick={close} className="block rounded-lg px-2 py-2 text-sm hover:bg-surface-muted">Audit history</Link>}
        {identity.canSignOut && <button type="button" onClick={() => { close(); void signOut(); }} className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-surface-muted"><LogOut className="h-4 w-4" />Sign out</button>}
      </section>
    </div>
  </details>;
}
