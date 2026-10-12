"use client";

import Link from "next/link";
import { useRef } from "react";
import { ChevronDown, LogOut, Settings, UserRound } from "lucide-react";
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
  return <details ref={panel} className="relative" onKeyDown={event => {
    if (event.key === "Escape") { close(); trigger.current?.focus(); }
  }} onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) close(); }}>
    <summary ref={trigger} aria-label={`Account menu: ${displayName}`} className="flex cursor-pointer list-none items-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2 text-sm text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500 [&::-webkit-details-marker]:hidden">
      <UserRound className="h-4 w-4" aria-hidden="true" /><span className="hidden max-w-40 truncate md:inline">{displayName}</span><ChevronDown className="h-3 w-3" aria-hidden="true" />
    </summary>
    <div className="absolute right-0 top-full z-50 mt-2 w-80 max-w-[calc(100vw-2rem)] space-y-4 rounded-xl border border-outline bg-surface p-4 shadow-xl" aria-label="Account details">
      <div className="space-y-1 text-sm"><p className="break-words font-semibold">{session ? identity.name : "Offline report"}</p>
        <p className="text-ink-secondary">{session ? identity.method : "No control-plane session"}</p>
        {session && <p className="break-words text-ink-secondary">{session.role_summary?.display_name || session.role || "Unknown role"} · {session.tenant_id}</p>}
      </div>
      <ThemePreferenceControl />
      <div aria-label="Account navigation" className="space-y-1 border-t border-outline pt-3">
        <Link href="/settings" onClick={close} className="flex items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-surface-muted"><Settings className="h-4 w-4" />Profile &amp; settings</Link>
        {hasCapability("keys.manage") && <Link href="/audit#access" onClick={close} className="block rounded-lg px-2 py-2 text-sm hover:bg-surface-muted">Access &amp; keys</Link>}
        {hasCapability("audit.read") && <Link href="/audit" onClick={close} className="block rounded-lg px-2 py-2 text-sm hover:bg-surface-muted">Audit history</Link>}
        {identity.canSignOut && <button type="button" onClick={() => { close(); void signOut(); }} className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-surface-muted"><LogOut className="h-4 w-4" />Sign out</button>}
      </div>
    </div>
  </details>;
}
