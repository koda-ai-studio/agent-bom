"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { api, type AuthMeResponse } from "@/lib/api";
import {
  ApiAuthError,
  ApiConflictError,
  ApiForbiddenError,
  ApiNetworkError,
  ApiServerError,
  userFacingApiErrorMessage,
} from "@/lib/api-errors";

import { clearCache } from "@/lib/api-cache";
import { disableOfflineReportMode } from "@/lib/offline-report-mode";
import { isExplicitlySignedOut, isSignOutConfirmed, setExplicitlySignedOut, SESSION_INTENT_EVENT } from "@/lib/session-intent";

interface AuthContextValue {
  signedOut: boolean;
  signOutConfirmed: boolean;
  signOutError: string | null;
  signOut: () => Promise<boolean>;
  resumeSession: () => Promise<void>;
  session: AuthMeResponse | null;
  loading: boolean;
  error: string | null;
  /**
   * True while the probe is silently retrying a transient/aborted fetch. Lets
   * the gate show a subtle "reconnecting…" hint instead of the scary fatal
   * "control plane unreachable" screen on the first aborted request.
   */
  reconnecting: boolean;
  /** True while the UI proxy reports the API is still booting (503 API_STARTING). */
  starting: boolean;
  refresh: () => Promise<void>;
  hasCapability: (capability: string) => boolean;
}

const defaultContext: AuthContextValue = {
  signedOut: false,
  signOutConfirmed: false,
  signOutError: null,
  signOut: async () => false,
  resumeSession: async () => {},
  session: null,
  loading: true,
  error: null,
  reconnecting: false,
  starting: false,
  refresh: async () => {},
  hasCapability: () => false,
};

const AuthContext = createContext<AuthContextValue>(defaultContext);

// Next dev on-demand compilation and route navigation routinely abort the
// bootstrap auth probe (AbortError / TimeoutError). A single aborted or
// transient network hiccup should never surface the fatal "control plane
// unreachable" state — retry a few times with backoff first. A genuine,
// repeated connection refusal still fails all attempts and shows the fatal UI.
const MAX_PROBE_ATTEMPTS = 3;
const PROBE_RETRY_BASE_MS = 150;

/** How long a cold load waits for a booting API before showing the unreachable state. */
export const STARTING_MAX_WAIT_MS = 60_000;

/** Seconds the proxy asked us to wait when the API is still starting; null for any other failure. */
function apiStartingRetryMs(err: unknown): number | null {
  if (!(err instanceof ApiServerError) || err.status !== 503) return null;
  const body = err.body as { error?: { code?: unknown }; retry_after_seconds?: unknown } | undefined;
  if (body?.error?.code !== "API_STARTING") return null;
  const seconds = typeof body.retry_after_seconds === "number" ? body.retry_after_seconds : 2;
  return Math.min(5_000, Math.max(1_000, seconds * 1000));
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableProbeError(err: unknown): boolean {
  // Auth/authorization outcomes are terminal — the operator must sign in.
  if (err instanceof ApiAuthError || err instanceof ApiForbiddenError) return false;
  // Aborted fetches, timeouts, and refused connections all arrive as
  // ApiNetworkError; transient 5xx as ApiServerError. Retry both.
  if (err instanceof ApiNetworkError || err instanceof ApiServerError) return true;
  const message = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    message.includes("abort") ||
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("network")
  );
}

function isLoopbackBrowser(): boolean {
  if (typeof window === "undefined") return false;
  return ["localhost", "127.0.0.1", "::1", "[::1]"].includes(window.location.hostname.toLowerCase());
}

async function tryLoopbackDevSession(resume: boolean): Promise<boolean | "signed_out"> {
  if (!isLoopbackBrowser()) return false;
  try {
    await api.createDevAuthSession(resume);
    return true;
  } catch (error) {
    if (error instanceof ApiConflictError) return "signed_out";
    // Expected for explicit API-key/SSO deployments, where the dev key is
    // intentionally absent. Preserve the original auth result and show login.
    return false;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthMeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reconnecting, setReconnecting] = useState(false);
  const [starting, setStarting] = useState(false);

  const [signedOut, setSignedOut] = useState(false);
  const [signOutConfirmed, setSignOutConfirmed] = useState(false);
  const [signOutError, setSignOutError] = useState<string | null>(null);
  const generation = useRef(0);
  const signOutPending = useRef<Promise<boolean> | null>(null);

  const lock = useCallback(() => {
    generation.current += 1;
    clearCache();
    disableOfflineReportMode();
    setSession(null);
    setSignedOut(true);
    setSignOutConfirmed(isSignOutConfirmed());
    setLoading(false);
    setReconnecting(false);
    setError(null);
  }, []);

  const refresh = useCallback(async (resume = false) => {
    if (isExplicitlySignedOut()) { lock(); return; }
    const current = ++generation.current;
    const stale = () => current !== generation.current || isExplicitlySignedOut();
    setSignedOut(false);
    setLoading(true);
    setError(null);
    setReconnecting(false);
    let devSessionAttempted = false;
    const startedAt = Date.now();
    for (let attempt = 1; attempt <= MAX_PROBE_ATTEMPTS; attempt += 1) {
      try {
        const next = await api.getAuthMe();
        if (stale()) return;
        setSession(next);
        setError(null);
        setReconnecting(false);
        setStarting(false);
        setLoading(false);
        return;
      } catch (nextError) {
        if (stale()) return;
        const startingRetryMs = apiStartingRetryMs(nextError);
        if (startingRetryMs != null && Date.now() - startedAt < STARTING_MAX_WAIT_MS) {
          // A booting API is expected on cold start: poll at the proxy's pace without spending probe attempts.
          setStarting(true);
          await delay(startingRetryMs);
          if (stale()) return;
          attempt -= 1;
          continue;
        }
        setStarting(false);
        if (nextError instanceof ApiAuthError && !devSessionAttempted) {
          devSessionAttempted = true;
          const exchange = await tryLoopbackDevSession(resume);
          if (stale()) return;
          if (exchange === "signed_out") {
            setExplicitlySignedOut(true);
            lock();
            return;
          }
          if (exchange) continue;
        }
        if (isRetryableProbeError(nextError) && attempt < MAX_PROBE_ATTEMPTS) {
          // Silent recovery: keep the gate in its loading/reconnecting state
          // rather than flashing the fatal screen for a single aborted fetch.
          setReconnecting(true);
          await delay(PROBE_RETRY_BASE_MS * attempt);
          if (stale()) return;
          continue;
        }
        setSession(null);
        setError(startingRetryMs != null
          ? `The control plane API did not finish starting within ${STARTING_MAX_WAIT_MS / 1000}s (503 Service Unavailable).`
          : userFacingApiErrorMessage(nextError, "Failed to load auth session"));
        setReconnecting(false);
        setLoading(false);
        return;
      }
    }
  }, [lock]);

  const signOut = useCallback((): Promise<boolean> => {
    if (signOutPending.current) return signOutPending.current;
    setExplicitlySignedOut(true);
    lock();
    setSignOutError(null);
    const request = api.deleteAuthSession().then(() => {
      setExplicitlySignedOut(true, true);
      setSignOutConfirmed(true);
      return true;
    }, () => {
      setSignOutError("Sign-out could not be confirmed. This browser is locked; retry to revoke the server session.");
      return false;
    }).finally(() => { clearCache(); signOutPending.current = null; });
    signOutPending.current = request;
    return request;
  }, [lock]);

  const resumeSession = useCallback(async () => {
    if (signOutPending.current) await signOutPending.current;
    setExplicitlySignedOut(false);
    setSignOutError(null);
    await refresh(true);
  }, [refresh]);

  useEffect(() => {
    const handleIntent = () => { if (isExplicitlySignedOut()) lock(); };
    window.addEventListener("storage", handleIntent);
    window.addEventListener(SESSION_INTENT_EVENT, handleIntent);
    window.addEventListener("focus", handleIntent);
    void refresh();
    return () => {
      generation.current += 1;
      window.removeEventListener("storage", handleIntent);
      window.removeEventListener(SESSION_INTENT_EVENT, handleIntent);
      window.removeEventListener("focus", handleIntent);
    };
  }, [lock, refresh]);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      signedOut,
      signOutConfirmed,
      signOutError,
      signOut,
      resumeSession,
      loading,
      error,
      reconnecting,
      starting,
      refresh,
      hasCapability: (capability: string) => Boolean(session?.role_summary?.capabilities.includes(capability)),
    }),
    [error, loading, reconnecting, starting, refresh, session, signedOut, signOutConfirmed, signOutError, signOut, resumeSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthState(): AuthContextValue {
  return useContext(AuthContext);
}
