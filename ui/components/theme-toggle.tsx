"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";

import {
  applyTheme,
  readThemePreference,
  type ThemePreference,
  getThemeModeServerSnapshot,
  readThemeMode,
  subscribeThemeMode,
  type ThemeMode,
} from "@/lib/theme-mode";

function subscribe(onChange: () => void) {
  return subscribeThemeMode(onChange);
}

function getServerSnapshot(): ThemeMode {
  return getThemeModeServerSnapshot();
}

export function ThemeToggle({ compact = false, className = "" }: { compact?: boolean; className?: string }) {
  const theme = useSyncExternalStore(subscribe, readThemeMode, getServerSnapshot);

  const nextTheme = theme === "dark" ? "light" : "dark";
  const label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <button
      type="button"
      onClick={() => {
        applyTheme(nextTheme);
      }}
      className={`inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-elevated)] ${compact ? "h-9 w-9 justify-center p-0" : "h-9 px-3 text-xs font-medium"} ${className}`}
      title={label}
      aria-label={label}
    >
      {theme === "dark" ? <Moon className="h-4 w-4 shrink-0" /> : <Sun className="h-4 w-4 shrink-0" />}
      {!compact && (
        <span className="truncate">
          {theme === "dark" ? "Dark theme" : "Light theme"}
        </span>
      )}
    </button>
  );
}


export function ThemePreferenceControl() {
  const preference = useSyncExternalStore(subscribeThemeMode, readThemePreference, (): ThemePreference => "dark");
  return <div role="group" aria-label="Appearance" className="flex flex-wrap gap-2">
    {(["light", "dark", "system"] as const).map(value => <button key={value} type="button" aria-pressed={preference === value}
      onClick={() => applyTheme(value)}
      className={`flex-1 rounded-lg border px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500 ${preference === value ? "border-emerald-500 bg-emerald-500/10 text-foreground" : "border-outline text-ink-secondary hover:bg-surface-muted"}`}>
      {value[0]!.toUpperCase() + value.slice(1)}
    </button>)}
  </div>;
}
