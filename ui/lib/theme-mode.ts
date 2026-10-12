import { useSyncExternalStore } from "react";

const THEME_STORAGE_KEY = "agent-bom-theme";
export type ThemeMode = "dark" | "light";
export type ThemePreference = ThemeMode | "system";

export function readThemePreference(): ThemePreference {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = document.documentElement.dataset.themeStorageUnavailable === "true"
      ? null : window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
  } catch { /* Use the active preference when storage is unavailable. */ }
  const active = document.documentElement.dataset.themePreference;
  return active === "system" || active === "light" || active === "dark" ? active : document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function readThemeMode(): ThemeMode {
  const preference = readThemePreference();
  if (preference !== "system") return preference;
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function syncRoot(): void {
  document.documentElement.dataset.themePreference = readThemePreference();
  const mode = readThemeMode();
  document.documentElement.dataset.theme = mode;
  document.documentElement.style.colorScheme = mode;
}

export function applyTheme(preference: ThemePreference): void {
  document.documentElement.dataset.themePreference = preference;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    delete document.documentElement.dataset.themeStorageUnavailable;
  } catch { document.documentElement.dataset.themeStorageUnavailable = "true"; }
  syncRoot();
  window.dispatchEvent(new Event("agent-bom-theme-change"));
}

export function subscribeThemeMode(onChange: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handleChange = () => { syncRoot(); onChange(); };
  const media = window.matchMedia?.("(prefers-color-scheme: dark)");
  window.addEventListener("storage", handleChange);
  window.addEventListener("agent-bom-theme-change", handleChange);
  media?.addEventListener("change", handleChange);
  return () => {
    window.removeEventListener("storage", handleChange);
    window.removeEventListener("agent-bom-theme-change", handleChange);
    media?.removeEventListener("change", handleChange);
  };
}

export function getThemeModeServerSnapshot(): ThemeMode { return "dark"; }
export function useThemeMode(): ThemeMode {
  return useSyncExternalStore(subscribeThemeMode, readThemeMode, getThemeModeServerSnapshot);
}
