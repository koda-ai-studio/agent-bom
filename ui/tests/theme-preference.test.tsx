import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ThemePreferenceControl } from "@/components/theme-toggle";
import { readThemeMode, subscribeThemeMode } from "@/lib/theme-mode";

afterEach(() => { localStorage.clear(); delete document.documentElement.dataset.themePreference; delete document.documentElement.dataset.themeStorageUnavailable; vi.restoreAllMocks(); });
it("follows system changes only while System is selected", () => {
  let dark = false;
  const listeners = new Set<() => void>();
  vi.stubGlobal("matchMedia", () => ({ get matches() { return dark; }, addEventListener: (_: string, fn: () => void) => listeners.add(fn), removeEventListener: (_: string, fn: () => void) => listeners.delete(fn) }));
  render(<ThemePreferenceControl />);
  fireEvent.click(screen.getByRole("button", { name: "System" }));
  expect(readThemeMode()).toBe("light");
  act(() => { dark = true; listeners.forEach(fn => fn()); });
  expect(document.documentElement.dataset.theme).toBe("dark");
  fireEvent.click(screen.getByRole("button", { name: "Light" }));
  act(() => { listeners.forEach(fn => fn()); });
  expect(readThemeMode()).toBe("light");
  expect(localStorage.getItem("agent-bom-theme")).toBe("light");
  vi.unstubAllGlobals();
});
it("updates rendered theme after another tab changes preference", () => {
  const unsubscribe = subscribeThemeMode(() => {});
  localStorage.setItem("agent-bom-theme", "light");
  window.dispatchEvent(new StorageEvent("storage", { key: "agent-bom-theme", newValue: "light" }));
  expect(document.documentElement.dataset.theme).toBe("light");
  unsubscribe();
});
it("applies the selected theme when storage reads succeed but writes fail", () => {
  localStorage.setItem("agent-bom-theme", "dark");
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Quota exceeded"); });
  render(<ThemePreferenceControl />);
  fireEvent.click(screen.getByRole("button", { name: "Light" }));
  expect(readThemeMode()).toBe("light");
  expect(document.documentElement.dataset.theme).toBe("light");
});
