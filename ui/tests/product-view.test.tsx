import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProductViewPicker } from "@/components/product-view-picker";
import { PRODUCT_VIEW_KEY, setProductView, useProductView } from "@/lib/product-view";

function Observer() { return <output aria-label="Observed view">{useProductView()}</output>; }

beforeEach(() => { setProductView("personal"); window.localStorage.removeItem(PRODUCT_VIEW_KEY); });
afterEach(() => { vi.restoreAllMocks(); setProductView("personal"); });

describe("product view preference", () => {
  it("defaults to Personal without inferring an audience from deployment evidence", () => {
    render(<ProductViewPicker />);
    expect(screen.getByRole("combobox", { name: "Product view" })).toHaveValue("personal");
    expect(screen.getByText(/Access and evidence scope stay the same/)).toBeVisible();
  });

  it("updates every subscriber and persists across remounts without an API write", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { unmount } = render(<><ProductViewPicker /><Observer /></>);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "team" } });
    expect(screen.getByLabelText("Observed view")).toHaveTextContent("team");
    expect(window.localStorage.getItem(PRODUCT_VIEW_KEY)).toBe("team");
    unmount();
    render(<ProductViewPicker />);
    expect(screen.getByRole("combobox")).toHaveValue("team");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("accepts cross-tab changes and resets unknown or cleared preferences safely", () => {
    render(<ProductViewPicker />);
    for (const [stored, expected] of [["organization", "organization"], ["administrator", "personal"]]) {
      act(() => {
        window.localStorage.setItem(PRODUCT_VIEW_KEY, stored!);
        const storageEvent = new Event("storage");
        Object.defineProperty(storageEvent, "key", { value: PRODUCT_VIEW_KEY });
        window.dispatchEvent(storageEvent);
      });
      expect(screen.getByRole("combobox")).toHaveValue(expected);
    }
    act(() => { setProductView("team"); });
    act(() => {
      window.localStorage.clear();
      const storageEvent = new Event("storage");
      Object.defineProperty(storageEvent, "key", { value: null });
      window.dispatchEvent(storageEvent);
    });
    expect(screen.getByRole("combobox")).toHaveValue("personal");
  });

  it("keeps selection usable when storage writes are denied", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("storage denied"); });
    render(<><ProductViewPicker /><Observer /></>);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "organization" } });
    expect(screen.getByLabelText("Observed view")).toHaveTextContent("organization");
  });
});
