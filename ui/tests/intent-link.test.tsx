import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({ href, children, prefetch, ...rest }: { href: string; children: React.ReactNode; prefetch?: boolean | null }) => (
    <a href={href} data-prefetch={prefetch === null ? "auto" : String(prefetch)} {...rest}>{children}</a>
  ),
}));

import { IntentLink } from "@/components/navigation/intent-link";

describe("IntentLink", () => {
  it("does not prefetch its route on render", () => {
    render(<IntentLink href="/findings">Findings</IntentLink>);
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("data-prefetch", "false");
  });

  it.each([
    ["hover", (link: HTMLElement) => fireEvent.mouseEnter(link)],
    ["keyboard focus", (link: HTMLElement) => fireEvent.focus(link)],
    ["touch", (link: HTMLElement) => fireEvent.touchStart(link)],
  ])("restores default prefetching on %s", (_intent, act) => {
    render(<IntentLink href="/findings">Findings</IntentLink>);
    const link = screen.getByRole("link", { name: "Findings" });
    act(link);
    expect(link).toHaveAttribute("data-prefetch", "auto");
    expect(link).toHaveAttribute("href", "/findings");
  });

  it("keeps the caller's own intent handlers", () => {
    const onMouseEnter = vi.fn();
    const onFocus = vi.fn();
    render(<IntentLink href="/findings" onMouseEnter={onMouseEnter} onFocus={onFocus}>Findings</IntentLink>);
    const link = screen.getByRole("link", { name: "Findings" });
    fireEvent.mouseEnter(link);
    fireEvent.focus(link);
    expect(onMouseEnter).toHaveBeenCalledTimes(1);
    expect(onFocus).toHaveBeenCalledTimes(1);
  });
});
