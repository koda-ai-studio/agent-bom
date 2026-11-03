import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphCountHint } from "@/components/graph-count-hint";

it("keeps count meaning off the canvas until hover or keyboard focus and dismisses with Escape", () => {
  render(<GraphCountHint text="2 linked findings · highest severity: high"><button>2</button></GraphCountHint>);
  expect(screen.queryByRole("tooltip")).toBeNull();
  fireEvent.focus(screen.getByRole("button"));
  expect(screen.getByRole("tooltip")).toHaveTextContent("2 linked findings · highest severity: high");
  expect(screen.getByRole("button")).toHaveAccessibleDescription("2 linked findings · highest severity: high");
  fireEvent.keyDown(screen.getByRole("button"), { key: "Escape" });
  expect(screen.queryByRole("tooltip")).toBeNull();
  expect(screen.getByRole("button")).not.toHaveAttribute("aria-describedby");
  fireEvent.mouseEnter(screen.getByRole("button").parentElement!);
  expect(screen.getByRole("tooltip")).toBeVisible();
  fireEvent.mouseLeave(screen.getByRole("button").parentElement!);
  expect(screen.queryByRole("tooltip")).toBeNull();
});
