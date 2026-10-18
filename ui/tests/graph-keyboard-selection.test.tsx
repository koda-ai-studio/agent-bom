import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";

it.each(["Enter", " "])("opens a focused entity with %s", key => {
  const select = vi.fn();
  render(<div onKeyDownCapture={activateGraphNodeFromKeyboard}><div role="group" tabIndex={0} className="react-flow__node" onClick={select}>Finding</div></div>);
  fireEvent.keyDown(screen.getByRole("group"), { key });
  expect(select).toHaveBeenCalledOnce();
});
it("leaves nested buttons and unrelated keys to their own handlers", () => {
  const select = vi.fn();
  render(<div onKeyDownCapture={activateGraphNodeFromKeyboard}><div role="group" className="react-flow__node" onClick={select}><button>Expand</button></div></div>);
  fireEvent.keyDown(screen.getByRole("button"), { key: "Enter" });
  fireEvent.keyDown(screen.getByRole("group"), { key: "ArrowRight" });
  expect(select).not.toHaveBeenCalled();
});
