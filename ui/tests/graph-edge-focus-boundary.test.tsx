import { act, fireEvent, render, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphEdgeFocusBoundary } from "@/components/graph-edge-focus-boundary";

it("restores the same edge after measurement replacement without stealing deliberate focus", async () => {
  const view = (revision: number) => <><button>Outside</button><GraphEdgeFocusBoundary><svg key={revision}><g className="react-flow__edge" data-id="recorded-edge" tabIndex={0} /></svg></GraphEdgeFocusBoundary></>;
  const { container, rerender, getByText } = render(view(0));
  const edge = () => container.querySelector<SVGGElement>(".react-flow__edge")!;
  const original = edge(); act(() => original.focus());
  rerender(view(1));
  expect(original.isConnected).toBe(false);
  await waitFor(() => expect(edge()).toHaveFocus());
  act(() => getByText("Outside").focus());
  rerender(view(2));
  await waitFor(() => expect(getByText("Outside")).toHaveFocus());
  act(() => edge().focus());
  fireEvent.pointerDown(document.body);
  rerender(view(3));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(edge()).not.toHaveFocus();
});
