import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useWheelZoomGate, WheelZoomHint, wheelZoomHintText } from "@/hooks/use-wheel-zoom-gate";

function Canvas() {
  const gate = useWheelZoomGate();
  return (
    <div data-testid="canvas" data-armed={gate.armed} {...gate.handlers}>
      <WheelZoomHint visible={gate.hintVisible} />
    </div>
  );
}

describe("useWheelZoomGate", () => {
  it("starts disarmed so a plain wheel scrolls the page, and shows the hint once", () => {
    vi.useFakeTimers();
    render(<Canvas />);
    const canvas = screen.getByTestId("canvas");
    expect(canvas).toHaveAttribute("data-armed", "false");
    expect(screen.queryByRole("status")).toBeNull();
    fireEvent.wheel(canvas, { deltaY: 120 });
    expect(canvas).toHaveAttribute("data-armed", "false");
    expect(screen.getByRole("status")).toHaveTextContent(wheelZoomHintText());
    act(() => { vi.advanceTimersByTime(2_500); });
    expect(screen.queryByRole("status")).toBeNull();
    fireEvent.wheel(canvas, { deltaY: 120 });
    expect(screen.queryByRole("status")).toBeNull();
    vi.useRealTimers();
  });

  it("arms while Ctrl or Meta is held and disarms on release", () => {
    render(<Canvas />);
    const canvas = screen.getByTestId("canvas");
    fireEvent.keyDown(window, { key: "Control" });
    expect(canvas).toHaveAttribute("data-armed", "true");
    fireEvent.keyUp(window, { key: "Control" });
    expect(canvas).toHaveAttribute("data-armed", "false");
    fireEvent.keyDown(window, { key: "Meta" });
    expect(canvas).toHaveAttribute("data-armed", "true");
    fireEvent.blur(window);
    expect(canvas).toHaveAttribute("data-armed", "false");
  });

  it("arms after a pointer press on the canvas until the pointer leaves it", () => {
    render(<Canvas />);
    const canvas = screen.getByTestId("canvas");
    fireEvent.pointerDown(canvas);
    expect(canvas).toHaveAttribute("data-armed", "true");
    fireEvent.wheel(canvas, { deltaY: 120 });
    expect(screen.queryByRole("status")).toBeNull();
    fireEvent.pointerLeave(canvas);
    expect(canvas).toHaveAttribute("data-armed", "false");
  });

  it("names the platform modifier in the hint", () => {
    expect(wheelZoomHintText("MacIntel")).toBe("Use ⌘ + scroll to zoom, or click the graph first");
    expect(wheelZoomHintText("Win32")).toBe("Use Ctrl + scroll to zoom, or click the graph first");
  });

  it("exposes a stable armed flag for renderers", () => {
    const { result } = renderHook(() => useWheelZoomGate());
    expect(result.current.armed).toBe(false);
    expect(typeof result.current.handlers.onWheel).toBe("function");
  });
});
