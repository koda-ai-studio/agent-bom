import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const flow = vi.hoisted(() => ({
  fitView: vi.fn().mockResolvedValue(true),
  setViewport: vi.fn().mockResolvedValue(true),
  width: 1440,
  height: 520,
}));
vi.mock("@xyflow/react", () => ({
  Controls: ({ children, showFitView }: { children?: React.ReactNode; showFitView?: boolean }) => (
    <div data-testid="controls">
      {showFitView !== false && <button type="button" aria-label="default fit view" onClick={() => void flow.fitView()} />}
      {children}
    </div>
  ),
  ControlButton: ({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) => <button type="button" {...props}>{children}</button>,
  Panel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  useReactFlow: () => flow,
  useStore: (select: (state: unknown) => unknown) => select({ width: flow.width, height: flow.height }),
}));

import { GraphCamera } from "@/components/attack-path-graph";
import { LegibleFitControls } from "@/components/graph-legible-controls";
import { LEGIBLE_CARD_TEXT_PX, legibleFit, legibleFitZoom, legibleZoomForText } from "@/lib/graph-adaptive-frame";
import { PATH_DESKTOP_MIN_ZOOM, NARROW_MIN_ZOOM } from "@/lib/attack-path-graph-layout";

afterEach(() => { cleanup(); vi.clearAllMocks(); flow.width = 1440; flow.height = 520; });

it("floors a fit at the zoom where card text stays legible and keeps a stricter caller floor", () => {
  expect(LEGIBLE_CARD_TEXT_PX).toBe(11);
  expect(legibleZoomForText(14) * 14).toBeCloseTo(11);
  expect(legibleFit({ padding: 0.2, maxZoom: 1.25 }, 0.4)).toEqual({ padding: 0.2, maxZoom: 1.25, minZoom: 0.4 });
  expect(legibleFit({ minZoom: 0.05, maxZoom: 1.25 }, legibleFitZoom(1440)).minZoom).toBe(0.4);
  expect(legibleFit({ minZoom: 0.05 }, legibleFitZoom(390)).minZoom).toBe(0.7);
  expect(legibleFit({ minZoom: 1.1, maxZoom: 1.1 }, 0.4)).toEqual({ minZoom: 1.1, maxZoom: 1.1 });
  // A ceiling under the floor is raised to it: the camera never has to choose an illegible zoom.
  expect(legibleFit({ maxZoom: 0.3 }, 0.4)).toEqual({ maxZoom: 0.4, minZoom: 0.4 });
});

it("the canvas fit button never fits below the legible floor", () => {
  render(<LegibleFitControls floor={0.4} fitOptions={{ padding: 0.25, minZoom: 0.05, maxZoom: 1.25 }} />);
  expect(screen.queryByRole("button", { name: "default fit view" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Fit View" }));
  expect(flow.fitView).toHaveBeenCalledWith({ padding: 0.25, minZoom: 0.4, maxZoom: 1.25 });
});

it("the canvas fit button defers to the owner's fit when it has one", () => {
  const onFit = vi.fn();
  render(<LegibleFitControls floor={0.4} onFit={onFit} />);
  fireEvent.click(screen.getByRole("button", { name: "Fit View" }));
  expect(onFit).toHaveBeenCalledTimes(1);
  expect(flow.fitView).not.toHaveBeenCalled();
});

function wideLayout(columns: number) {
  const positions = new Map(Array.from({ length: columns }, (_, index) => [`n${index}`, { x: index * 320, y: (index % 3) * 180 }] as const));
  return { direction: "LR" as const, positions, width: columns * 320, height: 540, nodeWidth: 260, nodeHeight: 140 } as never;
}

for (const [label, width, floor] of [["desktop", 1440, PATH_DESKTOP_MIN_ZOOM], ["phone", 390, NARROW_MIN_ZOOM]] as const) {
  it(`Fit all on the path and architecture canvases keeps 15px names at 11px or more on a ${label}`, () => {
    flow.width = width;
    const layout = wideLayout(15);
    const manual = { current: null as string | null };
    render(<GraphCamera layout={layout} spineIds={["n0", "n1", "n2"]} nodesKey="k" floor={floor} manual={manual} />);
    fireEvent.click(screen.getByRole("button", { name: "fit view" }));
    const zooms = flow.setViewport.mock.calls.map(([view]) => (view as { zoom: number }).zoom);
    expect(zooms.length).toBeGreaterThanOrEqual(2);
    for (const zoom of zooms) expect(15 * zoom).toBeGreaterThanOrEqual(11);
    // Fit all cannot show these nodes legibly, so it never offers to.
    expect(screen.queryByRole("button", { name: "Fit all" })).toBeNull();
  });
}

it("every graph canvas draws its fit button through the legible controls", () => {
  const root = join(__dirname, "..", "components");
  const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter(file => file.endsWith(".tsx"));
  const offenders = files.filter(file => {
    const source = readFileSync(join(root, file), "utf8");
    return [...source.matchAll(/<Controls\b[^>]*>/g)].some(([tag]) => !/showFitView=\{false\}/.test(tag));
  });
  expect(offenders).toEqual([]);
});
