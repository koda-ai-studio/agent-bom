import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installGraphPaintMeasurement } from "../e2e/helpers/graph-paint-measurement";

const target = window as Window & { graphPaintReadyAt?: number };
let callbacks: FrameRequestCallback[];
let now: number;
const frame = (time: number) => { now = time; callbacks.shift()!(time); };
beforeEach(() => {
  delete target.graphPaintReadyAt;
  callbacks = []; now = 0;
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callbacks.push(callback); return callbacks.length; });
  vi.spyOn(performance, "now").mockImplementation(() => now);
  document.body.innerHTML = `<div data-graph-adaptive-frame data-graph-camera-settled="false"><div class="react-flow">
    ${Array.from({ length: 5 }, (_, i) => `<div class="react-flow__node ${i < 3 ? "react-flow__node-serverNode" : ""}"><span class="graph-entity-glyph">Asset</span></div>`).join("")}
    ${'<svg class="react-flow__edge"></svg>'.repeat(4)}
  </div></div>`;
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
    return this.matches(".react-flow") ? new DOMRect(0, 0, 100, 100) : new DOMRect(20, 40, 20, 20);
  });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); document.body.innerHTML = ""; });

describe("browser graph first useful paint clock", () => {
  it("requires settled camera and two further ready frames, excluding later driver delay", () => {
    installGraphPaintMeasurement(); frame(100);
    expect(target.graphPaintReadyAt).toBeUndefined();
    document.querySelector<HTMLElement>("[data-graph-adaptive-frame]")!.dataset.graphCameraSettled = "true";
    frame(200); frame(216);
    expect(target.graphPaintReadyAt).toBeUndefined();
    frame(232); now = 900;
    expect(target.graphPaintReadyAt).toBe(232);
  });
  it.each(["hidden", "clipped", "missing-edge", "missing-node", "relationship-label", "off-center"])("rejects %s graph and restarts readiness", problem => {
    document.querySelector<HTMLElement>("[data-graph-adaptive-frame]")!.dataset.graphCameraSettled = "true";
    installGraphPaintMeasurement(); frame(100);
    const node = document.querySelector<HTMLElement>(".react-flow__node")!;
    if (problem === "hidden") node.style.visibility = "hidden";
    if (problem === "clipped") node.getBoundingClientRect = () => new DOMRect(-1, 40, 20, 20);
    if (problem === "off-center") for (const item of document.querySelectorAll(".react-flow__node")) item.getBoundingClientRect = () => new DOMRect(20, 0, 20, 20);
    if (problem === "missing-edge") document.querySelector(".react-flow__edge")!.remove();
    if (problem === "missing-node") node.remove();
    if (problem === "relationship-label") node.classList.add("graph-relationship-label");
    frame(116); frame(132); frame(148);
    expect(target.graphPaintReadyAt).toBeUndefined();
  });
});
