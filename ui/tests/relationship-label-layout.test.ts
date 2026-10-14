import { afterEach, expect, it, vi } from "vitest";
import { scheduleRelationshipLabelLayout } from "@/lib/relationship-label-layout";

function fixture() {
  document.body.innerHTML = '<div class="react-flow"><div class="react-flow__node"></div></div>';
  const canvas = document.querySelector<HTMLElement>(".react-flow")!;
  const node = canvas.querySelector<HTMLElement>(".react-flow__node")!;
  node.getBoundingClientRect = () => new DOMRect(450, 80, 100, 40);
  for (const id of ["a", "b"]) {
    const edge = document.createElementNS("http://www.w3.org/2000/svg", "g");
    edge.setAttribute("class", "react-flow__edge");
    edge.setAttribute("data-id", id);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("class", "react-flow__edge-path");
    Object.assign(path, { getTotalLength: () => 1000, getPointAtLength: (x: number) => ({ x, y: 100 }),
      getScreenCTM: () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }) });
    edge.append(path);
    canvas.append(edge);
    const label = document.createElement("div");
    label.className = "graph-relationship-label";
    Object.assign(label.dataset, { edgeId: id, labelX: "500", labelY: "100" });
    label.textContent = "Recorded relationship";
    label.getBoundingClientRect = () => new DOMRect(450, 90, 100, 20);
    canvas.append(label);
  }
  return [...canvas.querySelectorAll<HTMLElement>(".graph-relationship-label")];
}

afterEach(() => { document.body.innerHTML = ""; vi.unstubAllGlobals(); });

it("batches the canvas and moves captions along their paths clear of nodes and each other", () => {
  const callbacks: FrameRequestCallback[] = [];
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => callbacks.push(callback));
  vi.stubGlobal("CSS", { escape: (value: string) => value });
  const labels = fixture();
  labels.forEach(scheduleRelationshipLabelLayout);
  expect(callbacks).toHaveLength(1);
  callbacks[0]!(0);
  const positions = labels.map(label => Number(label.style.transform.match(/translate\((\d+)px, 100px\)$/)?.[1]));
  expect(positions[0]).toBeLessThan(396);
  expect(positions[1]).toBeGreaterThan(604);
  expect(positions.every(x => Math.abs(x - 500) < 150)).toBe(true);
  expect(labels.every(label => label.textContent === "Recorded relationship")).toBe(true);
});

it("keeps labels present when no clear path position exists", () => {
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 1; });
  vi.stubGlobal("CSS", { escape: (value: string) => value });
  const labels = fixture();
  document.querySelector<HTMLElement>(".react-flow__node")!.getBoundingClientRect = () => new DOMRect(-1000, -1000, 4000, 4000);
  scheduleRelationshipLabelLayout(labels[0]!);
  expect(labels[0]!.style.transform).toContain("translate(500px, 100px)");
  expect(labels[0]!.textContent).toBe("Recorded relationship");
});

it("moves a caption off a crossing relationship line, not only off nodes and captions", () => {
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 1; });
  vi.stubGlobal("CSS", { escape: (value: string) => value });
  const labels = fixture();
  document.querySelector<HTMLElement>(".react-flow__node")!.getBoundingClientRect = () => new DOMRect(-5000, -5000, 10, 10);
  const vertical = document.querySelector('.react-flow__edge[data-id="b"] path')!;
  Object.assign(vertical, { getPointAtLength: (at: number) => ({ x: 500, y: at / 5 }) });
  scheduleRelationshipLabelLayout(labels[0]!);
  const [ax, ay] = labels[0]!.style.transform.match(/translate\((-?[\d.]+)px, (-?[\d.]+)px\)$/)!.slice(1).map(Number);
  const [bx, by] = labels[1]!.style.transform.match(/translate\((-?[\d.]+)px, (-?[\d.]+)px\)$/)!.slice(1).map(Number);
  expect(ay).toBe(100);
  expect(Math.abs(ax! - 500)).toBeGreaterThan(50);
  expect(bx).toBe(500);
  expect(Math.abs(by! - 100)).toBeGreaterThan(10);
});

it("moves a caption just off its line when every point on a short link lies inside the endpoint cards", () => {
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 1; });
  vi.stubGlobal("CSS", { escape: (value: string) => value });
  const labels = fixture();
  document.querySelector<HTMLElement>(".react-flow__node")!.getBoundingClientRect = () => new DOMRect(-1000, 60, 4000, 80);
  labels[1]!.remove();
  labels[0]!.getBoundingClientRect = () => new DOMRect(450, 78, 100, 44);
  scheduleRelationshipLabelLayout(labels[0]!);
  const [x, y] = labels[0]!.style.transform.match(/translate\((-?[\d.]+)px, (-?[\d.]+)px\)$/)!.slice(1).map(Number);
  expect(y! + 22 <= 58 || y! - 22 >= 142).toBe(true);
  expect(Math.abs(x! - 500)).toBeLessThan(150);
});

it("never nudges a caption outside the visible canvas", () => {
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 1; });
  vi.stubGlobal("CSS", { escape: (value: string) => value });
  const labels = fixture();
  document.querySelector<HTMLElement>(".react-flow")!.getBoundingClientRect = () => new DOMRect(0, 40, 1000, 400);
  document.querySelector<HTMLElement>(".react-flow__node")!.getBoundingClientRect = () => new DOMRect(-1000, 60, 4000, 80);
  labels[1]!.remove();
  labels[0]!.getBoundingClientRect = () => new DOMRect(450, 78, 100, 44);
  scheduleRelationshipLabelLayout(labels[0]!);
  const y = Number(labels[0]!.style.transform.match(/translate\((-?[\d.]+)px, (-?[\d.]+)px\)$/)![2]);
  expect(y - 22).toBeGreaterThanOrEqual(40);
  expect(y - 22).toBeGreaterThanOrEqual(142);
});
