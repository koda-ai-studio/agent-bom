import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { automaticFlowLabel, GraphFlowControl } from "@/components/graph-flow-control";
import { GraphPathList } from "@/components/graph-path-list";
import { selectionHiddenByCollapse } from "@/hooks/use-investigation-flow-view";
import { byLabel, k8sFlowGraph } from "./k8s-projection-fixture";
import { investigationFlow } from "@/lib/graph-investigation-flow";

const allAvailable = { exposure: true, identity: true, vulnerability: true, inventory: true };
const select = () => screen.getByRole<HTMLSelectElement>("combobox", { name: "Investigation flow" });

describe("GraphFlowControl", () => {
  it("disables a flow with nothing to show and says what is missing", () => {
    render(<GraphFlowControl value="auto" automaticLabel="Automatic · Exposure" available={{ ...allAvailable, vulnerability: false }} onChange={vi.fn()} />);
    const option = screen.getByRole<HTMLOptionElement>("option", { name: "Vulnerability (no findings)" });
    expect(option.disabled).toBe(true);
    expect(screen.getByRole<HTMLOptionElement>("option", { name: "Exposure" }).disabled).toBe(false);
  });

  it("disables the whole control and shows the reason on screen when no flow can apply", () => {
    render(<GraphFlowControl value="auto" automaticLabel="Automatic · current layout" available={allAvailable} disabledReason="Flows are paused while you edit the layout." onChange={vi.fn()} />);
    expect(select().disabled).toBe(true);
    expect(screen.getByRole("status").textContent).toBe("Flows are paused while you edit the layout.");
  });

  it("explains a selected flow that cannot apply to the current view", () => {
    render(<GraphFlowControl value="exposure" automaticLabel="Automatic · current layout" available={allAvailable} note="No findings in this view." onChange={vi.fn()} />);
    expect(screen.getByRole("status").textContent).toBe("No findings in this view.");
    expect(select().disabled).toBe(false);
  });

  it("fits Automatic on a phone's narrow row and keeps the full label as the tooltip", () => {
    render(<GraphFlowControl value="auto" automaticLabel="Automatic · connection preview" available={allAvailable} compact onChange={() => {}} />);
    expect(screen.getByRole<HTMLOptionElement>("option", { name: "Automatic" }).selected).toBe(true);
    expect(select().title).toBe("Automatic · connection preview");
  });

  it("reports the selection", () => {
    const onChange = vi.fn();
    render(<GraphFlowControl value="auto" automaticLabel="Automatic · Exposure" available={allAvailable} onChange={onChange} />);
    fireEvent.change(select(), { target: { value: "identity" } });
    expect(onChange).toHaveBeenCalledWith("identity");
  });

  it("labels Automatic with what is on screen, never a flow that did not apply", () => {
    expect(automaticFlowLabel({ applied: true, scenario: "exposure", preview: false })).toBe("Automatic · Exposure");
    expect(automaticFlowLabel({ applied: false, scenario: "vulnerability", preview: false })).toBe("Automatic · current layout");
    expect(automaticFlowLabel({ applied: false, scenario: "exposure", preview: true })).toBe("Automatic · connection preview");
    expect(automaticFlowLabel({ applied: true, scenario: "connections", preview: false })).toBe("Automatic · Connections");
  });
});

describe("collapsing findings while one is selected", () => {
  it("reads ownership from the flow's nodes, where it is set, not the input nodes", () => {
    const { nodes, edges } = k8sFlowGraph("withFindings");
    const finding = byLabel(nodes, "CVE-2021-3711").id;
    expect(selectionHiddenByCollapse(nodes, finding)).toBe(false);
    expect(selectionHiddenByCollapse(investigationFlow(nodes, edges, "exposure").nodes, finding)).toBe(true);
    expect(selectionHiddenByCollapse(investigationFlow(nodes, edges, "exposure").nodes, null)).toBe(false);
  });
});

describe("the phone's path list", () => {
  it("does not call a ClusterIP route exposure, and names an unmounted token", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    render(<GraphPathList nodes={nodes} edges={edges} onSelect={vi.fn()} />);
    expect(screen.getAllByText("Routes in cluster to").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Assumes · token not mounted").length).toBeGreaterThan(0);
  });
});
