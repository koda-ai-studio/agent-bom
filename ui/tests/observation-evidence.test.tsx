import { render, screen, fireEvent } from "@testing-library/react";
import { expect, it } from "vitest";
import { ObservationEvidence } from "@/components/lineage-detail/observation-evidence";

it("shows current values, missing time, source and conflict without inventing certainty", () => {
  render(<ObservationEvidence attributes={{ internet_exposed: null, public_access: false, attribute_observations: {
    internet_exposed: { observed_at: "invalid-date", sources: ["cloud inventory"], conflicted: true },
    public_access: { observed_at: "2026-11-25T12:00:00Z", sources: [], conflicted: false },
  } }} />);
  expect(screen.getByText("Unknown value")).toBeInTheDocument();
  expect(screen.getByText("Unknown time")).toBeInTheDocument();
  expect(screen.getByText("Conflicting observations")).toBeInTheDocument();
  expect(screen.getByText("cloud inventory")).toBeInTheDocument();
  expect(screen.getByText("False")).toBeInTheDocument();
  expect(screen.getByText("Unknown source")).toBeInTheDocument();
});
it("paginates observations instead of silently dropping records after ten", () => {
  const attributes: Record<string, unknown> = Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`field_${i.toString().padStart(2, "0")}`, i]));
  attributes.attribute_observations = Object.fromEntries(Object.keys(attributes).map(key => [key, { sources: [] }]));
  render(<ObservationEvidence attributes={attributes} />);
  expect(screen.queryByText("Field 10")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next observations" }));
  expect(screen.getByText("Field 10")).toBeInTheDocument();
  expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
});
