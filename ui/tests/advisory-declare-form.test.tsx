import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdvisoryDeclareForm } from "@/components/advisories/advisory-declare-form";
import { OperatorAdvisoryList } from "@/components/advisories/operator-advisory-list";
import { ApiValidationError } from "@/lib/api-errors";
import { operatorAdvisoryApi } from "@/lib/operator-advisories";

vi.mock("@/lib/operator-advisories", async () => {
  const actual = await vi.importActual<typeof import("@/lib/operator-advisories")>("@/lib/operator-advisories");
  return { ...actual, operatorAdvisoryApi: { list: vi.fn(), declare: vi.fn(), retire: vi.fn() } };
});

const declare = vi.mocked(operatorAdvisoryApi.declare);
const list = vi.mocked(operatorAdvisoryApi.list);
const retire = vi.mocked(operatorAdvisoryApi.retire);

beforeEach(() => {
  declare.mockReset();
  list.mockReset();
  retire.mockReset();
});

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function fillValid() {
  fill("Advisory ID", "CVE-2026-109618");
  fill("Aliases", "CVE-2026-109619");
  fill("Summary", "php2shell: unauthenticated remote code execution in PHP core");
  fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
  fill("References", "https://www.php.net/ChangeLog-8.php");
  fireEvent.click(screen.getByRole("radio", { name: "CPE product" }));
  fill("CPE product (vendor:product)", "php:php");
  fill("Introduced", "8.3.0");
  fill("Fixed", "8.3.36");
}

describe("emergency advisory form", () => {
  it("validates on the client like the server model and does not post an invalid advisory", async () => {
    render(<AdvisoryDeclareForm />);
    fill("Advisory ID", "php2shell");
    fill("References", "http://insecure.example/advisory");
    fireEvent.click(screen.getByRole("radio", { name: "CPE product" }));
    fill("CPE product (vendor:product)", "php");
    fireEvent.click(screen.getByRole("button", { name: "Declare advisory" }));

    expect(await screen.findByText(/Use an id like CVE-2026-12345/)).toBeInTheDocument();
    expect(screen.getByLabelText("Advisory ID")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("Summary is required")).toBeInTheDocument();
    expect(screen.getByText("References must be https:// URLs")).toBeInTheDocument();
    expect(screen.getByText("cpe_product must be vendor:product, e.g. php:php")).toBeInTheDocument();
    expect(screen.getByText("Add at least one version range or an exact affected version")).toBeInTheDocument();
    expect(declare).not.toHaveBeenCalled();
  });

  it("posts exactly the OperatorAdvisory body with no extra fields", async () => {
    declare.mockResolvedValue({ id: "CVE-2026-109618" } as never);
    const onDeclared = vi.fn();
    render(<AdvisoryDeclareForm onDeclared={onDeclared} />);
    fillValid();
    fireEvent.click(screen.getByRole("button", { name: "Declare advisory" }));

    await waitFor(() => expect(declare).toHaveBeenCalledTimes(1));
    expect(declare.mock.calls[0]![0]).toEqual({
      id: "CVE-2026-109618",
      aliases: ["CVE-2026-109619"],
      summary: "php2shell: unauthenticated remote code execution in PHP core",
      severity: "critical",
      references: ["https://www.php.net/ChangeLog-8.php"],
      affected: [{ cpe_product: "php:php", ranges: [{ introduced: "8.3.0", fixed: "8.3.36" }], versions: [] }],
    });
    expect(await screen.findByText(/Declared CVE-2026-109618/)).toBeInTheDocument();
    expect(onDeclared).toHaveBeenCalledWith("CVE-2026-109618");
  });

  it("shows a 422 detail list next to the right field and as a clear summary", async () => {
    declare.mockRejectedValue(new ApiValidationError("introduced must precede fixed", {
      status: 422,
      statusText: "Unprocessable Entity",
      url: "",
      method: "POST",
      body: {
        error: { code: "VALIDATION_ERROR", message: "Value error, introduced must precede fixed" },
        detail: [
          { loc: ["body", "affected", 0], msg: "Value error, introduced must precede fixed", type: "value_error" },
          { loc: ["body", "summary"], msg: "String should have at most 1000 characters", type: "string_too_long" },
          { loc: ["body", "severity_score"], msg: "Extra inputs are not permitted", type: "extra_forbidden" },
        ],
      },
    }));
    render(<AdvisoryDeclareForm />);
    fillValid();
    fireEvent.click(screen.getByRole("button", { name: "Declare advisory" }));

    const summary = await screen.findByRole("alert", { name: "The server rejected this advisory" });
    const items = within(summary).getAllByRole("listitem").map(item => item.textContent);
    expect(items).toEqual([
      "Affected product 1: introduced must precede fixed",
      "Summary: String should have at most 1000 characters",
      "Severity score: Extra inputs are not permitted",
    ]);
    const product = screen.getByRole("group", { name: "Affected product 1" });
    expect(within(product).getByText("introduced must precede fixed")).toBeInTheDocument();
    expect(screen.getByLabelText("Summary")).toHaveAttribute("aria-invalid", "true");
  });
});

describe("operator advisory list", () => {
  it("lists declared advisories, links to affected assets, and retires after confirmation", async () => {
    list.mockResolvedValue({
      advisories: [{ id: "CVE-2026-109618", aliases: ["CVE-2026-109619"], summary: "php2shell", severity: "critical", references: [], affected: [{ cpe_product: "php:php", ranges: [], versions: [] }], updated_at: "2026-10-23T09:00:00+00:00" }],
      provenance: "operator_advisory",
      rematch: { last_run: "2026-10-24T01:00:00+00:00" },
    });
    retire.mockResolvedValue(undefined);
    render(<OperatorAdvisoryList refreshKey={0} />);

    const row = await screen.findByRole("listitem", { name: "CVE-2026-109618" });
    expect(within(row).getByText("critical")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "Affected assets for CVE-2026-109618" })).toHaveAttribute("href", "/advisories?id=CVE-2026-109618");
    fireEvent.click(within(row).getByRole("button", { name: "Retire CVE-2026-109618" }));
    expect(retire).not.toHaveBeenCalled();
    fireEvent.click(within(row).getByRole("button", { name: "Confirm retire CVE-2026-109618" }));
    await waitFor(() => expect(retire).toHaveBeenCalledWith("CVE-2026-109618"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
  });

  it("says plainly when nothing has been declared", async () => {
    list.mockResolvedValue({ advisories: [], provenance: "operator_advisory", rematch: null });
    render(<OperatorAdvisoryList refreshKey={0} />);
    expect(await screen.findByText("No emergency advisories declared")).toBeInTheDocument();
  });
});
