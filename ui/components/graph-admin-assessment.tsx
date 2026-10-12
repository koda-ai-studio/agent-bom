"use client";

export function AdminAssessment({ attributes }: { attributes: Record<string, unknown> }) {
  const status = attributes.admin_equivalence_status;
  if (typeof status !== "string") return null;
  const labels: Record<string, string> = { admin: "Admin", conditional_admin: "Conditional admin", not_admin: "Not admin", unknown: "Unknown" };
  return <div className="mt-2 text-sm"><p>Admin assessment: <strong>{labels[status] ?? "Unknown"}</strong></p>
    <p className="text-xs text-ink-secondary">{status === "conditional_admin" ? "Broad admin permissions are conditional. The required request context has not been verified." : status === "not_admin" ? "Collected policies do not establish admin permissions." : status === "admin" ? "Collected identity policies grant admin permissions within their recorded resource scope. Other authorization controls may still apply." : "Available evidence does not establish an admin verdict."}</p>
    {attributes.escalates_to_admin === true ? <p className="text-xs">Can assume an admin role.</p> : attributes.escalates_to_conditional_admin === true && <p className="text-xs">Can assume a conditional admin role. Its conditions have not been verified.</p>}
    {Array.isArray(attributes.admin_equivalence_resource_scopes) && attributes.admin_equivalence_resource_scopes.length > 0 && <p className="break-all text-xs">Scope: {attributes.admin_equivalence_resource_scopes.filter((scope): scope is string => typeof scope === "string").join(", ")}</p>}
  </div>;
}

