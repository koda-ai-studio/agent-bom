import Link from "next/link";

import type { FindingControlGroup } from "@/lib/finding-controls";

const CHIP = "rounded border border-outline bg-surface px-2 py-0.5 font-mono text-[11px] text-ink-secondary";

/** A finding's mapped controls, one row per framework, each linked to its compliance control. */
export function FindingControlGroups({ groups }: { groups: FindingControlGroup[] }) {
  const count = groups.reduce((sum, group) => sum + group.controls.length, 0);
  if (count === 0) return null;
  return (
    <details>
      <summary className="cursor-pointer text-sm text-ink-secondary">
        View {count} mapped control{count === 1 ? "" : "s"} across {groups.length} framework{groups.length === 1 ? "" : "s"}
      </summary>
      <div className="mt-3 space-y-2" data-testid="finding-control-groups">
        {groups.map((group) => (
          <div key={group.label}>
            <p className="text-[11px] font-medium text-ink-tertiary">{group.label} · {group.controls.length}</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {group.controls.map((control) => control.href ? (
                <Link key={control.code} href={control.href} className={`${CHIP} hover:border-[color:var(--accent-mint)] hover:text-foreground`}>
                  {control.code}
                </Link>
              ) : <span key={control.code} className={CHIP}>{control.code}</span>)}
            </div>
          </div>
        ))}
      </div>
    </details>
  );
}
