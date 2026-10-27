import Link from "next/link";
import { Server } from "lucide-react";
import { ASSET_KINDS } from "@/lib/asset-icon-registry";
import { agentDisplayName } from "@/lib/display-name";

const PackageGlyph = ASSET_KINDS.package.icon;

const chip = "rounded bg-[color:var(--surface-muted)] px-2 py-0.5 text-xs text-[color:var(--text-secondary)] underline decoration-dotted underline-offset-2 transition hover:text-[color:var(--foreground)]";

function AssetGroup({ icon, title, items, href, mono, label = (item) => item }: {
  icon: React.ReactNode; title: string; items: string[]; href: (item: string) => string; mono?: boolean; label?: (item: string) => string;
}) {
  if (items.length === 0) return null;
  return (
    <div className="mb-4">
      <div className="mb-2 flex items-center gap-1.5 text-xs text-[color:var(--text-tertiary)]">{icon}{title}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => <Link key={item} href={href(item)} title={item} className={`${chip} ${mono ? "font-mono" : ""}`}>{label(item)}</Link>)}
      </div>
    </div>
  );
}

/** A control's affected packages and agents, each opening its own page. */
export function ControlAffectedAssets({ packages, agents }: { packages: string[]; agents: string[] }) {
  if (packages.length === 0 && agents.length === 0) {
    return <p className="text-sm text-[color:var(--text-secondary)]">No affected package or agent identities were reported for this control.</p>;
  }
  return (
    <div>
      <AssetGroup icon={<PackageGlyph className="h-3.5 w-3.5" />} title="Affected packages" items={packages} mono
        href={(pkg) => `/findings?${new URLSearchParams({ q: pkg })}`} />
      <AssetGroup icon={<Server className="h-3.5 w-3.5" />} title="Affected agents" items={agents} label={agentDisplayName}
        href={(agent) => `/agents?${new URLSearchParams({ name: agent })}`} />
    </div>
  );
}
