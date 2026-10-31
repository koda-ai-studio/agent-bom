"use client";

import {
Activity,
Bot,
Boxes,
Bug,
ClipboardList,
Clock,
Cog,
Cpu,
DollarSign,
Eye,
FileCheck,
FileText,
FolderSearch,
Fingerprint,
Gauge,
HardDrive,
LayoutDashboard,
ListChecks,
Network,
Plug,
Radar,
Radio,
Scale,
Scan,
ScrollText,
Shield,
ShieldAlert,
ShieldCheck,
Users,
Wrench
} from "lucide-react";



// ─── Navigation Structure ──────────────────────────────────────────────────

export interface NavLink {
  href: string;
  label: string;
  icon: React.ElementType;
  capability?: string;
  /** One-line "what is this" descriptor, surfaced as a hover tooltip. */
  desc?: string;
  /** Deployment-wide operator surfaces are hidden unless the effective session has the capability. */
  operatorOnly?: boolean;
  /** Not served by the demo-estate backend; hidden there instead of linking to a 404. */
  hiddenInDemoEstate?: boolean;
}



export interface NavGroup {
  label: string;
  icon: React.ElementType;
  links: NavLink[];
  /** One-line descriptor so a newcomer knows what the group is for. */
  desc?: string;
  /**
   * Lower-frequency destinations kept in command search. Their routes remain
   * stable without adding another row to the primary navigation.
   */
  secondary?: NavLink[];
}



export const INVESTIGATION_LENS_PREFIXES = ["/security-graph", "/graph", "/mesh", "/context"];



export function isNavLinkActive(href: string, path: string): boolean {
  const hrefPath = href.split("?")[0] ?? href;
  if (hrefPath === "/") return path === "/";
  if (hrefPath === "/security-graph") {
    return INVESTIGATION_LENS_PREFIXES.some((prefix) => path.startsWith(prefix));
  }
  return path.startsWith(hrefPath);
}



export function activeGroupForPath(path: string | null): string {
  const matched = NAV_GROUPS.find((group) =>
    [...group.links, ...(group.secondary ?? [])].some((link) =>
      link.href === "/" ? path === "/" : Boolean(path?.startsWith(link.href))
    )
  );
  return matched?.label ?? NAV_GROUPS[0]!.label;
}



// Ordered top-to-bottom as the product pipeline: understand posture → inventory
// your AI → govern it → connect sources → watch runtime → operate. One job per
// group, with descriptors on the groups and on the easily-confused destinations
// (Connections vs Data Sources) so nothing reads as ambiguous.
export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Posture",
    icon: Gauge,
    desc: "Risk, findings, and fixes",
    links: [
      { href: "/", label: "Overview", icon: LayoutDashboard, desc: "Cross-domain posture snapshot" },
      {
        href: "/security-graph",
        label: "Investigation",
        icon: Network,
        desc: "Current estate topology with evidence-linked investigation lenses",
      },
      { href: "/findings", label: "Findings", icon: Bug, desc: "Queue of evidence; open a row to investigate the estate node" },
      { href: "/advisories", label: "Advisories", icon: ShieldAlert, desc: "Which assets a CVE or emergency advisory affects, and declaring one before feeds publish it" },
      { href: "/remediation", label: "Remediation", icon: Wrench },
    ],
  },
  {
    label: "Inventory",
    icon: Boxes,
    desc: "Assets, agents, AI BOM, and fleet",
    links: [
      {
        href: "/inventory",
        label: "Asset Inventory",
        icon: Boxes,
        desc: "Repos, packages, images, cloud, identities, MCP, agents — one section",
      },
      { href: "/agents", label: "Agents", icon: Bot, desc: "Discovered agent configurations and scan evidence" },
      {
        href: "/skills",
        label: "Skills",
        icon: ScrollText,
        desc: "Review instruction files for behavioral risk and signing provenance",
      },
      { href: "/manifest", label: "AI BOM", icon: ClipboardList, desc: "Registered agents, MCP inventory, and runtime observations" },
      { href: "/fleet", label: "Fleet", icon: Users, desc: "Enrollment, review, and lifecycle management" },
    ],
  },
  {
    label: "Governance",
    icon: Scale,
    desc: "Compliance, policy, and audit",
    links: [
      { href: "/compliance", label: "Compliance", icon: FileCheck },
      { href: "/governance", label: "Cloud Governance", icon: Eye, capability: "policy.manage", hiddenInDemoEstate: true },
      { href: "/drift", label: "Drift", icon: Radar, desc: "Config drift from approved baselines" },
      { href: "/audit", label: "Audit Log", icon: FileText },
    ],
    secondary: [
      { href: "/blueprints", label: "Blueprints", icon: Boxes },
      { href: "/findings?lens=trust", label: "Findings triage", icon: ListChecks },
    ],
  },
  {
    label: "Connect",
    icon: Plug,
    desc: "Add sources, then scan",
    links: [
      { href: "/get-started", label: "Get started", icon: FolderSearch, desc: "Choose a source, send a project, or preview a local report" },
      { href: "/connections", label: "Connections", icon: Plug, capability: "inventory.read", desc: "Connect cloud, code, AI, and data — then see every source in one place" },
      { href: "/scan", label: "New Scan", icon: Scan, capability: "scan.run" },
    ],
  },
  {
    label: "Runtime",
    icon: Cpu,
    desc: "Live enforcement and identity",
    links: [
      { href: "/runtime", label: "Runtime", icon: Shield },
      { href: "/live-activity", label: "Live Activity", icon: Radio, desc: "Review runtime decisions and investigate evidence" },
      { href: "/cwpp", label: "CWPP Side-Scan", icon: HardDrive, desc: "Agentless Azure/GCP disk side-scan — SBOM, CVEs, secrets" },
      { href: "/traces", label: "Traces", icon: Radio },
      { href: "/identity", label: "Identity", icon: Fingerprint, desc: "Non-human identities and creds" },
    ],
  },
  {
    label: "Operations",
    icon: Cog,
    desc: "Spend, jobs, and integrations",
    links: [
      { href: "/cost", label: "AI Spend", icon: DollarSign },
      { href: "/jobs", label: "Scan Jobs", icon: Clock },
      { href: "/activity", label: "Agent Activity", icon: Activity },
      { href: "/integrations", label: "Integrations", icon: Plug, desc: "Webhooks, SIEM, threat intel, and report exports" },
      {
        href: "/self-posture",
        label: "Control Plane Security",
        icon: ShieldCheck,
        capability: "policy.manage",
        operatorOnly: true,
        hiddenInDemoEstate: true,
        desc: "Operator checks for this deployment's authentication, isolation, audit, and secret controls",
      },
    ],
    secondary: [{ href: "/registry", label: "MCP Catalog", icon: Boxes }, { href: "/settings", label: "Settings", icon: Cog }],
  },
];



export const ALL_GROUP_LABELS = NAV_GROUPS.map((group) => group.label);



/** Per-route icon tint — semantic color without rainbow group chrome. */
export const NAV_LINK_ICON_CLASS: Record<string, string> = {
  "/": "text-sky-400",
  "/findings": "text-red-400",
  "/security-graph": "text-violet-400",
  "/remediation": "text-emerald-400",
  "/graph": "text-sky-400",
  "/mesh": "text-fuchsia-400",
  "/context": "text-amber-400",
  "/agents": "text-emerald-400",
  "/manifest": "text-cyan-400",
  "/fleet": "text-blue-400",
  "/inventory": "text-sky-400",
  "/connections": "text-purple-400",
  "/sources": "text-indigo-400",
  "/scan": "text-orange-400",
  "/identity": "text-pink-400",
  "/drift": "text-rose-400",
  "/runtime": "text-pink-400",
  "/traces": "text-violet-400",
  "/compliance": "text-emerald-400",
  "/governance": "text-amber-400",
  "/audit": "text-teal-400",
  "/self-posture": "text-emerald-400",
  "/registry": "text-amber-400",
  "/cost": "text-yellow-400",
  "/jobs": "text-orange-400",
  "/activity": "text-lime-400",
  "/integrations": "text-teal-400",
};



export const NAV_GROUP_ICON_CLASS: Record<string, string> = {
  Posture: "text-sky-400",
  Inventory: "text-sky-400",
  Governance: "text-emerald-400",
  Connect: "text-purple-400",
  Runtime: "text-pink-400",
  Operations: "text-orange-400",
};



export function navLinkIconClass(href: string, active: boolean, hoverGroup = "group"): string {
  const tone = NAV_LINK_ICON_CLASS[href];
  if (tone) {
    return active ? tone : `${tone} opacity-80 ${hoverGroup}-hover:opacity-100`;
  }
  return active
    ? "text-foreground"
    : `text-ink-tertiary ${hoverGroup}-hover:text-ink-secondary`;
}



export function navGroupIconClass(label: string, hasActiveChild: boolean): string {
  const tone = NAV_GROUP_ICON_CLASS[label];
  if (tone) {
    return hasActiveChild ? tone : `${tone} opacity-75`;
  }
  return hasActiveChild ? "text-foreground" : "text-ink-tertiary";
}
