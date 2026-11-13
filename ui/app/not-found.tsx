import { ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-[80vh] gap-4 text-center">
      <ShieldAlert className="w-12 h-12 text-[var(--text-tertiary)]" />
      <h1 className="text-lg font-semibold text-[var(--foreground)]">Page not found</h1>
      <p className="text-sm text-[var(--text-secondary)]">The page you are looking for does not exist. Nothing was opened in its place.</p>
      <div className="flex flex-wrap justify-center gap-2">
        <Link
          href="/"
          className="px-4 py-2 bg-[color:var(--accent)] hover:bg-[color:var(--accent-strong)] rounded-md text-sm text-[color:var(--accent-contrast)] transition-colors"
        >
          Back to Overview
        </Link>
        {/* An unknown address under /graph or /security-graph most often came from a graph link. */}
        <Link href="/security-graph?lens=attack-path" className="rounded-md border border-outline px-4 py-2 text-sm text-[var(--foreground)] hover:bg-surface-elevated">
          Open the investigation graph
        </Link>
      </div>
    </div>
  );
}
