import { ArrowLeftRight, ArrowRight, CornerUpLeft } from "lucide-react";

const ICONS = { next: ArrowRight, returns: CornerUpLeft, peer: ArrowLeftRight } as const;

/** One declared route in a list: the next step, a return to an earlier step, or a shared server. */
export function RouteLine({ kind, text }: { kind: keyof typeof ICONS; text: string }) {
  const Icon = ICONS[kind];
  return (
    <li className="flex items-start gap-1.5" data-route={kind}>
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="min-w-0">{text}</span>
    </li>
  );
}
