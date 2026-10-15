import { severityColor, severityText } from "@/lib/api";

interface Props {
  severity: string;
  severitySource?: string | null | undefined;
  className?: string;
}

export function SeverityBadge({ severity, severitySource, className = "" }: Props) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-mono font-semibold uppercase tracking-wide ${severityColor(severity)} ${className}`}
    >
      {severityText(severity, { severity_source: severitySource })}
    </span>
  );
}
