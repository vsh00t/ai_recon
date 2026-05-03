import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium tracking-tight border",
  {
    variants: {
      tone: {
        neutral: "bg-bg-2 text-fg-muted border-border-subtle",
        accent: "bg-accent-subtle text-accent border-accent/30",
        critical: "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
        high: "bg-sev-high/10 text-sev-high border-sev-high/30",
        medium: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
        low: "bg-sev-low/10 text-sev-low border-sev-low/30",
        info: "bg-sev-info/10 text-sev-info border-sev-info/30",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(({ className, tone, ...props }, ref) => (
  <span ref={ref} className={cn(badgeVariants({ tone }), className)} {...props} />
));
Badge.displayName = "Badge";

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = (
    {
      critical: "critical",
      high: "high",
      medium: "medium",
      low: "low",
      info: "info",
    } as const
  )[severity as "critical"] ?? "neutral";
  return <Badge tone={tone as any}>{severity}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { tone: any; label: string; pulse?: boolean }> = {
    queued: { tone: "neutral", label: "queued" },
    running: { tone: "accent", label: "running", pulse: true },
    completed: { tone: "low", label: "completed" },
    failed: { tone: "critical", label: "failed" },
    canceled: { tone: "info", label: "canceled" },
  };
  const cfg = map[status] ?? { tone: "neutral", label: status };
  return (
    <Badge tone={cfg.tone}>
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          cfg.tone === "low" && "bg-sev-low",
          cfg.tone === "accent" && "bg-accent",
          cfg.tone === "critical" && "bg-sev-critical",
          cfg.tone === "info" && "bg-sev-info",
          cfg.tone === "neutral" && "bg-fg-muted",
          cfg.pulse && "animate-pulse",
        )}
      />
      {cfg.label}
    </Badge>
  );
}
