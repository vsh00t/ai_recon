"use client";

import { use, useMemo, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";

type Sev = "critical" | "high" | "medium" | "low" | "info";
const SEV_COLORS: Record<Sev, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export default function ReportDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [filter, setFilter] = useState<Sev | "all">("all");
  const report = useQuery({ queryKey: ["report", id], queryFn: () => apiClient.report(id) });
  const findings = useQuery({ queryKey: ["run-findings", id], queryFn: () => apiClient.runFindings(id) });

  const filtered = useMemo(() => {
    const list = (findings.data ?? []) as any[];
    if (filter === "all") return list;
    return list.filter((f) => (f.severity ?? "info") === filter);
  }, [findings.data, filter]);

  async function download(fmt: "json" | "md") {
    const out = await apiClient.renderReport(id, fmt);
    const blob = new Blob([fmt === "json" ? JSON.stringify(out, null, 2) : String(out)], {
      type: fmt === "json" ? "application/json" : "text/markdown",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${id.slice(0, 8)}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const sev = report.data?.severity ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const total = report.data?.findings_total ?? 0;

  return (
    <>
      <PageHeader
        title={`Report ${id.slice(0, 12)}`}
        description={report.data?.profile ?? ""}
        actions={
          <>
            {report.data && <StatusBadge status={report.data.status} />}
            <Button variant="secondary" size="sm" onClick={() => download("md")}>
              <Download className="h-3.5 w-3.5" /> Markdown
            </Button>
            <Button variant="secondary" size="sm" onClick={() => download("json")}>
              <Download className="h-3.5 w-3.5" /> JSON
            </Button>
            <Button asChild size="sm" variant="ghost">
              <Link href={`/runs/${id}`}>View run</Link>
            </Button>
          </>
        }
      />
      <PageBody>
        <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4">
          <Card>
            <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">
              Severity
            </div>
            <div className="p-5 flex flex-col items-center gap-4">
              <Donut sev={sev} total={total} />
              <div className="w-full space-y-1.5">
                {(["critical", "high", "medium", "low", "info"] as Sev[]).map((s) => (
                  <button key={s} onClick={() => setFilter(filter === s ? "all" : s)}
                    className={"w-full flex items-center justify-between rounded px-2 py-1 text-xs transition-colors " +
                      (filter === s ? "bg-bg-2" : "hover:bg-bg-1")}>
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[s] }} />
                      <span className="text-fg capitalize">{s}</span>
                    </span>
                    <span className="font-mono text-fg-bold">{sev[s] ?? 0}</span>
                  </button>
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <div className="flex items-center justify-between px-5 py-3 border-b border-border-subtle">
              <div className="text-sm font-semibold text-fg-bold">
                Findings {filter !== "all" && <span className="text-fg-muted font-normal">· {filter}</span>}
              </div>
              {filter !== "all" && (
                <button onClick={() => setFilter("all")} className="text-xs text-accent hover:underline">Clear filter</button>
              )}
            </div>
            <ul className="divide-y divide-border-subtle max-h-[640px] overflow-y-auto">
              {filtered.map((f: any, i) => (
                <li key={i} className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity ?? "info"} />
                    <span className="text-sm font-medium text-fg-bold">{f.title ?? f.id}</span>
                    {f.technique_id && <span className="font-mono text-[11px] text-fg-muted">· {f.technique_id}</span>}
                  </div>
                  {f.description && <div className="text-xs text-fg-muted mt-1">{f.description}</div>}
                  {f.evidence && (
                    <pre className="mt-2 text-[11px] font-mono text-fg-muted bg-bg-1 rounded p-2 overflow-x-auto">
                      {JSON.stringify(f.evidence, null, 2)}
                    </pre>
                  )}
                </li>
              ))}
              {filtered.length === 0 && (
                <li className="px-5 py-10 text-center text-xs text-fg-muted">No findings match this filter.</li>
              )}
            </ul>
          </Card>
        </div>
      </PageBody>
    </>
  );
}

function Donut({ sev, total }: { sev: Record<Sev, number>; total: number }) {
  const size = 160;
  const r = 64;
  const c = 2 * Math.PI * r;
  const order: Sev[] = ["critical", "high", "medium", "low", "info"];
  const sum = order.reduce((a, k) => a + (sev[k] ?? 0), 0) || 1;
  let offset = 0;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg-2)" strokeWidth={14} />
        {order.map((k) => {
          const v = sev[k] ?? 0;
          if (!v) return null;
          const len = (v / sum) * c;
          const dasharray = `${len} ${c - len}`;
          const dashoffset = -offset;
          offset += len;
          return (
            <circle key={k} cx={size / 2} cy={size / 2} r={r} fill="none"
              stroke={SEV_COLORS[k]} strokeWidth={14}
              strokeDasharray={dasharray} strokeDashoffset={dashoffset}
              strokeLinecap="butt" />
          );
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-2xl font-semibold text-fg-bold tabular-nums">{total}</div>
        <div className="text-[10px] text-fg-muted uppercase tracking-wider">findings</div>
      </div>
    </div>
  );
}
