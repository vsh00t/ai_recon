"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Activity, Layers, Plug, ShieldCheck } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";

function Stat({ icon, label, value, hint }: { icon: React.ReactNode; label: string; value: number | string; hint?: string }) {
  return (
    <Card>
      <CardContent className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-wide text-fg-muted">{label}</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-fg-bold tabular-nums">{value}</div>
          {hint && <div className="mt-0.5 text-[11px] text-fg-muted">{hint}</div>}
        </div>
        <div className="flex h-9 w-9 items-center justify-center rounded-md border border-border-subtle bg-bg-2 text-fg-muted">
          {icon}
        </div>
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const runs = useQuery({ queryKey: ["runs"], queryFn: apiClient.runs });
  const techniques = useQuery({ queryKey: ["techniques"], queryFn: apiClient.techniques });
  const adapters = useQuery({ queryKey: ["adapters"], queryFn: apiClient.adapters });
  const scopes = useQuery({ queryKey: ["scopes"], queryFn: apiClient.scopes });

  const adapterCount = adapters.data
    ? Object.values(adapters.data).reduce((s, a) => s + a.length, 0)
    : 0;

  const recent = runs.data?.slice(0, 8) ?? [];

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Operations overview"
        actions={
          <Button asChild>
            <Link href="/runs/new">New run</Link>
          </Button>
        }
      />
      <PageBody>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Stat icon={<Activity className="h-4 w-4" />} label="Runs" value={runs.data?.length ?? "—"} hint="all time" />
          <Stat icon={<Layers className="h-4 w-4" />} label="Techniques" value={techniques.data?.length ?? "—"} hint="registered" />
          <Stat icon={<ShieldCheck className="h-4 w-4" />} label="Scopes" value={scopes.data?.length ?? "—"} hint="saved" />
          <Stat icon={<Plug className="h-4 w-4" />} label="Adapters" value={adapterCount} hint="across groups" />
        </div>

        <Card>
          <div className="flex items-center justify-between border-b border-border-subtle px-5 py-3">
            <div className="text-sm font-semibold text-fg-bold">Recent runs</div>
            <Link href="/runs" className="text-xs text-accent hover:underline">View all</Link>
          </div>
          {recent.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-5 w-5" />}
              title="No runs yet"
              description="Launch your first reconnaissance run to see activity here."
              action={<Button asChild><Link href="/runs/new">New run</Link></Button>}
            />
          ) : (
            <ul className="divide-y divide-border-subtle">
              {recent.map((r) => (
                <li key={r.id}>
                  <Link href={`/runs/${r.id}`} className="flex items-center justify-between px-5 py-3 hover:bg-bg-2/60">
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-fg-muted">{r.id.slice(0, 12)}</div>
                      <div className="text-sm text-fg-bold truncate">{r.profile_name}</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-fg-muted">
                        {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                      </span>
                      <StatusBadge status={r.status} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </PageBody>
    </>
  );
}
