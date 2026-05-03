"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export default function ProfileDetail({ params }: { params: Promise<{ name: string }> }) {
  const { name } = use(params);
  const { data, isLoading } = useQuery({
    queryKey: ["profile", name],
    queryFn: () => apiClient.profile(name),
  });

  if (isLoading) return <div className="p-6 text-fg-muted text-sm">Loading…</div>;
  if (!data) return <div className="p-6 text-sev-critical text-sm">Not found</div>;

  const techs = data.doc?.techniques ?? {};
  const enable: string[] = Array.isArray(techs) ? techs : techs.enable ?? [];
  const disable: string[] = Array.isArray(techs) ? [] : techs.disable ?? [];

  return (
    <>
      <PageHeader
        title={data.name}
        description={data.doc?.description ?? "Profile detail"}
        actions={
          <Button asChild>
            <Link href={`/runs/new?profile=${encodeURIComponent(data.name)}`}>Run with this profile</Link>
          </Button>
        }
      />
      <PageBody>
        <div className="flex flex-wrap gap-2">
          <Badge tone={data.source === "builtin" ? "info" : "accent"}>{data.source}</Badge>
          {data.doc?.intrusiveness_max && <Badge tone="medium">max intrusiveness: {data.doc.intrusiveness_max}</Badge>}
          <Badge tone="neutral">{enable.length} enabled</Badge>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">Enabled techniques</div>
            <ul className="p-3 space-y-1">
              {enable.length === 0 && <li className="text-xs text-fg-muted px-2 py-3">No techniques enabled.</li>}
              {enable.map((t) => (
                <li key={t}>
                  <Link className="font-mono text-xs flex items-center justify-between rounded-md px-2 py-1 hover:bg-bg-2" href={`/techniques/${encodeURIComponent(t)}`}>
                    {t}
                  </Link>
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">Disabled overrides</div>
            <ul className="p-3 space-y-1">
              {disable.length === 0 && <li className="text-xs text-fg-muted px-2 py-3">None.</li>}
              {disable.map((t) => (
                <li key={t} className="font-mono text-xs flex items-center justify-between rounded-md px-2 py-1">
                  {t}
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <Card>
          <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">Raw profile document</div>
          <pre className="p-5 text-xs font-mono whitespace-pre-wrap text-fg overflow-x-auto">
{JSON.stringify(data.doc, null, 2)}
          </pre>
        </Card>
      </PageBody>
    </>
  );
}
