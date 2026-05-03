"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function TechniqueDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, isLoading, error } = useQuery({
    queryKey: ["technique", id],
    queryFn: () => apiClient.technique(decodeURIComponent(id)),
  });

  if (isLoading) return <div className="p-6 text-fg-muted text-sm">Loading…</div>;
  if (error || !data) return <div className="p-6 text-sev-critical text-sm">Not found</div>;

  return (
    <>
      <PageHeader title={data.id} description={data.doc || data.module} />
      <PageBody>
        <div className="flex flex-wrap gap-2">
          <Badge tone="accent">{data.kind}</Badge>
          <Badge tone="neutral">intrusiveness: {data.intrusiveness}</Badge>
          {data.requires.map((r) => (
            <Badge key={r} tone="info">requires: {r}</Badge>
          ))}
          {data.produces.map((p) => (
            <Badge key={p} tone="low">produces: {p}</Badge>
          ))}
        </div>

        <Card>
          <CardContent className="space-y-3 text-sm">
            <div>
              <div className="text-xs uppercase tracking-wide text-fg-muted">Module</div>
              <div className="font-mono text-xs mt-0.5">{data.module}.{data.class_name}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-fg-muted">Description</div>
              <p className="mt-1 text-fg whitespace-pre-wrap">{data.doc || "—"}</p>
            </div>
          </CardContent>
        </Card>
      </PageBody>
    </>
  );
}
