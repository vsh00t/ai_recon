"use client";

import { useQuery } from "@tanstack/react-query";
import { Plug } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function AdaptersPage() {
  const { data } = useQuery({ queryKey: ["adapters"], queryFn: apiClient.adapters });
  return (
    <>
      <PageHeader title="Adapters" description="Plugins available across SIEM, repo and secrets groups." />
      <PageBody>
        <div className="grid gap-4 md:grid-cols-3">
          {data &&
            Object.entries(data).map(([group, kinds]) => (
              <Card key={group}>
                <CardContent>
                  <div className="flex items-center gap-2 mb-3">
                    <Plug className="h-4 w-4 text-fg-muted" />
                    <div className="text-sm font-semibold text-fg-bold capitalize">{group}</div>
                    <Badge tone="neutral">{kinds.length}</Badge>
                  </div>
                  <ul className="space-y-1">
                    {kinds.map((k) => (
                      <li key={k} className="font-mono text-xs flex items-center justify-between rounded-md px-2 py-1 hover:bg-bg-2">
                        <span>{k}</span>
                        <Badge tone="accent">available</Badge>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
        </div>
      </PageBody>
    </>
  );
}
