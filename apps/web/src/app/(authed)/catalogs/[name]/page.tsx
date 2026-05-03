"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";

export default function CatalogDetail({ params }: { params: Promise<{ name: string }> }) {
  const { name } = use(params);
  const { data, isLoading } = useQuery({
    queryKey: ["catalog", name],
    queryFn: () => apiClient.catalog(name),
  });

  return (
    <>
      <PageHeader title={name} description={`catalogs/${name}.yaml`} />
      <PageBody>
        <Card>
          <pre className="p-5 overflow-x-auto text-xs leading-relaxed font-mono text-fg whitespace-pre-wrap">
{isLoading ? "Loading…" : JSON.stringify(data, null, 2)}
          </pre>
        </Card>
      </PageBody>
    </>
  );
}
