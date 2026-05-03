"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Library } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";

export default function CatalogsPage() {
  const { data = [] } = useQuery({ queryKey: ["catalogs"], queryFn: apiClient.catalogs });
  return (
    <>
      <PageHeader title="Catalogs" description="Reference data: vendors, frameworks, signatures, prompts." />
      <PageBody>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {data.map((name) => (
            <Link key={name} href={`/catalogs/${name}`}>
              <Card className="hover:border-accent/50 transition-colors h-full">
                <CardContent className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-bg-2 border border-border-subtle text-fg-muted">
                    <Library className="h-4 w-4" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-fg-bold">{name}</div>
                    <div className="text-[11px] text-fg-muted font-mono">catalogs/{name}.yaml</div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </PageBody>
    </>
  );
}
