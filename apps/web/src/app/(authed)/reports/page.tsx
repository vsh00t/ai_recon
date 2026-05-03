"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { StatusBadge } from "@/components/ui/badge";
import { Table, Thead, Tr, Th, Td } from "@/components/ui/table";

export default function ReportsPage() {
  const { data = [] } = useQuery({ queryKey: ["runs"], queryFn: apiClient.runs });
  const completed = data.filter((r) => r.status === "completed" || r.status === "failed");

  return (
    <>
      <PageHeader title="Reports" description="Findings and severity summaries from completed runs." />
      <PageBody>
        {completed.length === 0 ? (
          <Card>
            <EmptyState
              icon={<FileText className="h-5 w-5" />}
              title="No reports yet"
              description="Reports become available once a run completes."
            />
          </Card>
        ) : (
          <Card>
            <Table>
              <Thead>
                <Tr><Th>Run</Th><Th>Profile</Th><Th>Finished</Th><Th>Status</Th></Tr>
              </Thead>
              <tbody>
                {completed.map((r) => (
                  <Tr key={r.id}>
                    <Td>
                      <Link className="font-mono text-xs text-fg-bold hover:text-accent" href={`/reports/${r.id}`}>
                        {r.id.slice(0, 12)}
                      </Link>
                    </Td>
                    <Td className="text-sm">{r.profile_name}</Td>
                    <Td className="text-fg-muted text-xs">{r.finished_at ? new Date(r.finished_at).toLocaleString() : "—"}</Td>
                    <Td><StatusBadge status={r.status} /></Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </Card>
        )}
      </PageBody>
    </>
  );
}
