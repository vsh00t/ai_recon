"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Table, Thead, Tr, Th, Td } from "@/components/ui/table";

export default function ScopesPage() {
  const { data = [] } = useQuery({ queryKey: ["scopes"], queryFn: apiClient.scopes });
  return (
    <>
      <PageHeader
        title="Scopes"
        description="Authorized hosts, ranges and target classifications."
        actions={<Button asChild><Link href="/scopes/new">New scope</Link></Button>}
      />
      <PageBody>
        {data.length === 0 ? (
          <Card>
            <EmptyState
              icon={<ShieldCheck className="h-5 w-5" />}
              title="No scopes saved"
              description="A scope defines what targets a run is authorized to touch."
              action={<Button asChild><Link href="/scopes/new">Create scope</Link></Button>}
            />
          </Card>
        ) : (
          <Card>
            <Table>
              <Thead>
                <Tr><Th>Name</Th><Th>Targets</Th><Th>ID</Th></Tr>
              </Thead>
              <tbody>
                {data.map((s) => {
                  const t = (s.doc as any)?.targets;
                  const count = Array.isArray(t) ? t.length : 0;
                  return (
                    <Tr key={s.id}>
                      <Td>
                        <Link className="text-sm font-medium text-fg-bold hover:text-accent" href={`/scopes/${s.id}`}>
                          {s.name}
                        </Link>
                      </Td>
                      <Td className="text-fg-muted">{count}</Td>
                      <Td className="font-mono text-xs text-fg-muted">{s.id}</Td>
                    </Tr>
                  );
                })}
              </tbody>
            </Table>
          </Card>
        )}
      </PageBody>
    </>
  );
}
