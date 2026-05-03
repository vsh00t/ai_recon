"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, Thead, Tr, Th, Td } from "@/components/ui/table";

export default function ProfilesPage() {
  const { data = [] } = useQuery({ queryKey: ["profiles"], queryFn: apiClient.profiles });
  return (
    <>
      <PageHeader title="Profiles" description="Pre-built and custom run presets." />
      <PageBody>
        <Card>
          <Table>
            <Thead>
              <Tr>
                <Th>Name</Th>
                <Th>Source</Th>
                <Th>Description</Th>
              </Tr>
            </Thead>
            <tbody>
              {data.map((p) => (
                <Tr key={p.name}>
                  <Td>
                    <Link className="text-sm text-fg-bold hover:text-accent" href={`/profiles/${p.name}`}>
                      {p.name}
                    </Link>
                  </Td>
                  <Td>
                    <Badge tone={p.source === "builtin" ? "info" : "accent"}>{p.source}</Badge>
                  </Td>
                  <Td className="text-fg-muted text-xs max-w-2xl truncate">{p.description ?? "—"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </Card>
      </PageBody>
    </>
  );
}
