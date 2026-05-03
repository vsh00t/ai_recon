"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { apiClient } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Table, Thead, Tr, Th, Td } from "@/components/ui/table";

const KIND_TONES: Record<string, "accent" | "neutral" | "info"> = {
  passive: "info",
  active: "accent",
  safety: "neutral",
  infra: "neutral",
  evasion: "accent",
};

export default function TechniquesPage() {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<string>("all");
  const { data = [] } = useQuery({ queryKey: ["techniques"], queryFn: apiClient.techniques });

  const kinds = useMemo(() => Array.from(new Set(data.map((t) => t.kind))).sort(), [data]);

  const filtered = data
    .filter((t) => (kind === "all" ? true : t.kind === kind))
    .filter((t) => q ? (t.id + " " + t.doc).toLowerCase().includes(q.toLowerCase()) : true);

  return (
    <>
      <PageHeader
        title="Techniques"
        description={`${data.length} techniques registered across ${kinds.length} kinds`}
      />
      <PageBody>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-72">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-fg-muted" />
            <Input
              placeholder="Search by id or description…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="pl-8"
            />
          </div>
          <div className="flex items-center gap-1 ml-2 text-xs">
            {["all", ...kinds].map((k) => (
              <button
                key={k}
                onClick={() => setKind(k)}
                className={
                  "rounded-md border px-2.5 py-1 transition-colors " +
                  (kind === k
                    ? "border-accent text-accent bg-accent-subtle"
                    : "border-border-subtle text-fg-muted hover:bg-bg-2")
                }
              >
                {k}
              </button>
            ))}
          </div>
        </div>

        <Card>
          <Table>
            <Thead>
              <Tr>
                <Th>ID</Th>
                <Th>Kind</Th>
                <Th>Intrusiveness</Th>
                <Th>Description</Th>
              </Tr>
            </Thead>
            <tbody>
              {filtered.map((t) => (
                <Tr key={t.id}>
                  <Td>
                    <Link className="font-mono text-xs text-fg-bold hover:text-accent" href={`/techniques/${encodeURIComponent(t.id)}`}>
                      {t.id}
                    </Link>
                  </Td>
                  <Td><Badge tone={KIND_TONES[t.kind] ?? "neutral"}>{t.kind}</Badge></Td>
                  <Td><Badge tone="neutral">{t.intrusiveness}</Badge></Td>
                  <Td className="text-fg-muted text-xs max-w-xl truncate">{t.doc || "—"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </Card>
      </PageBody>
    </>
  );
}
