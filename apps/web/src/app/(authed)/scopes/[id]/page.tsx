"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { apiClient, ApiError } from "@/lib/api";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { ScopeForm, ScopeDoc } from "@/features/scopes/scope-form";

export default function ScopeDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const { data, isLoading } = useQuery({ queryKey: ["scope", id], queryFn: () => apiClient.scope(id) });
  const [name, setName] = useState("");
  const [doc, setDoc] = useState<ScopeDoc>({ targets: [] });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setName(data.name);
      setDoc(data.doc as unknown as ScopeDoc);
    }
  }, [data]);

  if (isLoading) return <div className="p-6 text-fg-muted text-sm">Loading…</div>;
  if (!data) return <div className="p-6 text-sev-critical text-sm">Not found</div>;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await apiClient.updateScope(id, name, doc);
    } catch (e) {
      if (e instanceof ApiError) setError(JSON.stringify(e.data ?? e.message));
    } finally {
      setBusy(false);
    }
  }

  async function destroy() {
    if (!confirm(`Delete scope "${name}"?`)) return;
    await apiClient.deleteScope(id);
    router.push("/scopes");
  }

  return (
    <>
      <PageHeader
        title={data.name}
        description={`Scope ${id}`}
        actions={
          <>
            <Button variant="secondary" asChild><Link href={`/runs/new?scope=${id}`}>New run</Link></Button>
            <Button variant="destructive" onClick={destroy}>Delete</Button>
            <Button onClick={save} disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button>
          </>
        }
      />
      <PageBody>
        {error && (
          <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical font-mono whitespace-pre-wrap">{error}</div>
        )}
        <ScopeForm
          initialName={data.name}
          initialDoc={data.doc as unknown as ScopeDoc}
          onChange={(n, d) => { setName(n); setDoc(d); }}
        />
      </PageBody>
    </>
  );
}
