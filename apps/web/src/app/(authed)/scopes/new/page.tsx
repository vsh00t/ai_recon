"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageBody, PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { ScopeForm, ScopeDoc } from "@/features/scopes/scope-form";
import { apiClient, ApiError } from "@/lib/api";

export default function NewScopePage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [doc, setDoc] = useState<ScopeDoc>({ targets: [] });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const out = await apiClient.createScope(name, doc);
      router.push(`/scopes/${out.id}`);
    } catch (e) {
      if (e instanceof ApiError) setError(JSON.stringify(e.data ?? e.message));
      else setError("Network error");
    } finally {
      setBusy(false);
    }
  }

  const valid = name.trim().length > 0 && doc.targets.length > 0;

  return (
    <>
      <PageHeader
        title="New scope"
        description="Define the authorized perimeter for runs."
        actions={
          <>
            <Button variant="secondary" onClick={() => router.back()}>Cancel</Button>
            <Button onClick={save} disabled={!valid || busy}>{busy ? "Saving…" : "Save scope"}</Button>
          </>
        }
      />
      <PageBody>
        {error && (
          <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical font-mono whitespace-pre-wrap">
            {error}
          </div>
        )}
        <ScopeForm onChange={(n, d) => { setName(n); setDoc(d); }} />
      </PageBody>
    </>
  );
}
