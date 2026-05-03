"use client";

import { useState, useEffect } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export interface Target {
  host: string;
  port: number;
  scheme: "http" | "https" | "ws" | "wss" | "grpc";
  classification: string[];
}

export interface ScopeDoc {
  targets: Target[];
  authorization?: { granted: boolean; reference?: string };
}

const CLASSIFICATIONS = ["external", "internal", "ai", "api", "rag", "agent"];

export function ScopeForm({
  initialName = "",
  initialDoc = { targets: [] },
  onChange,
}: {
  initialName?: string;
  initialDoc?: ScopeDoc;
  onChange: (name: string, doc: ScopeDoc) => void;
}) {
  const [name, setName] = useState(initialName);
  const [doc, setDoc] = useState<ScopeDoc>(initialDoc);

  useEffect(() => onChange(name, doc), [name, doc, onChange]);

  function addTarget() {
    setDoc((d) => ({
      ...d,
      targets: [...d.targets, { host: "", port: 443, scheme: "https", classification: ["external"] }],
    }));
  }

  function updateTarget(i: number, patch: Partial<Target>) {
    setDoc((d) => {
      const t = [...d.targets];
      t[i] = { ...t[i], ...patch };
      return { ...d, targets: t };
    });
  }

  function removeTarget(i: number) {
    setDoc((d) => ({ ...d, targets: d.targets.filter((_, j) => j !== i) }));
  }

  function toggleClassification(i: number, c: string) {
    const t = doc.targets[i];
    const has = t.classification.includes(c);
    updateTarget(i, {
      classification: has ? t.classification.filter((x) => x !== c) : [...t.classification, c],
    });
  }

  return (
    <div className="space-y-4">
      <Card>
        <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">Identity</div>
        <div className="px-5 py-4">
          <label className="text-xs text-fg-muted">Name</label>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. acme-saas-prod" className="mt-1" />
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between px-5 py-3 border-b border-border-subtle">
          <div className="text-sm font-semibold text-fg-bold">Targets</div>
          <Button size="sm" variant="secondary" onClick={addTarget}>
            <Plus className="h-3.5 w-3.5" /> Add target
          </Button>
        </div>
        <div className="p-3 space-y-2">
          {doc.targets.length === 0 && (
            <div className="px-2 py-6 text-center text-xs text-fg-muted">
              No targets added.
            </div>
          )}
          {doc.targets.map((t, i) => (
            <div key={i} className="rounded-md border border-border-subtle bg-bg-1 p-3">
              <div className="flex flex-wrap gap-2 items-end">
                <div className="flex-1 min-w-[200px]">
                  <label className="text-[11px] text-fg-muted">Host</label>
                  <Input value={t.host} onChange={(e) => updateTarget(i, { host: e.target.value })} placeholder="api.example.com" className="mt-1" />
                </div>
                <div className="w-24">
                  <label className="text-[11px] text-fg-muted">Port</label>
                  <Input type="number" min={1} max={65535} value={t.port} onChange={(e) => updateTarget(i, { port: Number(e.target.value) })} className="mt-1" />
                </div>
                <div className="w-32">
                  <label className="text-[11px] text-fg-muted">Scheme</label>
                  <select
                    value={t.scheme}
                    onChange={(e) => updateTarget(i, { scheme: e.target.value as Target["scheme"] })}
                    className="mt-1 h-9 w-full rounded-md border border-border-subtle bg-bg-1 px-2 text-sm"
                  >
                    {(["https", "http", "wss", "ws", "grpc"] as Target["scheme"][]).map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <Button variant="ghost" size="icon" onClick={() => removeTarget(i)} aria-label="Remove">
                  <Trash2 className="h-4 w-4 text-sev-critical" />
                </Button>
              </div>
              <div className="mt-3">
                <div className="text-[11px] text-fg-muted mb-1">Classification</div>
                <div className="flex flex-wrap gap-1">
                  {CLASSIFICATIONS.map((c) => {
                    const on = t.classification.includes(c);
                    return (
                      <button
                        key={c}
                        type="button"
                        onClick={() => toggleClassification(i, c)}
                        className={
                          "rounded-full text-[11px] px-2.5 py-0.5 border transition-colors " +
                          (on
                            ? "bg-accent-subtle border-accent/30 text-accent"
                            : "bg-bg-2 border-border-subtle text-fg-muted hover:bg-bg-3")
                        }
                      >
                        {c}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div className="px-5 py-3 border-b border-border-subtle text-sm font-semibold text-fg-bold">Live preview</div>
        <pre className="p-5 text-xs font-mono text-fg whitespace-pre-wrap overflow-x-auto">
{JSON.stringify({ name, doc }, null, 2)}
        </pre>
      </Card>

      <div className="flex flex-wrap gap-2 text-xs text-fg-muted">
        <Badge tone="info">{doc.targets.length} targets</Badge>
        <Badge tone="neutral">validated server-side against scope.schema.json</Badge>
      </div>
    </div>
  );
}
