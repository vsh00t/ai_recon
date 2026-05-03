"use client";

import { Command } from "cmdk";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, FileText, Library, Plug, Shield, Wand2, Zap } from "lucide-react";

const items = [
  { id: "go-runs", label: "Go to Runs", href: "/runs", icon: Activity },
  { id: "go-reports", label: "Go to Reports", href: "/reports", icon: FileText },
  { id: "go-scopes", label: "Go to Scopes", href: "/scopes", icon: Shield },
  { id: "go-profiles", label: "Go to Profiles", href: "/profiles", icon: Wand2 },
  { id: "go-catalogs", label: "Go to Catalogs", href: "/catalogs", icon: Library },
  { id: "go-adapters", label: "Go to Adapters", href: "/adapters", icon: Plug },
  { id: "new-run", label: "New run…", href: "/runs/new", icon: Zap },
  { id: "new-scope", label: "New scope…", href: "/scopes/new", icon: Shield },
];

export function CommandMenu() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    const onCustom = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    document.addEventListener("ai-recon-cmdk", onCustom);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("ai-recon-cmdk", onCustom);
    };
  }, []);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-black/40 backdrop-blur-sm" onClick={() => setOpen(false)}>
      <div className="w-full max-w-lg rounded-xl border border-border-strong bg-bg-1 shadow-lg overflow-hidden animate-fade-in" onClick={(e) => e.stopPropagation()}>
        <Command label="Command palette" shouldFilter>
          <Command.Input
            autoFocus
            placeholder="Type a command…"
            className="w-full bg-transparent border-b border-border-subtle px-4 h-11 text-sm outline-none placeholder:text-fg-muted"
          />
          <Command.List className="max-h-80 overflow-y-auto p-1">
            <Command.Empty className="px-4 py-8 text-center text-xs text-fg-muted">No results.</Command.Empty>
            {items.map((it) => {
              const Icon = it.icon;
              return (
                <Command.Item
                  key={it.id}
                  value={it.label}
                  onSelect={() => {
                    setOpen(false);
                    router.push(it.href);
                  }}
                  className="flex items-center gap-2 px-3 py-2 rounded-md text-sm text-fg cursor-pointer aria-selected:bg-accent-subtle aria-selected:text-accent"
                >
                  <Icon className="h-4 w-4 opacity-80" />
                  {it.label}
                </Command.Item>
              );
            })}
          </Command.List>
        </Command>
      </div>
    </div>
  );
}
