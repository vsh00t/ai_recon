"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Boxes,
  FileText,
  Gauge,
  Layers,
  Library,
  Plug,
  Settings,
  Shield,
  Wand2,
} from "lucide-react";
import { cn } from "@/lib/cn";

const sections: { label: string; items: { href: string; label: string; icon: any }[] }[] = [
  {
    label: "Operate",
    items: [
      { href: "/", label: "Dashboard", icon: Gauge },
      { href: "/runs", label: "Runs", icon: Activity },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Library",
    items: [
      { href: "/scopes", label: "Scopes", icon: Shield },
      { href: "/profiles", label: "Profiles", icon: Wand2 },
      { href: "/techniques", label: "Techniques", icon: Layers },
      { href: "/catalogs", label: "Catalogs", icon: Library },
      { href: "/adapters", label: "Adapters", icon: Plug },
    ],
  },
  {
    label: "System",
    items: [{ href: "/settings", label: "Settings", icon: Settings }],
  },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="hidden md:flex flex-col w-60 shrink-0 border-r border-border-subtle bg-bg-1 h-screen sticky top-0">
      <div className="flex items-center gap-2 px-4 h-14 border-b border-border-subtle">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-accent text-accent-fg">
          <Boxes className="h-4 w-4" />
        </div>
        <span className="font-semibold tracking-tight text-fg-bold">ai-recon</span>
      </div>
      <nav className="flex-1 overflow-y-auto p-3 space-y-6">
        {sections.map((section) => (
          <div key={section.label}>
            <div className="px-2 text-[10px] font-semibold uppercase tracking-wider text-fg-muted mb-1.5">
              {section.label}
            </div>
            <ul className="space-y-0.5">
              {section.items.map((it) => {
                const active =
                  it.href === "/" ? path === "/" : path === it.href || path.startsWith(it.href + "/");
                const Icon = it.icon;
                return (
                  <li key={it.href}>
                    <Link
                      href={it.href}
                      className={cn(
                        "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors",
                        active
                          ? "bg-accent-subtle text-accent font-medium"
                          : "text-fg hover:bg-bg-2",
                      )}
                    >
                      <Icon className="h-4 w-4 opacity-80" />
                      {it.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-border-subtle text-[11px] text-fg-muted">
        v0.1.0 · <span className="text-fg">premium</span>
      </div>
    </aside>
  );
}
