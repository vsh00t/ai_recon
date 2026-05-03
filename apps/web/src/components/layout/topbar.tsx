"use client";

import { Search, Sun, Moon, LogOut } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import { apiClient } from "@/lib/api";
import { useRouter } from "next/navigation";

export function Topbar({ user }: { user?: { email: string; role: string } }) {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const router = useRouter();
  const isDark = (theme ?? resolvedTheme) === "dark";

  return (
    <header className="sticky top-0 z-20 h-14 border-b border-border-subtle bg-bg-1/85 backdrop-blur supports-[backdrop-filter]:bg-bg-1/70">
      <div className="flex h-full items-center gap-3 px-4">
        <button
          className="flex w-72 items-center gap-2 rounded-md border border-border-subtle bg-bg-0 px-2.5 h-8 text-xs text-fg-muted hover:bg-bg-2 transition-colors"
          onClick={() => document.dispatchEvent(new CustomEvent("ai-recon-cmdk"))}
        >
          <Search className="h-3.5 w-3.5" />
          <span>Search runs, profiles, techniques…</span>
          <span className="ml-auto kbd">⌘K</span>
        </button>
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Toggle theme"
            onClick={() => setTheme(isDark ? "light" : "dark")}
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
          {user && (
            <div className="flex items-center gap-2 pl-2 border-l border-border-subtle">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-accent-subtle text-accent text-[11px] font-semibold">
                {user.email[0].toUpperCase()}
              </div>
              <div className="hidden lg:block leading-tight">
                <div className="text-xs text-fg">{user.email}</div>
                <div className="text-[10px] text-fg-muted uppercase">{user.role}</div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Logout"
                onClick={async () => {
                  await apiClient.logout();
                  router.replace("/login");
                  router.refresh();
                }}
              >
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
