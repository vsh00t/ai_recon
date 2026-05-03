"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { CommandMenu } from "@/components/layout/command-menu";
import { apiClient, ApiError, User } from "@/lib/api";

export default function AuthedLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    apiClient
      .me()
      .then((u) => {
        setUser(u);
        setChecked(true);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) router.replace("/login");
      });
  }, [router]);

  if (!checked) {
    return (
      <div className="grid min-h-screen place-items-center text-fg-muted text-sm">
        Loading…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-bg-0 text-fg">
      <Sidebar />
      <div className="flex-1 min-w-0 flex flex-col">
        <Topbar user={user!} />
        <main className="flex-1 min-w-0">{children}</main>
      </div>
      <CommandMenu />
    </div>
  );
}
