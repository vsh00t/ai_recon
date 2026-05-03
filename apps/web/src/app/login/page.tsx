"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Boxes, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiClient, ApiError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiClient.login(email, password);
      router.replace("/");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError) setError("Invalid credentials.");
      else setError("Network error.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen grid place-items-center bg-bg-0 px-4">
      <div
        className="absolute inset-0 -z-10 opacity-[.35] pointer-events-none"
        style={{
          backgroundImage:
            "radial-gradient(60rem 30rem at 80% -10%, rgba(59,130,246,.15), transparent), radial-gradient(40rem 20rem at 10% 110%, rgba(168,85,247,.10), transparent)",
        }}
      />
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-accent text-accent-fg">
            <Boxes className="h-4 w-4" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-fg-bold">ai-recon</div>
            <div className="text-[11px] text-fg-muted">Operations console</div>
          </div>
        </div>
        <h1 className="text-xl font-semibold tracking-tight text-fg-bold">Sign in</h1>
        <p className="mt-1 text-sm text-fg-muted">Use the credentials provisioned for your operator account.</p>
        <form onSubmit={onSubmit} className="mt-6 space-y-3">
          <div>
            <label className="text-xs text-fg-muted">Email</label>
            <Input
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1"
            />
          </div>
          <div>
            <label className="text-xs text-fg-muted">Password</label>
            <Input
              type="password"
              autoComplete="current-password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1"
            />
          </div>
          {error && (
            <div className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
              {error}
            </div>
          )}
          <Button type="submit" disabled={busy} size="lg" className="w-full">
            {busy ? "Signing in…" : (
              <>
                Continue <ArrowRight className="h-4 w-4" />
              </>
            )}
          </Button>
        </form>
        <div className="mt-8 text-[11px] text-fg-muted">
          Bootstrap an admin via <code className="text-fg">AI_RECON_BOOTSTRAP_ADMIN_*</code> env vars on the API.
        </div>
      </div>
    </main>
  );
}
