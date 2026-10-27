"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "@/components/auth";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/attack-lab", label: "Attack Lab" },
  { href: "/defense-builder", label: "Defense Builder" },
  { href: "/experiments", label: "Experiments" },
  { href: "/conformal", label: "Conformal" },
  { href: "/admin", label: "Admin", admin: true },
];

function Shell({ children }: { children: ReactNode }) {
  const { user, loading, logout, can } = useAuth();
  const path = usePathname();
  if (loading) return <p className="p-6 text-sm text-muted">Loading…</p>;
  if (!user) return null; // redirecting to /login
  return (
    <div className="mx-auto max-w-6xl px-4 pb-10">
      <header className="flex flex-wrap items-center justify-between gap-2 py-3">
        <nav aria-label="Main" className="flex flex-wrap items-center gap-1">
          <span className="mr-3 text-base font-semibold">🛡 PromptShield</span>
          {NAV.filter((n) => !n.admin || can("admin")).map((n) => {
            const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
            return (
              <Link key={n.href} href={n.href} aria-current={active ? "page" : undefined}
                className={`rounded-md px-2.5 py-1 text-sm ${active ? "bg-accent text-accent-ink" : "text-ink2 hover:bg-surface"}`}>
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="flex items-center gap-2 text-sm text-ink2">
          <span>{user.email} · <span className="font-medium">{user.role}</span></span>
          <button className="btn-ghost" onClick={logout}>Sign out</button>
        </div>
      </header>
      <main>{children}</main>
    </div>
  );
}

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <Shell>{children}</Shell>
    </AuthProvider>
  );
}
