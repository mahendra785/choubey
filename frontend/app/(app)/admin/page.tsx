"use client";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { AuditVerify, Role } from "@/lib/types";
import { useAuth } from "@/components/auth";
import { ErrorBanner, PageHeader, StatusBadge, useLoad } from "@/components/ui";

const ROLES: Role[] = ["admin", "researcher", "viewer"];

export default function Admin() {
  const { user, can } = useAuth();
  const users = useLoad(() => (can("admin") ? api.users() : Promise.resolve([])), [user?.id]);
  const audit = useLoad(() => (can("admin") ? api.audit(100) : Promise.resolve([])), [user?.id]);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  if (!can("admin")) return <div className="card text-sm text-ink2">Admins only.</div>;

  const guard = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); } catch (e) { setError((e as Error).message); }
  };
  async function create(e: FormEvent) {
    e.preventDefault();
    await guard(async () => { await api.createUser(email, password, role); setEmail(""); setPassword(""); users.reload(); audit.reload(); });
  }

  return (
    <>
      <PageHeader title="Admin" subtitle="Users, roles, and the tamper-evident audit log." />
      <ErrorBanner error={error || users.error || audit.error} />
      <div className="grid gap-4 lg:grid-cols-[1fr_20rem]">
        <section className="card overflow-x-auto">
          <h2 className="mb-2 text-sm font-semibold">Users</h2>
          <table className="w-full min-w-[480px]">
            <thead><tr><th className="th">Email</th><th className="th">Role</th><th className="th">Active</th></tr></thead>
            <tbody>
              {(users.data ?? []).map((u) => (
                <tr key={u.id} className="border-t border-line">
                  <td className="td">{u.email}</td>
                  <td className="td">
                    <select aria-label={`Role of ${u.email}`} className="input w-36" value={u.role} disabled={u.id === user?.id}
                      onChange={(e) => guard(async () => { await api.setRole(u.id, e.target.value as Role); users.reload(); audit.reload(); })}>
                      {ROLES.map((r) => <option key={r}>{r}</option>)}
                    </select>
                  </td>
                  <td className="td">
                    <button className="btn-ghost" disabled={u.id === user?.id} onClick={() => guard(async () => { await api.setActive(u.id, !u.is_active); users.reload(); audit.reload(); })}>
                      {u.is_active ? "✓ active — deactivate" : "✕ disabled — enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <form onSubmit={create} className="card space-y-3">
          <h2 className="text-sm font-semibold">Create user</h2>
          <div><label className="label" htmlFor="nu-email">Email</label><input id="nu-email" className="input" type="email" required maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} /></div>
          <div><label className="label" htmlFor="nu-pw">Password (12+ chars)</label><input id="nu-pw" className="input" type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
          <div><label className="label" htmlFor="nu-role">Role</label><select id="nu-role" className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></div>
          <button className="btn w-full">Create</button>
        </form>
      </div>

      <section className="card mt-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">Audit log (newest first, hash-chained)</h2>
          <div className="flex items-center gap-2">
            {verify && (
              <span role="status">
                <StatusBadge ok={verify.valid} okLabel={`Chain intact (${verify.checked} records)`} badLabel={`TAMPERING DETECTED at record #${verify.broken_at_seq}`} />
                {!verify.valid && <span className="ml-2 text-xs text-bad">{verify.reason}</span>}
              </span>
            )}
            <button className="btn" onClick={() => guard(async () => { setVerify(await api.verifyAudit()); audit.reload(); })}>Verify chain</button>
          </div>
        </div>
        <div className="max-h-96 overflow-auto">
          <table className="w-full min-w-[720px]">
            <thead className="sticky top-0 bg-surface"><tr>{["#", "Time (UTC)", "Action", "Actor", "Detail", "Hash"].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {(audit.data ?? []).map((a) => (
                <tr key={a.seq} className={`border-t border-line ${verify && !verify.valid && a.seq === verify.broken_at_seq ? "bg-page text-bad" : ""}`}>
                  <td className="td">{a.seq}</td><td className="td whitespace-nowrap">{a.ts.slice(0, 19)}</td><td className="td font-medium">{a.action}</td>
                  <td className="td font-mono text-xs">{a.actor_id?.slice(0, 8) ?? "–"}</td><td className="td max-w-xs truncate font-mono text-xs" title={a.detail}>{a.detail}</td>
                  <td className="td font-mono text-xs">{a.hash.slice(0, 12)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
