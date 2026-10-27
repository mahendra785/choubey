"use client";
import { useState } from "react";
import { api } from "@/lib/api";
import type { ConformalSummary, EndToEndSummary, ExperimentDetail, ResultRow } from "@/lib/types";
import { useAuth } from "@/components/auth";
import { Heatmap } from "@/components/Heatmap";
import { SummaryTable } from "@/components/SummaryTable";
import { ErrorBanner, PageHeader, pct, useLoad, usePoll } from "@/components/ui";

const TARGETS = ["rag_bot", "email_agent", "support_bot"];
const ALPHAS = [0.01, 0.05, 0.1, 0.2];

export default function Experiments() {
  const { can } = useAuth();
  const list = useLoad(() => api.experiments(), []);
  const presets = useLoad(() => api.presets(), []);
  const configs = useLoad(() => api.configs(), []);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // launch form
  const [name, setName] = useState("baseline-comparison");
  const [kind, setKind] = useState<"end_to_end" | "conformal_sweep">("end_to_end");
  const [targets, setTargets] = useState<string[]>(["support_bot"]);
  const [defenses, setDefenses] = useState<string[]>(["none", "sanitizer"]);
  const [benign, setBenign] = useState(true);
  const [variants, setVariants] = useState(0);
  const [maxPayloads, setMaxPayloads] = useState(30);
  const [benignN, setBenignN] = useState(30);
  const [seed, setSeed] = useState(1234);
  const [busy, setBusy] = useState(false);

  const running = (list.data ?? []).some((e) => e.status === "queued" || e.status === "running");
  usePoll(list.reload, running);
  const toggle = (arr: string[], v: string, set: (a: string[]) => void) => set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  const available = [...(presets.data ?? []).filter((p) => p.available).map((p) => p.name), ...(configs.data ?? []).map((c) => c.name)];

  async function launch() {
    setBusy(true); setError(null);
    try {
      const e = await api.createExperiment({ name, kind, targets, defenses, include_benign: benign, n_variants: variants, max_payloads: maxPayloads, benign_per_target: benignN, alphas: ALPHAS, seed });
      setSelected(e.id); list.reload();
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Experiments" subtitle="Launch a reproducible run (seeded) and inspect its results. All numbers come from recorded runs." />
      <ErrorBanner error={error || list.error} />
      <div className="grid gap-4 lg:grid-cols-[22rem_1fr]">
        <div className="space-y-4">
          {can("admin", "researcher") ? (
            <section className="card space-y-3">
              <h2 className="text-sm font-semibold">Launch experiment</h2>
              <div>
                <label className="label" htmlFor="ename">Name</label>
                <input id="ename" className="input" maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div>
                <label className="label" htmlFor="kind">Type</label>
                <select id="kind" className="input" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
                  <option value="end_to_end">End-to-end: targets × attacks × defenses</option>
                  <option value="conformal_sweep">Conformal sweep over α (detector test/OOD sets)</option>
                </select>
              </div>
              {kind === "end_to_end" && (
                <>
                  <fieldset>
                    <legend className="label">Targets</legend>
                    {TARGETS.map((t) => (
                      <label key={t} className="mr-3 inline-flex items-center gap-1 text-sm"><input type="checkbox" checked={targets.includes(t)} onChange={() => toggle(targets, t, setTargets)} />{t}</label>
                    ))}
                  </fieldset>
                  <fieldset>
                    <legend className="label">Defenses</legend>
                    <div className="max-h-40 overflow-y-auto">
                      {available.map((d) => (
                        <label key={d} className="mr-3 inline-flex items-center gap-1 text-sm"><input type="checkbox" checked={defenses.includes(d)} onChange={() => toggle(defenses, d, setDefenses)} />{d}</label>
                      ))}
                    </div>
                  </fieldset>
                  <div className="grid grid-cols-2 gap-2">
                    <div><label className="label" htmlFor="mp">Max attacks / target</label><input id="mp" className="input" type="number" min={1} max={1000} value={maxPayloads} onChange={(e) => setMaxPayloads(Number(e.target.value))} /></div>
                    <div><label className="label" htmlFor="nv">Mutations / payload</label><input id="nv" className="input" type="number" min={0} max={5} value={variants} onChange={(e) => setVariants(Number(e.target.value))} /></div>
                    <div><label className="label" htmlFor="bn">Benign / target</label><input id="bn" className="input" type="number" min={0} max={500} value={benignN} onChange={(e) => setBenignN(Number(e.target.value))} disabled={!benign} /></div>
                    <label className="mt-5 flex items-center gap-1 text-sm"><input type="checkbox" checked={benign} onChange={(e) => setBenign(e.target.checked)} />Include benign</label>
                  </div>
                </>
              )}
              <div><label className="label" htmlFor="seed">Seed</label><input id="seed" className="input" type="number" min={0} value={seed} onChange={(e) => setSeed(Number(e.target.value))} /></div>
              <button className="btn w-full" disabled={busy || !name.trim() || (kind === "end_to_end" && (!targets.length || !defenses.length))} onClick={launch}>{busy ? "Starting…" : "Launch"}</button>
            </section>
          ) : (
            <section className="card text-sm text-ink2">Viewers can read experiments that researchers have shared, but cannot launch them.</section>
          )}
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">Runs</h2>
            <ul className="space-y-2">
              {(list.data ?? []).map((e) => (
                <li key={e.id}>
                  <button onClick={() => setSelected(e.id)} className={`w-full rounded-md border p-2 text-left text-sm ${selected === e.id ? "border-accent" : "border-line"}`}>
                    <div className="flex justify-between gap-2"><span className="truncate font-medium">{e.name}</span><span className="text-xs">{statusIcon(e.status)} {e.status}</span></div>
                    <div className="text-xs text-muted">{e.kind} · {new Date(e.created_at).toLocaleString()}</div>
                    {(e.status === "running" || e.status === "queued") && (
                      <div className="mt-1 h-1.5 rounded bg-line" role="progressbar" aria-valuemin={0} aria-valuemax={e.total} aria-valuenow={e.completed}>
                        <div className="h-1.5 rounded bg-accent" style={{ width: `${e.total ? (100 * e.completed) / e.total : 5}%` }} />
                      </div>
                    )}
                  </button>
                </li>
              ))}
              {list.data?.length === 0 && <li className="text-sm text-muted">No experiments yet.</li>}
            </ul>
          </section>
        </div>
        <div>{selected ? <Detail id={selected} onChanged={list.reload} /> : <div className="card text-sm text-muted">Select a run to see its results.</div>}</div>
      </div>
    </>
  );
}

const statusIcon = (s: string) => ({ done: "✓", failed: "✕", running: "…", queued: "·" }[s] ?? "");

function Detail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const { user, can } = useAuth();
  const d = useLoad(() => api.experiment(id), [id]);
  const files = useLoad(() => api.files(id), [id, d.data?.status]);
  const [page, setPage] = useState(0);
  const results = useLoad(() => (d.data?.status === "done" && d.data.kind === "end_to_end" ? api.results(id, 15, page * 15) : Promise.resolve(null)), [id, page, d.data?.status]);
  usePoll(d.reload, d.data?.status === "running" || d.data?.status === "queued", 1500);
  const e: ExperimentDetail | null = d.data;
  if (!e) return <div className="card text-sm text-muted">{d.error ?? "Loading…"}</div>;
  const mine = user?.id === e.owner_id || user?.role === "admin";

  return (
    <div className="space-y-4">
      <section className="card">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-base font-semibold">{e.name}</h2>
          <span className="text-sm">{statusIcon(e.status)} {e.status} · {e.completed}/{e.total}</span>
        </div>
        <p className="text-xs text-muted">run {e.id} · model {e.model || "–"} · seed {e.seed}</p>
        {e.error && <p role="alert" className="mt-2 text-sm text-bad">⚠ {e.error}</p>}
        {mine && can("admin", "researcher") && (
          <label className="mt-2 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={e.shared} onChange={async (ev) => { await api.setShared(e.id, ev.target.checked); d.reload(); onChanged(); }} />
            Share read-only with viewers
          </label>
        )}
        {(files.data ?? []).length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {files.data!.map((f) => <a key={f} href={api.fileUrl(e.id, f)} className="btn-ghost text-xs" download>{f}</a>)}
          </div>
        )}
      </section>
      {e.summary && e.kind === "end_to_end" && <EndToEndView s={e.summary as EndToEndSummary} />}
      {e.summary && e.kind === "conformal_sweep" && <p className="card text-sm text-ink2">Conformal sweep finished ({(e.summary as ConformalSummary).classifier}). Open the <a className="underline" href="/conformal">Conformal view</a> for charts.</p>}
      {results.data && (
        <section className="card">
          <h3 className="mb-2 text-sm font-semibold">Raw runs ({results.data.total})</h3>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[700px]">
              <thead><tr className="border-b border-line">{["Kind", "Target", "Defense", "Payload", "Category", "Result", "ms", "Response (text)"].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>{results.data.items.map((r) => <RunRow key={r.id} r={r} />)}</tbody>
            </table>
          </div>
          <div className="mt-2 flex gap-2">
            <button className="btn-ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
            <button className="btn-ghost" disabled={(page + 1) * 15 >= results.data.total} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </section>
      )}
    </div>
  );
}

function RunRow({ r }: { r: ResultRow }) {
  const label = r.kind === "attack" ? (r.success ? "✕ attack succeeded" : r.blocked ? "🛑 blocked" : "✓ resisted") : r.blocked ? "✕ false positive" : "✓ served";
  return (
    <tr className="border-b border-line align-top">
      <td className="td">{r.kind}</td><td className="td">{r.target}</td><td className="td">{r.defense}</td><td className="td">{r.payload_id}</td>
      <td className="td">{r.category}</td><td className={`td ${r.success || (r.kind === "benign" && r.blocked) ? "text-bad" : ""}`}>{label}</td>
      <td className="td">{r.latency_ms}</td><td className="td max-w-xs truncate" title={r.response_text}>{r.response_text}</td>
    </tr>
  );
}

function EndToEndView({ s }: { s: EndToEndSummary }) {
  return (
    <>
      <section className="card">
        <h3 className="mb-2 text-sm font-semibold">ASR heatmap</h3>
        <Heatmap categories={s.heatmap.categories} defenses={s.heatmap.defenses} values={s.heatmap.asr} />
        {s.errors ? <p className="mt-2 text-xs text-warn">⚠ {s.errors} runs skipped because of LLM errors.</p> : null}
      </section>
      <section className="card">
        <h3 className="mb-2 text-sm font-semibold">Metrics ({pct(s.defenses[s.baseline]?.asr.rate)} baseline ASR)</h3>
        <SummaryTable summary={s} />
      </section>
    </>
  );
}
