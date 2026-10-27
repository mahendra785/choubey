"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { EndToEndSummary } from "@/lib/types";
import { Heatmap } from "@/components/Heatmap";
import { SummaryTable } from "@/components/SummaryTable";
import { ErrorBanner, PageHeader, useLoad } from "@/components/ui";

export default function Overview() {
  const list = useLoad(() => api.experiments("end_to_end"), []);
  const done = (list.data ?? []).filter((e) => e.status === "done");
  const [id, setId] = useState<string>("");
  const [target, setTarget] = useState<string>("");
  useEffect(() => { if (!id && done.length) setId(done[0].id); }, [done, id]);
  const detail = useLoad(() => (id ? api.experiment(id) : Promise.resolve(null)), [id]);
  const summary = detail.data?.summary as EndToEndSummary | null | undefined;
  const targets = summary ? Object.keys(summary.per_target) : [];

  // Heatmap values for the selected target slice (or all targets).
  const view = summary && target && summary.per_target[target]
    ? (() => {
        const defs = summary.heatmap.defenses.filter((d) => summary.per_target[target][d]);
        return { categories: summary.heatmap.categories, defenses: defs,
          values: summary.heatmap.categories.map((c) => defs.map((d) => summary.per_target[target][d].asr_by_category[c]?.rate ?? null)) };
      })()
    : summary ? { categories: summary.heatmap.categories, defenses: summary.heatmap.defenses, values: summary.heatmap.asr } : null;

  return (
    <>
      <PageHeader title="Overview" subtitle="Attack success rate (ASR) by attack category and defense. Success = canary leaked or forbidden tool executed.">
        <div className="flex gap-2">
          <select aria-label="Experiment" className="input w-64" value={id} onChange={(e) => { setId(e.target.value); setTarget(""); }}>
            {done.length === 0 && <option value="">No finished experiments</option>}
            {done.map((e) => <option key={e.id} value={e.id}>{e.name} · {new Date(e.created_at).toLocaleDateString()}</option>)}
          </select>
          <select aria-label="Target" className="input w-40" value={target} onChange={(e) => setTarget(e.target.value)} disabled={!targets.length}>
            <option value="">All targets</option>
            {targets.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </PageHeader>
      <ErrorBanner error={list.error || detail.error} />
      {!done.length && !list.loading && (
        <div className="card text-sm text-ink2">
          No finished experiments yet. {" "}
          <Link href="/experiments" className="font-medium text-accent underline">Launch one</Link> (researcher or admin role) or{" "}
          ask a researcher to share one with you.
        </div>
      )}
      {summary && view && (
        <div className="space-y-4">
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">ASR heatmap (lower is better)</h2>
            <Heatmap {...view} />
            <p className="mt-2 text-xs text-muted">Model: {detail.data?.model} · seed {detail.data?.seed} · run {detail.data?.id}</p>
          </section>
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">Table view — all metrics</h2>
            <SummaryTable summary={summary} target={target || undefined} />
          </section>
        </div>
      )}
    </>
  );
}
