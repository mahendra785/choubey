"use client";
import { useEffect, useState, type ReactNode } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "@/lib/api";
import type { ConformalSummary } from "@/lib/types";
import { ErrorBanner, PageHeader, num, pct, useLoad } from "@/components/ui";

const C = { s1: "var(--s1)", s2: "var(--s2)", s3: "var(--s3)", grid: "var(--line)", axis: "var(--muted)" };
const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)", fontSize: 12 };

interface Series { key: string; label: string; color: string; dashed?: boolean }

/** Line chart with a legend, a hover crosshair/tooltip, and a table view of the same data (accessibility). */
function LineCard({ title, note, data, series, yFormat, yDomain, xLabel, yLabel }: {
  title: string; note?: ReactNode; data: Record<string, number | null>[]; series: Series[];
  yFormat: (v: number) => string; yDomain?: [number, number]; xLabel: string; yLabel: string;
}) {
  const [table, setTable] = useState(false);
  return (
    <section className="card">
      <div className="mb-1 flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        <button className="btn-ghost px-2 py-0.5 text-xs" aria-pressed={table} onClick={() => setTable(!table)}>{table ? "Chart" : "Table"} view</button>
      </div>
      {note && <p className="mb-2 text-xs text-ink2">{note}</p>}
      {table ? (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead><tr><th className="th">α</th>{series.map((s) => <th key={s.key} className="th">{s.label}</th>)}</tr></thead>
            <tbody>{data.map((r) => (
              <tr key={String(r.alpha)} className="border-t border-line"><td className="td">{r.alpha}</td>{series.map((s) => <td key={s.key} className="td">{r[s.key] == null ? "–" : yFormat(r[s.key] as number)}</td>)}</tr>
            ))}</tbody>
          </table>
        </div>
      ) : (
        <div style={{ height: 260 }} role="img" aria-label={`${title}. Use the table view for exact values.`}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 8, right: 16, bottom: 20, left: 4 }}>
              <CartesianGrid stroke={C.grid} strokeWidth={0.6} vertical={false} />
              <XAxis dataKey="alpha" type="number" domain={["dataMin", "dataMax"]} ticks={data.map((d) => d.alpha as number)} stroke={C.axis} tick={{ fontSize: 11 }} label={{ value: xLabel, position: "insideBottom", offset: -12, fontSize: 11, fill: "var(--ink2)" }} />
              <YAxis stroke={C.axis} tick={{ fontSize: 11 }} tickFormatter={yFormat} domain={yDomain ?? ["auto", "auto"]} width={52} label={{ value: yLabel, angle: -90, position: "insideLeft", fontSize: 11, fill: "var(--ink2)" }} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => (typeof v === "number" ? yFormat(v) : String(v))} labelFormatter={(l) => `α = ${l}`} cursor={{ stroke: "var(--axis)", strokeWidth: 1 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {series.map((s) => (
                <Line key={s.key} dataKey={s.key} name={s.label} stroke={s.color} strokeWidth={2} strokeDasharray={s.dashed ? "5 4" : undefined}
                  dot={s.dashed ? false : { r: 4, strokeWidth: 2, stroke: "var(--surface)", fill: s.color }} activeDot={{ r: 5 }} connectNulls isAnimationActive={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}

export default function ConformalView() {
  const list = useLoad(() => api.experiments("conformal_sweep"), []);
  const done = (list.data ?? []).filter((e) => e.status === "done");
  const [id, setId] = useState("");
  const [split, setSplit] = useState("test");
  useEffect(() => { if (!id && done.length) setId(done[0].id); }, [done, id]);
  const det = useLoad(() => (id ? api.experiment(id) : Promise.resolve(null)), [id]);
  const s = det.data?.summary as ConformalSummary | null | undefined;
  const splits = s ? Object.keys(s.splits) : [];
  useEffect(() => { if (s && !s.splits[split]) setSplit(Object.keys(s.splits)[0]); }, [s, split]);
  const sp = s?.splits[split];
  const dt = s?.detection?.[split];

  const covData = sp?.rows.map((r) => ({ alpha: r.alpha, target: r.target_coverage, injection: r.coverage_injection, benign: r.coverage_benign })) ?? [];
  const escData = sp?.rows.map((r) => ({ alpha: r.alpha, escalation: r.escalation_rate, setsize: r.avg_set_size })) ?? [];
  const latData = dt?.cascade.map((c) => ({ alpha: c.alpha, cascade: c.latency_ms_mean, judge: dt.judge_only.latency_ms_mean ?? null, clf: s?.clf_latency_ms ?? null })) ?? [];
  const f1Data = dt?.cascade.map((c) => ({ alpha: c.alpha, cascade: c.f1, judge: dt.judge_only.f1, clf: dt["classifier_at_0.5"].f1 })) ?? [];

  return (
    <>
      <PageHeader title="Conformal view" subtitle="Does the gate deliver the promised coverage, and what does it cost in judge calls and latency?">
        <div className="flex gap-2">
          <select aria-label="Sweep" className="input w-64" value={id} onChange={(e) => setId(e.target.value)}>
            {done.length === 0 && <option>No finished sweeps</option>}
            {done.map((e) => <option key={e.id} value={e.id}>{e.name} · {new Date(e.created_at).toLocaleDateString()}</option>)}
          </select>
          <select aria-label="Split" className="input w-44" value={split} onChange={(e) => setSplit(e.target.value)}>
            {splits.map((x) => <option key={x} value={x}>{x === "ood" ? "OOD (unseen categories)" : "test (in-distribution)"}</option>)}
          </select>
        </div>
      </PageHeader>
      <ErrorBanner error={list.error || det.error} />
      {!done.length && !list.loading && <div className="card text-sm text-ink2">No conformal sweep yet. Train the detector (<code>ml/train_detector.py</code>, <code>ml/calibrate.py</code>) and launch a “Conformal sweep” on the Experiments page.</div>}
      {s && sp && (
        <div className="space-y-4">
          <p className="text-xs text-muted">Classifier: {s.classifier} · calibration n = {s.n_calibration} · eval n = {sp.n} · single-text CPU latency {num(s.clf_latency_ms)} ms · judge {s.judge_used ? "used" : s.judge_error ? `unavailable (${s.judge_error})` : "not used"}</p>
          <div className="grid gap-4 lg:grid-cols-2">
            <LineCard title="Empirical coverage vs. target (1 − α)" xLabel="α" yLabel="coverage" data={covData} yFormat={(v) => pct(v, 1)} yDomain={[0.6, 1]}
              note="The guarantee: the injection-class line should sit on or above the dashed target. Under distribution shift (OOD) it may fall below."
              series={[{ key: "target", label: "target 1−α", color: "var(--muted)", dashed: true }, { key: "injection", label: "injection class", color: C.s1 }, { key: "benign", label: "benign class", color: C.s2 }]} />
            <LineCard title="Escalation rate vs. α" xLabel="α" yLabel="escalated to judge" data={escData} yFormat={(v) => pct(v, 0)}
              note="Share of inputs the classifier is not sure about (prediction set has 0 or 2 labels). Smaller α → stronger guarantee → more escalation."
              series={[{ key: "escalation", label: "escalation rate", color: C.s1 }]} />
            <LineCard title="Average prediction-set size vs. α" xLabel="α" yLabel="set size" data={escData} yFormat={(v) => v.toFixed(2)}
              series={[{ key: "setsize", label: "avg set size", color: C.s3 }]} />
            {dt ? (
              <LineCard title="Mean latency per request vs. α" xLabel="α" yLabel="ms" data={latData} yFormat={(v) => `${v.toFixed(0)} ms`}
                note={`Measured on ${dt.n} sampled inputs. Cascade = classifier + judge only when escalated.`}
                series={[{ key: "judge", label: "judge only", color: C.s2, dashed: true }, { key: "cascade", label: "cascade", color: C.s1 }, { key: "clf", label: "classifier only", color: C.s3, dashed: true }]} />
            ) : <section className="card text-sm text-ink2">Latency/detection comparison needs an LLM judge during the sweep (none was available for this run).</section>}
            {dt && (
              <LineCard title="Detection F1 vs. α" xLabel="α" yLabel="F1" data={f1Data} yFormat={(v) => v.toFixed(3)} yDomain={[0, 1]}
                series={[{ key: "judge", label: "judge only", color: C.s2, dashed: true }, { key: "cascade", label: "cascade", color: C.s1 }, { key: "clf", label: "classifier @ 0.5", color: C.s3, dashed: true }]} />
            )}
          </div>
          <section className="card overflow-x-auto">
            <h2 className="mb-2 text-sm font-semibold">All numbers ({split})</h2>
            <table className="w-full min-w-[640px]">
              <thead><tr>{["α", "target", "coverage", "injection cov.", "benign cov.", "set size", "escalation"].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>{sp.rows.map((r) => (
                <tr key={r.alpha} className="border-t border-line">
                  <td className="td">{r.alpha}</td><td className="td">{pct(r.target_coverage)}</td><td className="td">{pct(r.coverage)}</td>
                  <td className={`td ${r.coverage_injection < r.target_coverage ? "text-bad" : ""}`}>{r.coverage_injection < r.target_coverage ? "✕ " : "✓ "}{pct(r.coverage_injection)}</td>
                  <td className="td">{pct(r.coverage_benign)}</td><td className="td">{num(r.avg_set_size, 2)}</td><td className="td">{pct(r.escalation_rate)}</td>
                </tr>))}</tbody>
            </table>
          </section>
        </div>
      )}
    </>
  );
}
