"use client";
import { useState } from "react";
import { api } from "@/lib/api";
import type { Stage } from "@/lib/types";
import { useAuth } from "@/components/auth";
import { ErrorBanner, PageHeader, StatusBadge, useLoad } from "@/components/ui";

const STAGE_TYPES: { type: string; label: string; help: string; defaults: Stage }[] = [
  { type: "sanitizer", label: "Sanitizer", help: "Unicode normalisation, decode-and-rescan, heuristic rules.", defaults: { type: "sanitizer", threshold: 0.5 } },
  { type: "spotlighting", label: "Spotlighting", help: "Randomised delimiters + datamarking for untrusted documents/e-mails.", defaults: { type: "spotlighting", datamark: true } },
  { type: "classifier", label: "Classifier", help: "DeBERTa/TF-IDF detector at a fixed probability threshold.", defaults: { type: "classifier", threshold: 0.5 } },
  { type: "llm_judge", label: "LLM judge", help: "Every input is judged by an LLM (slow, strong).", defaults: { type: "llm_judge" } },
  { type: "cascade", label: "Conformal cascade", help: "Classifier + conformal gate; only uncertain inputs go to the judge.", defaults: { type: "cascade", alpha: 0.1 } },
  { type: "output_guard", label: "Output guard", help: "Blocks secret-shaped output and forbidden tool calls.", defaults: { type: "output_guard", use_known_secrets: false } },
];
const ALPHAS = [0.01, 0.05, 0.1, 0.2];

export default function DefenseBuilder() {
  const { can } = useAuth();
  const presets = useLoad(() => api.presets(), []);
  const detector = useLoad(() => api.detector(), []);
  const configs = useLoad(() => api.configs(), []);
  const [stages, setStages] = useState<Stage[]>([{ type: "sanitizer", threshold: 0.5 }, { type: "cascade", alpha: 0.1 }, { type: "output_guard", use_known_secrets: false }]);
  const [name, setName] = useState("my-pipeline");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const update = (i: number, patch: Partial<Stage>) => setStages((s) => s.map((st, k) => (k === i ? { ...st, ...patch } : st)));
  const move = (i: number, d: -1 | 1) => setStages((s) => {
    const j = i + d;
    if (j < 0 || j >= s.length) return s;
    const c = [...s]; [c[i], c[j]] = [c[j], c[i]]; return c;
  });
  const needsDetector = stages.some((s) => s.type === "classifier" || s.type === "cascade");
  const detectorOk = !!detector.data?.classifier && detector.data.calibration_n != null;

  async function save() {
    setError(null); setSaved(null);
    try { await api.saveConfig(name, stages); setSaved(`Saved “${name}”. It now appears in the Attack Lab and Experiments.`); configs.reload(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <>
      <PageHeader title="Defense Builder" subtitle="Compose a pipeline. Stages run top to bottom on every input; the first block wins. Output guard runs on the model's output." />
      <ErrorBanner error={error || presets.error} />
      {saved && <div className="mb-3 rounded-md border border-good px-3 py-2 text-sm text-good">✓ {saved}</div>}
      <div className="grid gap-4 lg:grid-cols-[1fr_20rem]">
        <section className="card space-y-3">
          <div className="flex flex-wrap gap-2">
            {STAGE_TYPES.map((t) => (
              <button key={t.type} className="btn-ghost" title={t.help} onClick={() => setStages((s) => [...s, { ...t.defaults }])} disabled={stages.length >= 8}>+ {t.label}</button>
            ))}
          </div>
          <ol className="space-y-2">
            {stages.map((st, i) => {
              const meta = STAGE_TYPES.find((t) => t.type === st.type)!;
              return (
                <li key={i} className="rounded-md border border-line p-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium">{i + 1}. {meta.label}</span>
                    <span className="flex gap-1">
                      <button className="btn-ghost px-2" aria-label="Move up" onClick={() => move(i, -1)} disabled={i === 0}>↑</button>
                      <button className="btn-ghost px-2" aria-label="Move down" onClick={() => move(i, 1)} disabled={i === stages.length - 1}>↓</button>
                      <button className="btn-ghost px-2" aria-label="Remove stage" onClick={() => setStages((s) => s.filter((_, k) => k !== i))}>✕</button>
                    </span>
                  </div>
                  <p className="text-xs text-muted">{meta.help}</p>
                  {st.type === "cascade" && (
                    <div className="mt-2 flex items-center gap-2 text-sm">
                      <span className="text-xs text-ink2">α (miss-rate budget on the injection class):</span>
                      {ALPHAS.map((a) => (
                        <button key={a} onClick={() => update(i, { alpha: a })} aria-pressed={st.alpha === a} className={st.alpha === a ? "btn px-2 py-0.5" : "btn-ghost px-2 py-0.5"}>{a}</button>
                      ))}
                      <span className="text-xs text-muted">→ target injection coverage {(100 * (1 - Number(st.alpha))).toFixed(0)}%</span>
                    </div>
                  )}
                  {(st.type === "classifier" || st.type === "sanitizer") && (
                    <div className="mt-2 flex items-center gap-2 text-sm">
                      <label className="text-xs text-ink2" htmlFor={`thr${i}`}>Block threshold</label>
                      <input id={`thr${i}`} type="range" min={0.1} max={0.95} step={0.05} value={Number(st.threshold)} onChange={(e) => update(i, { threshold: Number(e.target.value) })} />
                      <span className="text-xs">{Number(st.threshold).toFixed(2)}</span>
                    </div>
                  )}
                  {st.type === "output_guard" && (
                    <label className="mt-2 flex items-center gap-2 text-xs text-ink2">
                      <input type="checkbox" checked={!!st.use_known_secrets} onChange={(e) => update(i, { use_known_secrets: e.target.checked })} />
                      Also block registered secrets in any encoding (strong but assumes you know every secret)
                    </label>
                  )}
                  {st.type === "spotlighting" && (
                    <label className="mt-2 flex items-center gap-2 text-xs text-ink2">
                      <input type="checkbox" checked={!!st.datamark} onChange={(e) => update(i, { datamark: e.target.checked })} /> Datamarking
                    </label>
                  )}
                </li>
              );
            })}
            {stages.length === 0 && <li className="text-sm text-muted">No stages = the undefended baseline.</li>}
          </ol>
          {needsDetector && !detectorOk && (
            <p className="text-sm text-warn">⚠ This pipeline needs a trained detector + calibration (run <code>ml/train_detector.py</code> and <code>ml/calibrate.py</code>); it cannot run until they exist.</p>
          )}
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-48 flex-1">
              <label className="label" htmlFor="cfgname">Name</label>
              <input id="cfgname" className="input" maxLength={80} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <button className="btn" onClick={save} disabled={!name.trim() || !can("admin", "researcher")}>Save pipeline</button>
          </div>
          <pre className="overflow-x-auto rounded-md border border-line p-2 text-xs">{JSON.stringify({ stages }, null, 2)}</pre>
        </section>

        <aside className="space-y-4">
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">Detector status</h2>
            <p className="text-sm">Classifier: {detector.data?.classifier ?? "not trained"}</p>
            <p className="text-sm">Calibration set: {detector.data?.calibration_n ?? "–"}</p>
            <p className="text-sm">LLM: {detector.data?.llm_configured ? "configured" : "missing"}</p>
          </section>
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">Saved pipelines</h2>
            <ul className="space-y-1 text-sm">
              {(configs.data ?? []).map((c) => (
                <li key={c.id} className="flex items-center justify-between gap-2">
                  <button className="truncate text-left underline" onClick={() => { setName(c.name); setStages(c.config.stages); }}>{c.name}</button>
                  <button className="btn-ghost px-2 py-0.5" aria-label={`Delete ${c.name}`} onClick={async () => { await api.deleteConfig(c.id); configs.reload(); }}>✕</button>
                </li>
              ))}
              {configs.data?.length === 0 && <li className="text-muted">None yet.</li>}
            </ul>
          </section>
          <section className="card">
            <h2 className="mb-2 text-sm font-semibold">Built-in presets</h2>
            <ul className="space-y-1 text-sm">
              {(presets.data ?? []).map((p) => (
                <li key={p.name} className="flex items-center justify-between gap-2">
                  <button className="truncate text-left underline" onClick={() => setStages(p.stages)}>{p.name}</button>
                  <StatusBadge ok={p.available} okLabel="ready" badLabel="needs detector" />
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </>
  );
}
