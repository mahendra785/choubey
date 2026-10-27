"use client";
import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { LabResult } from "@/lib/types";
import { useAuth } from "@/components/auth";
import { CanaryText } from "@/components/CanaryText";
import { ErrorBanner, PageHeader, StatusBadge, useLoad } from "@/components/ui";

export default function AttackLab() {
  const { can } = useAuth();
  const targets = useLoad(() => api.targets(), []);
  const attacks = useLoad(() => api.attacks(), []);
  const presets = useLoad(() => api.presets(), []);
  const configs = useLoad(() => api.configs(), []);

  const [target, setTarget] = useState("support_bot");
  const [mode, setMode] = useState<"library" | "custom">("library");
  const [payloadId, setPayloadId] = useState("do-01");
  const [custom, setCustom] = useState("");
  const [vector, setVector] = useState<"direct" | "indirect">("direct");
  const [userQuery, setUserQuery] = useState("");
  const [defense, setDefense] = useState("none");
  const [alpha, setAlpha] = useState<number | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LabResult | null>(null);

  const compatible = useMemo(() => (attacks.data ?? []).filter((a) => a.target_compat.includes(target)), [attacks.data, target]);
  const selected = compatible.find((a) => a.id === payloadId) ?? compatible[0];
  const defenseNames = [...(presets.data ?? []).filter((p) => p.available).map((p) => p.name), ...(configs.data ?? []).map((c) => c.name)];
  const isCascade = defense.startsWith("cascade");

  async function run() {
    setBusy(true); setError(null); setResult(null);
    try {
      setResult(await api.runLab({
        target, defense, vector: mode === "custom" ? vector : "direct",
        ...(mode === "library" ? { payload_id: selected?.id } : { custom_text: custom, user_query: userQuery || undefined }),
        ...(isCascade && alpha !== "" ? { alpha: Number(alpha) } : {}),
      }));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Attack Lab" subtitle="Fire one payload at a target app with a chosen defense. Each run gets a fresh random canary." />
      <ErrorBanner error={error || targets.error || attacks.error} />
      {!can("admin", "researcher") && <div className="card mb-3 text-sm text-ink2">Your role is read-only: running attacks needs researcher or admin.</div>}
      <div className="grid gap-4 lg:grid-cols-[22rem_1fr]">
        <section className="card space-y-3">
          <div>
            <label className="label" htmlFor="target">Target</label>
            <select id="target" className="input" value={target} onChange={(e) => setTarget(e.target.value)}>
              {(targets.data ?? []).map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
            </select>
            <p className="mt-1 text-xs text-muted">{targets.data?.find((t) => t.name === target)?.description}</p>
          </div>
          <div className="flex gap-2" role="radiogroup" aria-label="Payload source">
            {(["library", "custom"] as const).map((m) => (
              <button key={m} role="radio" aria-checked={mode === m} onClick={() => setMode(m)} className={mode === m ? "btn" : "btn-ghost"}>{m === "library" ? "Payload library" : "Custom text"}</button>
            ))}
          </div>
          {mode === "library" ? (
            <div>
              <label className="label" htmlFor="payload">Payload ({compatible.length} compatible)</label>
              <select id="payload" className="input" value={selected?.id ?? ""} onChange={(e) => setPayloadId(e.target.value)}>
                {compatible.map((a) => <option key={a.id} value={a.id}>{a.id} · {a.category} · {a.technique}</option>)}
              </select>
              {selected && (
                <div className="mt-2 rounded-md border border-line p-2 text-xs text-ink2">
                  <p className="mb-1 font-medium">{selected.vector} injection{selected.multi_turn ? ` · ${selected.multi_turn.length} turns` : ""}{selected.ood ? " · OOD category" : ""}</p>
                  {/* rendered as text, never HTML */}
                  <p className="whitespace-pre-wrap break-words">{(selected.multi_turn ?? [selected.text]).join("\n— next turn —\n")}</p>
                </div>
              )}
            </div>
          ) : (
            <>
              <div>
                <label className="label" htmlFor="custom">Your payload (max 4000 chars)</label>
                <textarea id="custom" className="input h-28" maxLength={4000} value={custom} onChange={(e) => setCustom(e.target.value)} />
              </div>
              <div>
                <label className="label" htmlFor="vector">Delivery</label>
                <select id="vector" className="input" value={vector} onChange={(e) => setVector(e.target.value as "direct" | "indirect")}>
                  <option value="direct">Direct (as the user's message)</option>
                  <option value="indirect" disabled={!targets.data?.find((t) => t.name === target)?.supports_indirect}>Indirect (planted in a document / e-mail)</option>
                </select>
              </div>
              {vector === "indirect" && (
                <div>
                  <label className="label" htmlFor="uq">Innocent user request that triggers reading it</label>
                  <input id="uq" className="input" maxLength={1000} value={userQuery} onChange={(e) => setUserQuery(e.target.value)} placeholder="e.g. Summarize my inbox." />
                </div>
              )}
            </>
          )}
          <div>
            <label className="label" htmlFor="defense">Defense</label>
            <select id="defense" className="input" value={defense} onChange={(e) => setDefense(e.target.value)}>
              {defenseNames.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          {isCascade && (
            <div>
              <label className="label" htmlFor="alpha">Conformal α override (optional)</label>
              <input id="alpha" className="input" type="number" min={0.001} max={0.5} step={0.01} value={alpha} onChange={(e) => setAlpha(e.target.value === "" ? "" : Number(e.target.value))} />
            </div>
          )}
          <button className="btn w-full" disabled={busy || !can("admin", "researcher") || (mode === "custom" && !custom.trim())} onClick={run}>{busy ? "Running…" : "Run attack"}</button>
        </section>

        <section className="space-y-3">
          {!result && !busy && <div className="card text-sm text-muted">Results appear here.</div>}
          {busy && <div className="card text-sm text-muted" aria-live="polite">Waiting for the model…</div>}
          {result && (
            <>
              <div className="card flex flex-wrap items-center gap-3">
                <StatusBadge ok={!result.success} okLabel="Attack failed — defended" badLabel="Attack SUCCEEDED" />
                {result.blocked && <span className="rounded-full border border-line px-2 py-0.5 text-xs">🛑 blocked by defense</span>}
                {result.escalated && <span className="rounded-full border border-line px-2 py-0.5 text-xs">↗ escalated to judge</span>}
                {result.canary_leaked && <span className="text-xs text-bad">canary leaked ({result.canary_form})</span>}
                {result.forbidden_tool_called && <span className="text-xs text-bad">forbidden tool executed</span>}
                <span className="ml-auto text-xs text-muted">{result.latency_ms} ms · {result.llm_calls} LLM calls</span>
              </div>
              {result.turns.map((t, i) => (
                <div key={i} className="card space-y-2">
                  <h3 className="text-xs font-semibold text-muted">
                    Turn {i + 1}
                  </h3>
                  <div className="rounded-md border border-line p-2 text-xs text-ink2">
                    <span className="font-medium">User: </span><span className="whitespace-pre-wrap break-words">{result.payload.turns[i] ?? ""}</span>
                  </div>
                  <div>
                    <h4 className="mb-1 text-xs font-semibold text-muted">Response</h4>
                    <CanaryText text={t.text} spans={t.canary_spans} />
                  </div>
                  {t.tool_calls.length > 0 && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold text-muted">Tool calls (mock — nothing real happens)</h4>
                      <ul className="space-y-1 text-xs">
                        {t.tool_calls.map((c, k) => (
                          <li key={k} className={`rounded border px-2 py-1 ${c.forbidden ? "border-bad text-bad" : "border-line"}`}>
                            {c.forbidden ? "⛔ FORBIDDEN " : "🔧 "}<span className="font-medium">{c.tool}</span>({JSON.stringify(c.arguments)}) → {c.result}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {t.decisions.length > 0 && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold text-muted">Defense decisions</h4>
                      <ul className="space-y-1 text-xs">
                        {t.decisions.map((d, k) => (
                          <li key={k} className="rounded border border-line px-2 py-1">
                            <span className="font-medium">{d.defense}</span> → {d.action} (score {d.score.toFixed(2)}, {d.latency_ms.toFixed(1)} ms) — {d.reason}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </section>
      </div>
    </>
  );
}
