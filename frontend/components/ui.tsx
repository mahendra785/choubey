"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";

export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-2">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-ink2">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return <div role="alert" className="mb-3 rounded-md border border-bad px-3 py-2 text-sm text-bad">⚠ {error}</div>;
}

/** Status is never colour-only: icon + label. */
export function StatusBadge({ ok, okLabel, badLabel }: { ok: boolean; okLabel: string; badLabel: string }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${ok ? "border-good text-good" : "border-bad text-bad"}`}>
      <span aria-hidden>{ok ? "✓" : "✕"}</span>{ok ? okLabel : badLabel}
    </span>
  );
}

export const pct = (v: number | null | undefined, digits = 1) => (v == null ? "–" : `${(100 * v).toFixed(digits)}%`);
export const num = (v: number | null | undefined, digits = 1) => (v == null ? "–" : v.toFixed(digits));

/** Poll `fn` every `ms` while `active` is true (used for experiment progress). */
export function usePoll(fn: () => void, active: boolean, ms = 2000) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => ref.current(), ms);
    return () => clearInterval(t);
  }, [active, ms]);
}

/** Load async data with loading/error state. */
export function useLoad<T>(loader: () => Promise<T>, deps: unknown[]): { data: T | null; error: string | null; reload: () => void; loading: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    loader().then((d) => { if (live) { setData(d); setError(null); } })
      .catch((e: Error) => { if (live) setError(e.message); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}
