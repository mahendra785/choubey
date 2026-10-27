"use client";
import { useState } from "react";

const RAMP = ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"];

function rampColor(v: number): string {
  const x = Math.min(1, Math.max(0, v)) * (RAMP.length - 1);
  return RAMP[Math.round(x)];
}

/** Category x defense heatmap of attack success rate. One-hue sequential ramp; every cell shows its number
 *  (so colour is never the only channel) and has a hover tooltip. */
export function Heatmap({ categories, defenses, values }: { categories: string[]; defenses: string[]; values: (number | null)[][] }) {
  const [tip, setTip] = useState<{ c: string; d: string; v: number | null } | null>(null);
  if (!categories.length) return <p className="text-sm text-muted">No attack runs in this experiment.</p>;
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="border-separate" style={{ borderSpacing: 2 }}>
          <thead>
            <tr>
              <th />
              {defenses.map((d) => (
                <th key={d} className="px-1 pb-1 text-left align-bottom text-xs font-medium text-ink2" style={{ minWidth: 64 }}>{d}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {categories.map((c, i) => (
              <tr key={c}>
                <th scope="row" className="whitespace-nowrap pr-2 text-right text-xs font-medium text-ink2">{c}</th>
                {defenses.map((d, j) => {
                  const v = values[i]?.[j] ?? null;
                  return (
                    <td
                      key={d}
                      tabIndex={0}
                      onMouseEnter={() => setTip({ c, d, v })}
                      onFocus={() => setTip({ c, d, v })}
                      onMouseLeave={() => setTip(null)}
                      onBlur={() => setTip(null)}
                      className="h-9 rounded-sm text-center text-xs font-medium"
                      style={{ background: v == null ? "transparent" : rampColor(v), color: v != null && v > 0.45 ? "#fff" : "#0b0b0b", border: v == null ? "1px dashed var(--line)" : undefined }}
                    >
                      {v == null ? "–" : Math.round(v * 100)}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-2 flex items-center gap-3 text-xs text-ink2" aria-live="polite">
        <span className="flex items-center gap-1">
          0% {RAMP.map((r) => <span key={r} className="inline-block h-3 w-5" style={{ background: r }} />)} 100% attack success rate
        </span>
        <span className="min-h-4">{tip ? `${tip.c} × ${tip.d}: ${tip.v == null ? "no runs" : (tip.v * 100).toFixed(1) + "% of attacks succeeded"}` : "Hover or focus a cell for details."}</span>
      </div>
    </div>
  );
}
