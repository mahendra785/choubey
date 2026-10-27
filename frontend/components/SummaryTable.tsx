"use client";
import type { EndToEndSummary, Rate } from "@/lib/types";
import { num, pct } from "./ui";

const ci = (r: Rate) => (r.rate == null ? "–" : `${pct(r.rate)} [${pct(r.ci_low, 0)}–${pct(r.ci_high, 0)}]`);

/** Per-defense metrics. Also doubles as the accessible "table view" of the heatmap's data. */
export function SummaryTable({ summary, target }: { summary: EndToEndSummary; target?: string }) {
  const rows = target ? summary.per_target[target] ?? {} : summary.defenses;
  const names = summary.heatmap.defenses.filter((d) => rows[d]);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] border-collapse">
        <caption className="sr-only">Metrics per defense configuration</caption>
        <thead>
          <tr className="border-b border-line">
            {["Defense", "ASR [95% CI]", "ASR in-dist", "ASR OOD", "Detect TPR", "FPR [95% CI]", "F1", "Utility", "Defense ms (mean / p95)", "LLM calls/req", "Escalated"].map((h) => (
              <th key={h} className="th">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {names.map((d) => {
            const s = rows[d];
            return (
              <tr key={d} className="border-b border-line">
                <th scope="row" className="td text-left font-medium">{d}</th>
                <td className="td">{ci(s.asr)}</td>
                <td className="td">{pct(s.asr_in_distribution.rate)}</td>
                <td className="td">{pct(s.asr_ood.rate)}</td>
                <td className="td">{pct(s.detection_tpr.rate)}</td>
                <td className="td">{ci(s.fpr)}</td>
                <td className="td">{num(s.f1, 2)}</td>
                <td className="td">{pct(s.utility)}</td>
                <td className="td">{num(s.defense_latency_ms_mean)} / {num(s.defense_latency_ms_p95)}</td>
                <td className="td">{num(s.llm_calls_per_request, 2)}</td>
                <td className="td">{pct(s.escalation_rate)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
