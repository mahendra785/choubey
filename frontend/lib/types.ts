export type Role = "admin" | "researcher" | "viewer";

export interface User { id: string; email: string; role: Role; is_active: boolean }

export interface Rate { rate: number | null; n: number; ci_low: number | null; ci_high: number | null }

export interface DefenseSummary {
  n_attack: number; n_benign: number;
  asr: Rate; asr_by_category: Record<string, Rate>; asr_by_vector: Record<string, Rate>;
  asr_in_distribution: Rate; asr_ood: Rate; detection_tpr: Rate; fpr: Rate;
  precision: number | null; recall: number | null; f1: number | null; utility: number | null;
  utility_drop?: number | null; escalation_rate: number | null; llm_calls_per_request: number | null;
  defense_latency_ms_mean: number | null; defense_latency_ms_p95: number | null;
  latency_ms_mean: number | null; latency_ms_p95: number | null; latency_overhead_ms_mean?: number | null;
}

export interface EndToEndSummary {
  baseline: string; errors?: number;
  defenses: Record<string, DefenseSummary>;
  per_target: Record<string, Record<string, DefenseSummary>>;
  heatmap: { categories: string[]; defenses: string[]; asr: (number | null)[][] };
}

export interface ConformalRow {
  alpha: number; target_coverage: number; coverage: number; coverage_injection: number; coverage_benign: number;
  avg_set_size: number; escalation_rate: number;
}
export interface DetectionMetrics { tpr: number | null; fpr: number | null; f1: number | null; precision: number | null; n: number; latency_ms_mean?: number; llm_calls_per_request?: number }
export interface ConformalSummary {
  classifier: string | null; alphas: number[]; clf_latency_ms: number; n_calibration: number; judge_used: boolean; judge_error?: string;
  splits: Record<string, { n: number; rows: ConformalRow[]; "classifier_at_0.5": DetectionMetrics }>;
  detection: Record<string, {
    n: number; judge_only: DetectionMetrics; "classifier_at_0.5": DetectionMetrics;
    cascade: (DetectionMetrics & { alpha: number; escalation_rate: number; latency_ms_mean: number; latency_ms_p95: number })[];
  }>;
}

export interface ExperimentBrief {
  id: string; name: string; kind: "end_to_end" | "conformal_sweep"; status: "queued" | "running" | "done" | "failed";
  shared: boolean; owner_id: string; total: number; completed: number; model: string; seed: number;
  created_at: string; finished_at: string | null; error: string | null;
}
export interface ExperimentDetail extends ExperimentBrief { config: Record<string, unknown>; summary: EndToEndSummary | ConformalSummary | null }

export interface ResultRow {
  id: number; kind: string; target: string; defense: string; payload_id: string; category: string; vector: string; ood: boolean;
  success: boolean; canary_form: string | null; forbidden_tool: boolean; blocked: boolean; escalated: boolean;
  latency_ms: number; llm_calls: number; response_text: string;
}

export interface TargetInfo { name: string; kind: string; description: string; supports_indirect: boolean }
export interface AttackInfo {
  id: string; category: string; technique: string; vector: "direct" | "indirect"; text: string;
  multi_turn: string[] | null; target_compat: string[]; user_query: string | null; ood: boolean;
}
export interface Preset { name: string; stages: Stage[]; available: boolean }
export interface Stage { type: string; [param: string]: unknown }
export interface SavedConfig { id: string; name: string; config: { stages: Stage[] }; owner_id: string }
export interface DetectorInfo { classifier: string | null; calibration_n: number | null; alphas: number[]; llm_configured: boolean }

export interface Decision { defense: string; action: string; score: number; reason: string; latency_ms: number; extra: Record<string, unknown> }
export interface ToolCallOut { tool: string; arguments: Record<string, unknown>; forbidden: boolean; result: string }
export interface LabTurn {
  text: string; blocked: boolean; blocked_by: string | null; decisions: Decision[]; tool_calls: ToolCallOut[];
  canary_spans: [number, number][]; latency_ms: number;
}
export interface LabResult {
  payload: { id: string; category: string; text: string; turns: string[] };
  success: boolean; canary_leaked: boolean; canary_form: string | null; forbidden_tool_called: boolean;
  blocked: boolean; escalated: boolean; llm_calls: number; latency_ms: number; turns: LabTurn[];
}

export interface AuditEntry { seq: number; ts: string; actor_id: string | null; action: string; detail: string; hash: string }
export interface AuditVerify { valid: boolean; checked: number; broken_at_seq: number | null; reason: string | null }
