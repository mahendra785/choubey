"""Export experiment results for the paper/report: CSV, LaTeX tables, PNG plots.

Every file records run id, model, seed and timestamp:
  CSV   -> leading '# key: value' comment lines;   LaTeX -> '% key: value' lines;
  PNG   -> text in the PNG metadata AND a small footer line inside the figure.
Plot colours follow the project's validated palette (blue / orange / aqua = categorical slots 1-3, blue ramp for
magnitude); grids are hairline and recessive; no dual axes.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#fcfcfb"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
SEQ = LinearSegmentedColormap.from_list("blue_seq", ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"])
plt.rcParams.update({"font.family": "sans-serif", "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": MUTED,
                     "ytick.color": MUTED, "text.color": INK, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
                     "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6})


def _meta_lines(meta: dict[str, Any]) -> list[tuple[str, str]]:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return [("run_id", str(meta.get("run_id"))), ("model", str(meta.get("model"))), ("seed", str(meta.get("seed"))), ("timestamp", stamp)]


def write_csv(path: Path, header: list[str], rows: list[list[Any]], meta: dict[str, Any]) -> None:
    buf = io.StringIO()
    for k, v in _meta_lines(meta):
        buf.write(f"# {k}: {v}\n")
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def _pct(x: Any) -> str:
    return "--" if x is None else f"{100 * x:.1f}"


def _tex_escape(s: str) -> str:
    return s.replace("\\", "").replace("_", r"\_").replace("%", r"\%").replace("&", r"\&").replace("#", r"\#")


def write_tex(path: Path, caption: str, label: str, header: list[str], rows: list[list[str]], meta: dict[str, Any]) -> None:
    lines = [f"% {k}: {v}" for k, v in _meta_lines(meta)]
    lines += [r"\begin{table}[ht]", r"\centering", rf"\caption{{{_tex_escape(caption)}}}", rf"\label{{{label}}}",
              r"\begin{tabular}{l" + "r" * (len(header) - 1) + "}", r"\hline",
              " & ".join(_tex_escape(h) for h in header) + r" \\", r"\hline"]
    lines += [" & ".join(_tex_escape(str(c)) for c in r) + r" \\" for r in rows]
    lines += [r"\hline", r"\end{tabular}", r"\end{table}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _save(fig: plt.Figure, path: Path, meta: dict[str, Any]) -> None:
    footer = " | ".join(f"{k}={v}" for k, v in _meta_lines(meta))
    fig.tight_layout(rect=(0, 0.05, 1, 1))  # leave a strip at the bottom for the provenance footer
    fig.text(0.01, 0.008, footer, fontsize=6, color=MUTED, ha="left", va="bottom")
    fig.savefig(path, dpi=160, metadata={"Description": footer}, bbox_inches="tight")
    plt.close(fig)


def _ci_cell(m: dict[str, Any] | None) -> str:
    if not m or m.get("rate") is None:
        return "--"
    return f"{_pct(m['rate'])} [{_pct(m['ci_low'])}, {_pct(m['ci_high'])}]"


def export_end_to_end(summary: dict[str, Any], rows: list[dict[str, Any]], out: Path, meta: dict[str, Any]) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    defs = summary["heatmap"]["defenses"]
    S = summary["defenses"]
    files: list[str] = []

    header = ["defense", "ASR %", "ASR 95% CI", "ASR in-dist %", "ASR OOD %", "TPR %", "FPR %", "FPR 95% CI", "precision", "F1",
              "utility %", "utility drop", "mean defense ms", "p95 defense ms", "LLM calls/req", "escalation rate"]
    body = []
    for d in defs:
        s = S[d]
        body.append([d, _pct(s["asr"]["rate"]), f"[{_pct(s['asr']['ci_low'])}, {_pct(s['asr']['ci_high'])}]",
                     _pct(s["asr_in_distribution"]["rate"]), _pct(s["asr_ood"]["rate"]), _pct(s["detection_tpr"]["rate"]),
                     _pct(s["fpr"]["rate"]), f"[{_pct(s['fpr']['ci_low'])}, {_pct(s['fpr']['ci_high'])}]",
                     s["precision"], s["f1"], _pct(s["utility"]), s.get("utility_drop"), s["defense_latency_ms_mean"],
                     s["defense_latency_ms_p95"], s["llm_calls_per_request"], s["escalation_rate"]])
    write_csv(out / "summary_by_defense.csv", header, body, meta)
    files.append("summary_by_defense.csv")
    fmt = lambda v: "--" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))  # noqa: E731
    write_tex(out / "table_main.tex", "Attack success rate (ASR), false-positive rate (FPR) and latency per defense.", "tab:main",
              ["Defense", "ASR \\%", "OOD ASR \\%", "TPR \\%", "FPR \\%", "Defense ms", "LLM calls"],
              [[r[0], r[1], r[4], r[5], r[6], fmt(r[12]), fmt(r[14])] for r in body], meta)
    files.append("table_main.tex")

    cats = summary["heatmap"]["categories"]
    write_csv(out / "asr_by_category.csv", ["category"] + defs,
              [[c] + [summary["heatmap"]["asr"][i][j] for j in range(len(defs))] for i, c in enumerate(cats)], meta)
    files.append("asr_by_category.csv")
    write_tex(out / "table_category.tex", "ASR (\\%) by attack category and defense.", "tab:category", ["Category"] + defs,
              [[c] + [_pct(summary["heatmap"]["asr"][i][j]) for j in range(len(defs))] for i, c in enumerate(cats)], meta)
    files.append("table_category.tex")

    keys = list(rows[0].keys()) if rows else []
    write_csv(out / "runs.csv", keys, [[r[k] for k in keys] for r in rows], meta)
    files.append("runs.csv")

    # --- heatmap: category x defense ---
    if cats and defs:
        data = np.array([[np.nan if v is None else v for v in row] for row in summary["heatmap"]["asr"]], float)
        fig, ax = plt.subplots(figsize=(1.1 * len(defs) + 3, 0.5 * len(cats) + 1.8))
        ax.grid(False)
        im = ax.imshow(data, cmap=SEQ, vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(defs)), defs, rotation=35, ha="right")
        ax.set_yticks(range(len(cats)), cats)
        for i in range(len(cats)):
            for j in range(len(defs)):
                if not np.isnan(data[i, j]):
                    ax.text(j, i, f"{100 * data[i, j]:.0f}", ha="center", va="center", fontsize=8, color="white" if data[i, j] > 0.45 else INK)
        ax.set_title("Attack success rate (%) by category and defense", loc="left", fontsize=11)
        fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02).set_label("ASR")
        _save(fig, out / "asr_heatmap.png", meta)
        files.append("asr_heatmap.png")

    # --- ASR and FPR per defense with 95% CI ---
    fig, ax = plt.subplots(figsize=(8, 0.45 * len(defs) + 1.6))
    y = np.arange(len(defs))
    for k, (key, label) in enumerate([("asr", "ASR (attacks that succeeded)"), ("fpr", "FPR (benign requests blocked)")]):
        v = np.array([S[d][key]["rate"] or 0 for d in defs])
        lo = np.array([S[d][key]["ci_low"] or 0 for d in defs])
        hi = np.array([S[d][key]["ci_high"] or 0 for d in defs])
        ax.barh(y + (k - 0.5) * 0.32, 100 * v, height=0.28, color=SERIES[k], label=label, xerr=[100 * (v - lo), 100 * (hi - v)],
                error_kw={"ecolor": INK2, "elinewidth": 0.8, "capsize": 2})
    ax.set_yticks(y, defs)
    ax.invert_yaxis()
    ax.set_xlabel("percent (95% bootstrap CI)")
    ax.set_xlim(0, 100)
    ax.grid(axis="y", visible=False)  # category axis: no gridlines through the bars
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=2, fontsize=8)
    ax.set_title("Security vs. false positives per defense", loc="left", fontsize=11)
    _save(fig, out / "asr_fpr_by_defense.png", meta)
    files.append("asr_fpr_by_defense.png")
    return files


def export_conformal(summary: dict[str, Any], out: Path, meta: dict[str, Any]) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    files: list[str] = []
    header = ["split", "alpha", "target_coverage", "coverage", "coverage_injection", "coverage_benign", "avg_set_size", "escalation_rate"]
    body = [[sp, r["alpha"], r["target_coverage"], r["coverage"], r["coverage_injection"], r["coverage_benign"], r["avg_set_size"], r["escalation_rate"]]
            for sp, d in summary["splits"].items() for r in d["rows"]]
    write_csv(out / "conformal_coverage.csv", header, body, meta)
    write_tex(out / "table_conformal.tex", "Empirical conformal coverage, set size and escalation rate by alpha.", "tab:conformal",
              ["Split", "alpha", "target", "cov.", "cov. inj.", "set size", "escal."],
              [[b[0], b[1], f"{b[2]:.2f}", f"{b[3]:.3f}", f"{b[4]:.3f}", f"{b[6]:.2f}", f"{b[7]:.3f}"] for b in body], meta)
    files += ["conformal_coverage.csv", "table_conformal.tex"]

    splits = list(summary["splits"])
    alphas = summary["alphas"]
    fig, ax = plt.subplots(figsize=(6.4, 4))
    ax.plot([1 - a for a in alphas], [1 - a for a in alphas], color=MUTED, linestyle="--", linewidth=1.2, label="target 1-alpha")
    for k, sp in enumerate(splits):
        ax.plot([1 - a for a in alphas], [r["coverage_injection"] for r in summary["splits"][sp]["rows"]], marker="o", markersize=6,
                linewidth=2, color=SERIES[k], label=f"injection-class coverage ({sp})")
    ax.set_xlabel("target coverage (1 - alpha)")
    ax.set_ylabel("empirical coverage")
    ax.legend(frameon=False, fontsize=8)
    ax.set_title("Conformal coverage vs. target", loc="left", fontsize=11)
    _save(fig, out / "coverage_vs_alpha.png", meta)
    files.append("coverage_vs_alpha.png")

    fig, ax = plt.subplots(figsize=(6.4, 4))
    for k, sp in enumerate(splits):
        ax.plot(alphas, [100 * r["escalation_rate"] for r in summary["splits"][sp]["rows"]], marker="o", markersize=6, linewidth=2,
                color=SERIES[k], label=sp)
    ax.set_xlabel("alpha")
    ax.set_ylabel("escalated to judge (%)")
    ax.legend(frameon=False, fontsize=8)
    ax.set_title("Escalation rate vs. alpha", loc="left", fontsize=11)
    _save(fig, out / "escalation_vs_alpha.png", meta)
    files.append("escalation_vs_alpha.png")

    det = summary.get("detection") or {}
    if det:
        fig, ax = plt.subplots(figsize=(6.4, 4))
        for k, sp in enumerate(det):
            ax.plot(alphas, [c["latency_ms_mean"] for c in det[sp]["cascade"]], marker="o", markersize=6, linewidth=2, color=SERIES[k],
                    label=f"cascade ({sp})")
            ax.axhline(det[sp]["judge_only"]["latency_ms_mean"], color=SERIES[k], linestyle=":", linewidth=1.2, label=f"judge only ({sp})")
        ax.set_xlabel("alpha")
        ax.set_ylabel("mean latency per request (ms)")
        ax.legend(frameon=False, fontsize=8)
        ax.set_title("Cascade latency vs. alpha", loc="left", fontsize=11)
        _save(fig, out / "latency_vs_alpha.png", meta)
        files.append("latency_vs_alpha.png")
        rows = [[sp, "judge_only", "", d["judge_only"]["tpr"], d["judge_only"]["fpr"], d["judge_only"]["f1"], d["judge_only"]["latency_ms_mean"], 1.0]
                for sp, d in det.items()]
        rows += [[sp, "classifier@0.5", "", d["classifier_at_0.5"]["tpr"], d["classifier_at_0.5"]["fpr"], d["classifier_at_0.5"]["f1"],
                  d["classifier_at_0.5"]["latency_ms_mean"], 0.0] for sp, d in det.items()]
        rows += [[sp, "cascade", c["alpha"], c["tpr"], c["fpr"], c["f1"], c["latency_ms_mean"], c["llm_calls_per_request"]]
                 for sp, d in det.items() for c in d["cascade"]]
        write_csv(out / "conformal_detection.csv", ["split", "method", "alpha", "tpr", "fpr", "f1", "latency_ms_mean", "llm_calls_per_request"], rows, meta)
        files.append("conformal_detection.csv")
    return files
