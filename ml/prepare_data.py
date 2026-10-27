"""Build train / calibration / test / OOD splits for the injection detector.

Sources
  * public Hugging Face datasets (only those we can VERIFY exist and carry a permissive licence; the script
    queries the Hub and records the licence it finds in data/sources.json - nothing is assumed);
  * our own material: the YAML attack payloads (+ seeded mutations) as injections, and the benign prompt
    sets of the three target apps as benign.

Leakage control
  * exact + near-duplicate removal (TF-IDF cosine >= 0.90) across the WHOLE pool before splitting;
  * grouped splitting: a payload and all of its mutated variants share a `group` and always land in the same split;
  * OOD split: every injection of the held-out CATEGORIES (default obfuscation, payload_splitting) is removed from
    train/cal/test and placed only in `ood`, together with a disjoint slice of benign groups.
  * a final audit asserts no text appears in two splits and writes it to data/stats.json.

Usage:  python ml/prepare_data.py [--seed 1234] [--variants 8] [--no-hf]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.attacks.benign import benign_prompts  # noqa: E402
from app.attacks.library import DEFAULT_OOD_CATEGORIES, load_payloads  # noqa: E402
from app.attacks.mutator import Mutator  # noqa: E402

DATA = ROOT / "ml" / "data"
PERMISSIVE = ("apache-2.0", "mit", "cc-by-4.0", "cc-by-sa-4.0", "cc0-1.0", "bsd-3-clause", "openrail", "cc-by-3.0")
# Candidate public datasets. Each is verified against the Hub at run time; unavailable/unlicensed ones are skipped.
HF_CANDIDATES = [
    # `positives`: raw label values meaning "attack"; `cap`: max rows kept per label (seeded sample) to keep CPU work bounded;
    # `group`: optional column whose value keeps related rows (augmented siblings) in the same split.
    {"repo": "deepset/prompt-injections", "text": "text", "label": "label", "positives": {"1"}, "cap": 5000},
    {"repo": "neuralchemy/Prompt-injection-dataset", "text": "text", "label": "label", "positives": {"1"}, "cap": 2000, "group": "group_id"},
    {"repo": "jackhhao/jailbreak-classification", "text": "prompt", "label": "type", "positives": {"jailbreak"}, "cap": 2000},
    {"repo": "hendzh/PromptShield", "text": "prompt", "label": "label", "positives": {"1"}, "cap": 1500},
    {"repo": "xTRam1/safe-guard-prompt-injection", "text": "text", "label": "label", "positives": {"1"}, "cap": 2000},
]


def norm_key(t: str) -> str:
    return re.sub(r"\W+", " ", t.lower()).strip()


def load_hf(no_hf: bool) -> tuple[list[dict], list[dict]]:
    """Return (items, source_report). Items: text,label,source,group,category,hf_split."""
    items, report = [], []
    if no_hf:
        return items, [{"repo": "(skipped by --no-hf)", "used": False}]
    try:
        from datasets import load_dataset
        from huggingface_hub import HfApi
    except ImportError:
        return items, [{"repo": "(datasets/huggingface_hub not installed)", "used": False}]
    api = HfApi()
    for c in HF_CANDIDATES:
        rec = {"repo": c["repo"], "used": False}
        try:
            info = api.dataset_info(c["repo"])
            lic = (info.card_data.license if info.card_data and info.card_data.license else None)
            lic = (lic[0] if isinstance(lic, list) else lic)
            rec["license"] = lic
            if not lic or lic.lower() not in PERMISSIVE:
                rec["note"] = "skipped: licence missing or not on the permissive allow-list"
                report.append(rec)
                continue
            ds = load_dataset(c["repo"])
            rng = random.Random(0)
            pool: dict[int, list[dict]] = {0: [], 1: []}
            for split, d in ds.items():  # official splits are pooled: we re-split ourselves so cal and test are exchangeable
                for k, row in enumerate(d):
                    text = str(row[c["text"]]).strip()
                    if not text:
                        continue
                    y = int(str(row[c["label"]]).strip().lower() in c["positives"])
                    grp = f"hf:{c['repo']}:{row[c['group']]}" if c.get("group") else f"hf:{c['repo']}:{split}:{k}"
                    pool[y].append({"text": text, "label": y, "source": c["repo"], "group": grp, "category": None, "hf_split": None})
            n = 0
            for y in (0, 1):
                rng.shuffle(pool[y])
                items += pool[y][: c["cap"]]
                n += min(len(pool[y]), c["cap"])
            rec.update(used=True, rows=n, rows_available=sum(len(v) for v in pool.values()), official_splits_pooled=list(ds.keys()))
        except Exception as e:  # network error, gated dataset, missing repo...
            rec["note"] = f"unavailable: {type(e).__name__}: {str(e)[:120]}"
        report.append(rec)
    return items, report


def own_items(variants: int, seed: int) -> list[dict]:
    items: list[dict] = []
    payloads = load_payloads()
    mut = Mutator(seed=seed)  # no LLM -> no language_switch; fully deterministic
    for p in payloads:
        # Use the malicious turn only; earlier turns of multi-turn attacks are innocuous small talk.
        for q in [p] + mut.variants(p, variants):
            items.append({"text": q.text, "label": 1, "source": "own:payload", "group": f"atk:{p.id}", "category": p.category, "hf_split": None})
    for tgt in ("rag_bot", "email_agent", "support_bot"):
        for b in benign_prompts(tgt):
            items.append({"text": b.text, "label": 0, "source": f"own:benign:{tgt}", "group": f"bn:{b.id}", "category": None, "hf_split": None})
    return items


def dedupe(items: list[dict], threshold: float = 0.90) -> tuple[list[dict], int]:
    from sklearn.feature_extraction.text import TfidfVectorizer

    seen, exact = set(), []
    for it in items:
        k = (norm_key(it["text"]), it["label"])
        if k not in seen and it["text"]:
            seen.add(k)
            exact.append(it)
    X = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True).fit_transform([i["text"] for i in exact])
    drop: set[int] = set()
    for start in range(0, X.shape[0], 500):
        sim = (X[start:start + 500] @ X.T).toarray()
        for r in range(sim.shape[0]):
            i = start + r
            if i in drop:
                continue
            for j in np.where(sim[r] >= threshold)[0]:
                if j > i and exact[j]["label"] == exact[i]["label"]:  # keep the earlier one
                    drop.add(int(j))
    kept = [it for i, it in enumerate(exact) if i not in drop]
    return kept, len(items) - len(kept)


def split(items: list[dict], ood_categories: list[str], seed: int) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    out: dict[str, list[dict]] = {"train": [], "cal": [], "test": [], "ood": []}
    ood_inj = [i for i in items if i["label"] == 1 and i["category"] in ood_categories]
    rest = [i for i in items if i not in ood_inj]
    out["ood"] += ood_inj
    # Group-wise assignment, stratified by label so every split has both classes.
    for label in (0, 1):
        groups: dict[str, list[dict]] = defaultdict(list)
        for it in rest:
            if it["label"] == label:
                groups[it["group"]].append(it)
        keys = sorted(groups)
        rng.shuffle(keys)
        if label == 0:  # a disjoint slice of benign groups goes to OOD so FPR can be measured there too
            n_ood = max(1, int(len(ood_inj) * 1.0))
            ood_keys, keys = [], keys
            taken = 0
            for k in list(keys):
                if taken >= n_ood:
                    break
                ood_keys.append(k)
                taken += len(groups[k])
                keys.remove(k)
            for k in ood_keys:
                out["ood"] += groups[k]
        total = sum(len(groups[k]) for k in keys)
        acc = 0
        for k in keys:
            g = groups[k]
            frac = acc / total
            part = "train" if frac < 0.6 else "cal" if frac < 0.8 else "test"
            out[part] += g
            acc += len(g)
    return out


def audit(splits: dict[str, list[dict]]) -> dict:
    owner: dict[str, str] = {}
    leaks = 0
    for name, rows in splits.items():
        for r in rows:
            k = norm_key(r["text"])
            if k in owner and owner[k] != name:
                leaks += 1
            owner[k] = name
    return {"cross_split_text_overlap": leaks}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--variants", type=int, default=8)
    ap.add_argument("--no-hf", action="store_true")
    ap.add_argument("--ood", nargs="*", default=DEFAULT_OOD_CATEGORIES)
    a = ap.parse_args()

    hf, report = load_hf(a.no_hf)
    pool, n_dropped = dedupe(hf + own_items(a.variants, a.seed))
    splits = split(pool, a.ood, a.seed)
    aud = audit(splits)
    assert aud["cross_split_text_overlap"] == 0, aud

    DATA.mkdir(parents=True, exist_ok=True)
    stats: dict = {"seed": a.seed, "ood_categories": a.ood, "near_duplicates_removed": n_dropped, "sources": report, **aud, "splits": {}}
    for name, rows in splits.items():
        with open(DATA / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")  # ASCII-escaped: raw U+2028 etc. would break line splitting
        stats["splits"][name] = {"n": len(rows), "labels": dict(Counter(r["label"] for r in rows)),
                                 "sources": dict(Counter(r["source"] for r in rows)),
                                 "sha256": hashlib.sha256("\n".join(sorted(r["text"] for r in rows)).encode()).hexdigest()[:16]}
    (DATA / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
