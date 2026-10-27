"""Train the stage-1 injection detector.

  python ml/train_detector.py --backbone deberta     # microsoft/deberta-v3-small, needs torch + transformers (GPU recommended)
  python ml/train_detector.py --backbone tfidf       # TF-IDF + logistic regression, CPU, seconds

Runs on a free Colab/Kaggle T4 (fp16 autocast, batch 16, max_len 256, ~1-2 min per epoch on this data size).
Inference is CPU-only (see backend/app/defenses/classifier.py). Saves the model + metrics.json to ml/artifacts/.
Early stopping watches validation loss; the best epoch's weights are restored.
Metrics are computed on the held-out TEST (in-distribution) and OOD (unseen attack categories) splits at the
default 0.5 threshold - the plain-classifier baseline the conformal cascade is compared against.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DATA, ART = ROOT / "ml" / "data", ROOT / "ml" / "artifacts"
MODEL_NAME = "microsoft/deberta-v3-small"


def read(name: str) -> list[dict]:
    return [json.loads(l) for l in (DATA / f"{name}.jsonl").read_text(encoding="utf-8").split(chr(10)) if l.strip()]


def group_val_split(rows: list[dict], frac: float, seed: int) -> tuple[list[dict], list[dict]]:
    groups = sorted({r["group"] for r in rows})
    random.Random(seed).shuffle(groups)
    val_groups = set(groups[: max(1, int(len(groups) * frac))])
    return [r for r in rows if r["group"] not in val_groups], [r for r in rows if r["group"] in val_groups]


def metrics_at(probs: np.ndarray, labels: np.ndarray, thr: float = 0.5) -> dict:
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

    pred = (probs >= thr).astype(int)
    out = {"n": int(len(labels)), "accuracy": float((pred == labels).mean()),
           "precision": float(precision_score(labels, pred, zero_division=0)),
           "recall_tpr": float(recall_score(labels, pred, zero_division=0)),
           "f1": float(f1_score(labels, pred, zero_division=0)),
           "fpr": float(((pred == 1) & (labels == 0)).sum() / max(1, (labels == 0).sum()))}
    if len(set(labels.tolist())) == 2:
        out["auc"] = float(roc_auc_score(labels, probs))
    return out


def train_tfidf(train, val) -> object:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    pipe = Pipeline([
        ("tf", FeatureUnion([("w", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
                             ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=3))])),
        ("lr", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced")),
    ])
    pipe.fit([r["text"] for r in train + val], [r["label"] for r in train + val])  # no early stopping needed
    return pipe


def train_deberta(train, val, args) -> object:
    import torch
    from torch.utils.data import DataLoader
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

    torch.manual_seed(args.seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(MODEL_NAME)
    # fp32 master weights: transformers 5 may otherwise load the checkpoint in fp16, which GradScaler cannot unscale.
    # Mixed precision is applied separately through autocast below.
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2, dtype=torch.float32).to(dev)

    def loader(rows, shuffle):
        def collate(batch):
            enc = tok([b["text"] for b in batch], truncation=True, max_length=args.max_len, padding=True, return_tensors="pt")
            enc["labels"] = torch.tensor([b["label"] for b in batch])
            return enc
        return DataLoader(rows, batch_size=args.batch, shuffle=shuffle, collate_fn=collate)

    tl, vl = loader(train, True), loader(val, False)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.1 * len(tl) * args.epochs), len(tl) * args.epochs)
    scaler = torch.amp.GradScaler(enabled=dev == "cuda")
    best, best_state, bad, history = float("inf"), None, 0, []
    t_start = time.time()
    for epoch in range(args.epochs):
        model.train()
        for step, batch in enumerate(tl, 1):
            if step % 50 == 0:
                print(f"  epoch {epoch + 1} step {step}/{len(tl)} ({time.time() - t_start:.0f}s elapsed)", flush=True)
            batch = {k: v.to(dev) for k, v in batch.items()}
            with torch.autocast(device_type=dev, dtype=torch.float16, enabled=dev == "cuda"):
                loss = model(**batch).loss
            opt.zero_grad()
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt)
            scaler.update()
            sched.step()
        model.eval()
        vloss, n = 0.0, 0
        with torch.no_grad():
            for batch in vl:
                batch = {k: v.to(dev) for k, v in batch.items()}
                vloss += model(**batch).loss.item() * len(batch["labels"])
                n += len(batch["labels"])
        vloss /= max(1, n)
        history.append({"epoch": epoch + 1, "val_loss": vloss})
        print(f"epoch {epoch + 1}: val_loss={vloss:.4f}", flush=True)
        if vloss < best - 1e-4:
            best, bad = vloss, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= args.patience:
                print("early stopping", flush=True)
                break
    model.load_state_dict(best_state)
    out = ART / "deberta"
    out.mkdir(parents=True, exist_ok=True)
    model.cpu().save_pretrained(out)
    tok.save_pretrained(out)
    return {"history": history, "best_val_loss": best, "device": dev}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backbone", choices=["deberta", "tfidf"], default="deberta")
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--patience", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    ART.mkdir(parents=True, exist_ok=True)
    train, val = group_val_split(read("train"), 0.1, args.seed)
    t0 = time.time()
    extra: dict = {}
    if args.backbone == "tfidf":
        import joblib

        model = train_tfidf(train, val)
        joblib.dump(model, ART / "tfidf.joblib")
        predict = lambda texts: model.predict_proba(texts)[:, 1]  # noqa: E731
    else:
        extra = train_deberta(train, val, args)
        import sys

        sys.path.insert(0, str(ROOT / "backend"))
        from app.defenses.classifier import DebertaClassifier

        clf = DebertaClassifier(ART / "deberta")
        predict = clf.predict_proba
    result = {"backbone": args.backbone, "base_model": MODEL_NAME if args.backbone == "deberta" else "tfidf+logreg",
              "train_n": len(train), "val_n": len(val), "seed": args.seed, "train_seconds": round(time.time() - t0, 1),
              "hyperparameters": {k: getattr(args, k) for k in ("epochs", "lr", "batch", "max_len", "patience")}, **extra}
    for split in ("test", "ood"):
        rows = read(split)
        probs = np.asarray(predict([r["text"] for r in rows]))
        result[f"{split}_at_0.5"] = metrics_at(probs, np.array([r["label"] for r in rows]))
    (ART / f"metrics_{args.backbone}.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
