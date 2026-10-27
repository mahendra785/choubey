"""Launch experiments through the real PromptShield API and wait for them (what the dashboard does, scriptable).

  python scripts/run_experiments.py --email admin@example.com --password '...' pilot
  python scripts/run_experiments.py --email ... --password ... full
  python scripts/run_experiments.py --email ... --password ... conformal

Presets only choose request bodies; every number still comes from recorded runs on the server.
Uses httpx (already a backend dependency): run with the backend virtualenv's Python.
"""
from __future__ import annotations

import argparse
import sys
import time

import httpx

ALL_DEFENSES = ["none", "sanitizer", "spotlighting", "output_guard", "classifier_0.5", "llm_judge",
                "cascade_a0.01", "cascade_a0.05", "cascade_a0.1", "cascade_a0.2", "full_stack"]
PRESETS = {
    "pilot": {"name": "pilot-support-bot", "kind": "end_to_end", "targets": ["support_bot"], "defenses": ["none", "sanitizer", "cascade_a0.1"],
              "max_payloads": 12, "benign_per_target": 6, "n_variants": 0, "seed": 1234},
    "full": {"name": "full-comparison", "kind": "end_to_end", "targets": ["support_bot", "rag_bot", "email_agent"], "defenses": ALL_DEFENSES,
             "max_payloads": 60, "benign_per_target": 20, "n_variants": 0, "seed": 1234},
    # Realistic false-positive check: a MIX of ordinary and tricky benign prompts (one attack only because the API requires >= 1).
    "benign": {"name": "benign-mix-support-bot", "kind": "end_to_end", "targets": ["support_bot"],
               "defenses": ["none", "sanitizer", "output_guard", "classifier_0.5", "cascade_a0.05", "full_stack"],
               "max_payloads": 1, "benign_per_target": 45, "n_variants": 0, "seed": 1234},
    "conformal": {"name": "conformal-sweep", "kind": "conformal_sweep", "alphas": [0.01, 0.05, 0.1, 0.2], "seed": 1234},
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("preset", choices=sorted(PRESETS))
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--origin", default="http://localhost:3000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--timeout-min", type=float, default=600)
    a = ap.parse_args()

    with httpx.Client(base_url=a.base, timeout=60, headers={"Origin": a.origin}) as c:
        def login() -> dict[str, str]:
            r = c.post("/auth/login", json={"email": a.email, "password": a.password})
            r.raise_for_status()
            return {"X-CSRF-Token": r.json()["csrf_token"]}

        csrf = login()
        r = c.post("/experiments", json=PRESETS[a.preset], headers=csrf)
        if r.status_code >= 400:
            print("launch failed:", r.status_code, r.text, file=sys.stderr)
            return 1
        exp_id = r.json()["id"]
        print("started", exp_id, flush=True)
        t0, last = time.time(), -1
        while time.time() - t0 < a.timeout_min * 60:
            resp = c.get(f"/experiments/{exp_id}")
            if resp.status_code == 401:  # the 15-minute access token expired: sign in again and retry
                try:
                    csrf = login()
                except httpx.HTTPError:
                    pass  # e.g. a busy SQLite DB; try again on the next poll
                time.sleep(10)
                continue
            e = resp.json()
            if e["completed"] != last:
                last = e["completed"]
                print(f"  {e['status']}: {e['completed']}/{e['total']}  ({time.time() - t0:.0f}s)", flush=True)
            if e["status"] in ("done", "failed"):
                print("final status:", e["status"], e.get("error") or "")
                print("files:", c.get(f"/experiments/{exp_id}/files").json())
                return 0 if e["status"] == "done" else 2
            time.sleep(10)
        print("timed out waiting (the job keeps running on the server)")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
