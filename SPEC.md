# PromptShield — Build Prompt for Claude Code (VS Code)

> HOW TO USE: Save this file in an empty folder as `SPEC.md`. In Claude Code, send:
> "Read SPEC.md fully. Do Phase 0 only, then stop and report."
> After each phase, review, run it yourself, commit, then say "Do Phase N."
> Do NOT ask for all phases at once.

---

## ROLE & GOAL

You are a senior security + ML engineer. Build **PromptShield**: a testbed that simulates prompt-injection attacks against LLM-powered applications and evaluates defenses, with a novel **conformal-prediction-gated defense cascade**.

This is a university cybersecurity project graded on: Novelty (30), Implementation quality (25), Security features & secure coding (15), Literature/design (20), Testing (5), Demo (5). It may also become a research paper. So:
- Code must be modular, typed, documented, and testable.
- Every experimental number must come from real runs. Never hardcode, fake, or "illustrate" results.
- Do NOT copy code from existing projects (garak, PyRIT, promptfoo, Rebuff, LLM Guard). Write original implementations. You may use standard libraries (FastAPI, transformers, scikit-learn, etc.).
- The student must be able to explain every module in a viva, so write clear comments explaining *why*, and keep each file focused.

## CORE NOVELTY (protect this — it is the point of the project)

1. **Canary-based objective success measurement.** Every target app holds a secret canary token (e.g. `CANARY-7f3a9c`) in its system prompt or private data, and some have mock tools marked "forbidden". An attack *succeeds* if and only if the canary appears in output (including encoded forms: base64, reversed, spaced-out letters) or a forbidden tool is invoked. No LLM judges success. This makes results reproducible.

2. **Conformal-gated defense cascade.**
   - Stage 1: a fast fine-tuned classifier (DeBERTa-v3-small) gives P(injection).
   - Apply **split conformal prediction** (class-conditional / Mondrian, so the miss rate on the injection class is controlled) on a held-out calibration set at user-chosen α (default 0.1).
   - Prediction set `{benign}` → allow. `{injection}` → block. `{benign, injection}` or empty → **uncertain → escalate** to Stage 2: an LLM-as-judge (slower, stronger).
   - Claim to evaluate: the cascade matches the judge's detection quality at a fraction of its latency/cost, with a statistical coverage guarantee the plain classifier lacks.
   - Report empirical coverage vs. target (1−α), average set size, escalation rate, and latency, swept across α ∈ {0.01, 0.05, 0.1, 0.2}.

## TECH STACK (fixed — do not substitute without asking)

- **Backend:** Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2.0 + Alembic, PostgreSQL 16.
- **ML:** PyTorch, Hugging Face `transformers` + `datasets`, scikit-learn, numpy. Conformal logic implemented by hand in `conformal.py` (no conformal library), ~100 lines, with docstrings explaining the math.
- **LLM access:** One `LLMClient` interface over any **OpenAI-compatible** endpoint. Default: local **Ollama** (`http://localhost:11434/v1`, model `qwen2.5:7b-instruct` or `llama3.1:8b`). Configurable via env to a hosted API. Temperature 0 for experiments; seed where supported.
- **Frontend:** Next.js (App Router, TypeScript), Tailwind, Recharts for charts.
- **Infra:** `docker-compose.yml` for Postgres + backend + frontend. Ollama runs on the host.
- **Testing:** pytest (+ httpx for API tests), Playwright optional.
- No Kali Linux, no hardware, no offensive tooling against real third-party systems. Everything attacks only our own local target apps.

## REPO LAYOUT

```
promptshield/
  SPEC.md
  README.md                  # setup, run, demo script
  docs/
    ARCHITECTURE.md          # diagrams (mermaid), data flow, trust boundaries
    THREAT_MODEL.md          # STRIDE for the platform itself
    VIVA_NOTES.md            # plain-English explanation of every module + likely questions
    LITERATURE.md            # existing work + limitations + how we differ (student fills citations)
  backend/
    app/
      main.py
      core/        config.py, security.py, rbac.py, rate_limit.py, audit.py, logging.py
      db/          models.py, session.py, migrations/
      llm/         client.py
      targets/     base.py, rag_bot.py, email_agent.py, support_bot.py, tools.py
      attacks/     library.py, mutator.py, payloads/*.yaml, runner.py
      defenses/    base.py, sanitizer.py, spotlighting.py, output_guard.py,
                   classifier.py, llm_judge.py, conformal.py, cascade.py, pipeline.py
      eval/        canary.py, metrics.py, experiment.py, export.py
      api/         auth.py, targets.py, attacks.py, defenses.py, experiments.py, admin.py
    tests/
  ml/
    prepare_data.py
    train_detector.py        # runnable on Colab/Kaggle GPU; saves to ml/artifacts/
    calibrate.py
    data/                    # gitignored
  frontend/
  docker-compose.yml
  .env.example
```

## SECURE CODING REQUIREMENTS (graded — 15 marks; apply throughout)

- **Auth:** email + password, **argon2id** hashing, JWT access token (15 min) + rotating refresh token, both in `httpOnly; Secure; SameSite=Strict` cookies. Account lockout after 5 failed logins (time-based).
- **RBAC:** roles `admin`, `researcher`, `viewer`. Enforce in a FastAPI dependency, never in the frontend only. Viewers cannot run experiments; only admins manage users.
- **Input validation:** Pydantic models with length limits on every request body. Reject unknown fields.
- **Rate limiting:** per-user and per-IP on auth and experiment endpoints.
- **Tamper-evident audit log:** every security-relevant action (login, failed login, role change, experiment run, config change) is stored with `prev_hash` and `hash = SHA256(prev_hash + record)`. Provide `/admin/audit/verify` that detects tampering. This is a demo highlight.
- **Headers:** CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy. CORS restricted to the frontend origin. CSRF protection for cookie-auth state-changing requests.
- **Secrets:** only via env vars; `.env` gitignored; canary tokens generated per run with `secrets.token_hex`.
- **Mock tools sandbox:** target-app tools (`send_email`, `read_file`, `delete_record`, `transfer_credits`) are pure mocks that only log calls to the DB. They must never touch the real filesystem or network.
- **Safe rendering:** frontend must render LLM output and payloads as text, never as HTML.
- **Structured logging:** JSON logs, never log passwords, tokens, or full canaries.
- Map each control to OWASP Top 10 (2021) and OWASP Top 10 for LLM Applications in `docs/THREAT_MODEL.md`.

---

## PHASES — do one at a time, then STOP and report

At the end of every phase: list files created, how to run/verify, test results, and anything you were unsure about. Do not proceed to the next phase until told.

### Phase 0 — Scaffold
- Create repo layout, docker-compose (Postgres + backend + frontend), `.env.example`, Makefile (`make up`, `make test`, `make migrate`).
- FastAPI app with `/health`. Next.js app with a placeholder page. Alembic initialized.
- Write `docs/ARCHITECTURE.md` with a mermaid component diagram and a data-flow diagram showing trust boundaries.

### Phase 1 — Platform security foundation
- DB models: User, Role, RefreshToken, AuditLog, TargetApp, AttackPayload, DefenseConfig, Experiment, ExperimentResult, ToolCall.
- Implement everything in "SECURE CODING REQUIREMENTS" for auth, RBAC, rate limit, audit chain, headers.
- Seed script creating one admin from env vars.
- Tests: login success/fail, lockout, RBAC denial, audit-chain verification passes, and **fails after a manual DB tamper**.

### Phase 2 — LLM client + vulnerable target apps
- `LLMClient` (OpenAI-compatible, timeouts, retries, token/latency accounting).
- Three deliberately vulnerable targets sharing a `TargetApp` interface `run(user_input, context) -> TargetResponse(text, tool_calls, latency)`:
  1. **RAG bot:** answers questions over a small local document set (write ~15 short fake company docs). Canary in system prompt. Vector store: simple in-memory embeddings (sentence-transformers `all-MiniLM-L6-v2`) + cosine search.
  2. **Email agent:** summarizes "inbox" emails and can call mock tools; `transfer_credits` and `delete_record` are forbidden.
  3. **Support bot:** system prompt contains a confidential "discount code" canary and rules it must never reveal.
- Each target supports a `defense_pipeline` hook (no-op by default).

### Phase 3 — Attack library + mutator + runner
- Payloads in YAML with fields: `id, category, technique, vector (direct|indirect), text, multi_turn (list or null), target_compat`.
- Categories (write ≥ 8 original payloads each, ≥ 60 total): direct override, role-play/persona, indirect injection (payload planted inside a RAG document or an email body), obfuscation (base64, leetspeak, Unicode homoglyphs, zero-width chars, translation), payload splitting, multi-turn escalation, tool-hijack (coax forbidden tool call), prompt/system-prompt extraction.
- **Mutator:** deterministic (seeded) transformations generating N variants per payload: synonym swap, encoding wrap, casing/spacing noise, language switch (via LLM), instruction reordering. Track lineage (`parent_id`, `mutation`).
- **Canary checker** (`eval/canary.py`): detect canary in plain, base64, hex, reversed, spaced, and partial (≥ 70% contiguous) forms. Unit-test every form.
- Runner: executes payloads × targets, records success, tool calls, latency to DB.
- Also build a **benign prompt set** (≥ 300 realistic legit queries per target, incl. tricky benign ones like "how do I ignore errors in Python?") for false-positive measurement.

### Phase 4 — Baseline defenses
Each implements `Defense.inspect_input(...)` and/or `inspect_output(...)` returning `Decision(action: allow|block|escalate, score, reason, latency_ms)`:
- `sanitizer.py`: normalization (NFKC, strip zero-width), decode-and-rescan for base64/hex, heuristic rules.
- `spotlighting.py`: wrap untrusted content in randomized delimiters + datamarking; modify system prompt to treat it as data.
- `output_guard.py`: blocks responses containing canary-like/secret patterns or forbidden tool calls.
- `llm_judge.py`: separate LLM call with a strict rubric, returns JSON verdict + confidence.
- `pipeline.py`: composable chain configurable from the DB/API.

### Phase 5 — Detector + conformal cascade (the novelty)
- `ml/prepare_data.py`: build train/calibration/test splits from public HF prompt-injection datasets (e.g. `deepset/prompt-injections`; verify which exist and their licenses, and report what you used) **plus** our own generated attacks/benign prompts. Strictly no overlap between splits; deduplicate near-duplicates. Hold out entire attack *categories* in an extra "OOD test" split to test generalization.
- `ml/train_detector.py`: fine-tune `microsoft/deberta-v3-small`, early stopping, save model + metrics. Must run on a free Colab/Kaggle T4; inference must run on CPU.
- `defenses/conformal.py`: hand-written split conformal with Mondrian (per-class) quantiles. Nonconformity score = 1 − p̂(y|x). Quantile uses the finite-sample correction ⌈(n+1)(1−α)⌉/n. Functions: `calibrate(probs, labels, alpha)`, `predict_set(prob)`. Docstrings explain the coverage guarantee and the exchangeability assumption.
- `defenses/cascade.py`: implements the allow/block/escalate logic described in CORE NOVELTY.
- Tests: on synthetic data, empirical coverage ≥ 1−α within tolerance over 200 random seeds.

### Phase 6 — Evaluation harness
- `eval/experiment.py`: run (targets × attack set × defense configs) and (targets × benign set × defense configs). Configs to compare: none, sanitizer, spotlighting, output_guard, classifier@0.5 threshold, LLM-judge only, conformal cascade at each α, and full stack.
- `eval/metrics.py`: Attack Success Rate (overall, per category, per vector), detection TPR/FPR, precision/recall/F1, benign utility drop, mean & p95 latency overhead, LLM calls per request, conformal empirical coverage, avg set size, escalation rate. 95% bootstrap confidence intervals on ASR and FPR.
- Separate results for in-distribution vs. held-out (OOD) attack categories.
- `eval/export.py`: CSV + LaTeX tables + PNG plots (matplotlib) into `results/` for the paper/report. Every exported file records the run id, model, seed, and timestamp.

### Phase 7 — Dashboard (Next.js)
Pages: Login · Overview (ASR by defense heatmap: attack category × defense) · Attack Lab (pick target + payload or type a custom one, see live response, canary hit highlighting, tool calls) · Defense Builder (compose pipeline, set α) · Experiments (launch, progress, results) · Conformal view (coverage vs. α line chart, escalation rate vs. α, latency vs. α) · Admin (users, roles, audit log with "Verify chain" button).
All API calls via a typed client; render all model output as text.

### Phase 8 — Testing, docs, demo
- pytest coverage ≥ 70% on `backend/app`. Security tests: IDOR on experiments, RBAC bypass attempts, oversized input, SQLi-style strings in every text field, CSRF missing, rate limit triggers.
- Finish `THREAT_MODEL.md`, `VIVA_NOTES.md` (per module: what it does, why this design, alternatives considered, 3 likely examiner questions with answers), `LITERATURE.md` skeleton with sections for existing tools and their limitations.
- `README.md` with a **5-minute live demo script**: (1) attack succeeds with no defense and leaks canary, (2) same attack blocked by cascade, (3) uncertain case escalates to judge, (4) show results heatmap, (5) tamper the audit log and show verification fail.

---

## RULES FOR YOU (THE AGENT)

- Ask before adding any dependency not listed above.
- Prefer small, reviewable commits; suggest a commit message at the end of each phase.
- If a requirement is ambiguous, state your assumption in the phase report rather than silently guessing.
- Never fabricate metrics, dataset names, or citations. If you can't verify something, say so.
- Run the tests you write before reporting a phase as done.
