# PromptShield — Viva Notes

Plain-English explanation of every module: **what** it does, **why** it is designed that way, **alternatives** considered, and **three likely examiner questions** with answers. Read the file named in each heading as you revise.

## 0. The 60-second story

PromptShield is a lab for prompt injection. We build three deliberately vulnerable LLM apps (a RAG bot, an e-mail agent with tools, a support bot), attack them with 64 original payloads (+ seeded mutations), and measure — **objectively, using secret canary tokens, not an LLM judge** — whether each attack succeeded. Then we test defenses. Our contribution is a **conformal-gated cascade**: a fast classifier decides most inputs; a *conformal prediction set* says when it is not sure enough, and only those cases are escalated to a slow LLM judge. The conformal part gives a statistical guarantee on the miss rate for the injection class. Around that sits a securely built platform (auth, RBAC, hash-chained audit log, …).

---

## 1. `core/security.py`, `api/auth.py` — authentication
**What:** argon2id password hashing; 15-minute JWT in an `httpOnly; Secure; SameSite=Strict` cookie; opaque refresh token (random, stored only as a SHA-256 hash), rotated on every use; lockout after 5 failures.
**Why:** short-lived access tokens limit theft damage; server-side refresh tokens can be revoked; rotation + reuse detection turns a stolen token into a visible event (the whole family is revoked). Cookies are `httpOnly` so XSS cannot read them.
**Alternatives:** bcrypt/scrypt (argon2id is memory-hard, current OWASP recommendation); JWT in localStorage (XSS-readable); long-lived JWTs (cannot revoke).
**Questions**
1. *Why a dummy hash when the e-mail doesn't exist?* — To equalise timing; otherwise response time reveals whether an account exists (user enumeration).
2. *What is refresh-token reuse detection?* — If a token that was already rotated is presented again, either the user or a thief has an old copy; we cannot tell which, so we revoke the whole family and force re-login.
3. *Why store only the hash of the refresh token?* — A database leak then doesn't give attackers usable tokens; SHA-256 is enough because the token has 384 bits of randomness (no need for a slow hash).

## 2. `core/rbac.py` — authorization
**What:** FastAPI dependencies `require_admin / require_researcher / require_any` re-read the user from the DB on each request.
**Why:** server-side enforcement is the only real control; frontend hiding is cosmetic. Re-reading means demotion/deactivation is immediate despite a still-valid JWT.
**Alternatives:** role claim only in the JWT (stale for 15 min); decorators per route (easy to forget).
**Questions**
1. *Where is "viewers cannot run experiments" enforced?* — `require_researcher` dependency on the POST routes; tested by `test_rbac_matrix`.
2. *Why 404 not 403 for another user's experiment?* — 403 confirms the id exists (information leak); 404 does not (IDOR defence).
3. *Can a user change their role by editing the cookie?* — No: the JWT is HMAC-signed, role is re-read from the DB, and role changes are admin-only routes.

## 3. `core/audit.py` — tamper-evident audit log (demo highlight)
**What:** each row stores `prev_hash` and `hash = SHA256(prev_hash + canonical_record)`. `/admin/audit/verify` recomputes the chain from genesis.
**Why:** editing or deleting a row in the middle breaks the next row's `prev_hash`, so tampering is detectable without trusting the DB.
**Alternatives:** append-only DB permissions (admin can bypass); external WORM storage / blockchain (overkill); signed logs (needs key management).
**Questions**
1. *Can the DBA defeat it?* — Yes if they recompute every later hash or truncate the newest rows. Mitigation: periodically anchor the head hash somewhere the DBA cannot write (printout, external service). We state this limitation.
2. *Why a fixed JSON canonical form?* — The same record must serialise to identical bytes on write and verify, otherwise valid rows fail verification.
3. *Concurrency?* — The tip row is read `FOR UPDATE` inside the request transaction so two writers cannot extend the same predecessor.

## 4. `core/middleware.py`, `core/rate_limit.py`, `core/logging.py`
**What:** security headers (CSP, HSTS, nosniff, frame-deny, referrer-policy); double-submit CSRF + Origin check; body-size cap; sliding-window rate limiter (per IP and per account/user); JSON logs with redaction.
**Why:** defence in depth: SameSite=Strict already blocks most CSRF, the token covers browsers/edge cases. We do **not** trust `X-Forwarded-For` for rate limiting because clients can forge it.
**Questions**
1. *Why double-submit and not a server-side CSRF store?* — Stateless and simple; secure because an attacker site can cause the cookie to be *sent* but cannot *read* it to copy into the header.
2. *Limitation of the limiter?* — Per-process memory; with several replicas you need a shared store (Redis).
3. *What does the logger redact?* — Values of keys like password/token/secret/cookie/canary, JWT-shaped strings and `CANARY-…` (keeps only the first two hex chars).

## 5. `llm/client.py` — LLM access
**What:** one client for any OpenAI-compatible endpoint (Ollama default), temperature 0 + seed, timeouts, bounded exponential-backoff retries (not on 4xx), token/latency accounting, structured and text-format (`<tool_call>`) tool-call parsing.
**Why:** swapping Ollama for a hosted API is a config change; determinism is required for reproducible experiments.
**Questions**
1. *Is temperature 0 fully deterministic?* — No: seeds are honoured by some servers only, and GPU kernels can differ; we record model and seed and report CIs rather than claim bit-exactness.
2. *Why retry 5xx/timeouts but not 400?* — 5xx/429 are transient; 4xx means our request is wrong and retrying cannot help.
3. *Why parse `<tool_call>` text?* — Some local models emit tool calls as text instead of the structured field.

## 6. `targets/*` — vulnerable apps and mock tools
**What:** `RagBot` (15 fake docs, cosine retrieval, canary in system prompt), `EmailAgent` (inbox + 4 mock tools, 2 forbidden), `SupportBot` (confidential discount code). All share `run(user_input, context) -> TargetResponse` and accept a `defense_pipeline`.
**Why vulnerable on purpose:** documents/e-mails are pasted into the prompt without separation, secrets sit next to untrusted input, the agent is over-privileged — exactly the real-world mistakes we want defenses to compensate for.
**Safety:** `tools.py` is pure Python dict lookups and logging. A test parses its AST to prove it imports nothing like `os`, `socket`, `subprocess` and never calls `open`/`exec`/`eval`.
**Questions**
1. *Can a successful injection harm the host?* — No: the worst tool outcome is an in-memory log entry / `ToolCall` DB row.
2. *How are indirect attacks delivered?* — The payload is planted as an extra RAG document or e-mail body; the *user* only asks an innocent question (`runner.run_attack`).
3. *Why a fresh target per run?* — New random canary each time, no state leakage between runs.

## 7. `eval/canary.py` — the objective success oracle (core novelty #1)
**What:** attack success ⇔ the run's canary appears in anything observable (reply text *and* tool-call arguments) in one of: plain, reversed, spaced/separated, base64, hex, partial (≥70 % contiguous) — or a forbidden tool executed.
**Why:** LLM judges are non-deterministic and can be fooled by the same attacks; string/structure checks are reproducible and auditable.
**Alternatives:** LLM-graded "did the model comply?" (subjective, costly); keyword refusal detection (many false results).
**Questions**
1. *What does the oracle miss?* — Leaks in encodings not implemented (e.g. rot13 — tested as a known gap), semantic leaks without the token, and harms other than leakage/forbidden tools.
2. *Why count partial matches?* — A truncated secret is still a leak; the 70 % threshold avoids random matches (the token has 12 random hex chars).
3. *Why canary per run?* — Prevents memorisation across runs and guarantees nothing real can leak.

## 8. `attacks/*` — library, transforms, mutator, benign set, runner
**What:** 64 YAML payloads in 8 categories (8 each); `{{b64:…}}`-style directives expanded at load so YAML stays readable but the sent text is truly obfuscated; seeded mutator (synonym swap, encoding wrap, noise, reorder, LLM language switch) with lineage; ≥300 benign prompts per target including tricky ones ("how do I ignore errors in Python?").
**Why:** categories mirror known attack classes; benign set measures false positives and utility cost, otherwise a defense that blocks everything looks perfect.
**Questions**
1. *Who wrote the payloads?* — Original, written for this project (no copying from garak/PyRIT/promptfoo). Limitation: written by the same team that wrote the baseline defense, so baselines may be tuned to them; the OOD split and public datasets partly mitigate this.
2. *How is the mutator deterministic?* — `random.Random(f"{seed}:{payload_id}:{i}")`; same seed → identical variants.
3. *Why multi-turn?* — Some attacks build rapport first; success is checked on every turn.

## 9. `defenses/sanitizer.py`, `spotlighting.py`, `output_guard.py`, `llm_judge.py`
**Sanitizer:** NFKC + strip invisible chars (zero-width), fold homoglyphs/de-leet for scanning, decode base64/hex/rot13/reversed and rescan, noisy-OR of rule weights. **Spotlighting:** random per-instance delimiters + datamarking of untrusted docs/e-mails + system-prompt notice. **Output guard:** blocks forbidden tool calls *before execution* and secret-shaped output (optionally registered secrets in any encoding). **Judge:** strict rubric, JSON verdict, fail-closed.
**Questions**
1. *Why does spotlighting not help against direct injection?* — It only marks third-party content; the user's own message is not wrapped (and we don't want to mark it).
2. *Isn't the output guard "cheating" if it knows the canary?* — Yes, that mode is optional and OFF by default; the default uses generic secret shapes. Both are reported honestly.
3. *What if the judge is itself injected?* — Text is delimited and declared as data; unparsable output fails closed; but a successful judge injection would be an escape — noted as residual risk.

## 10. `defenses/conformal.py` — the mathematics (core novelty #2)
**What:** split conformal prediction, Mondrian (per-class). Score `s = 1 − p̂(y|x)`. For each class y, `q̂_y` = the ⌈(n_y+1)(1−α)⌉-th smallest calibration score of that class. Prediction set `{y : 1 − p̂(y|x) ≤ q̂_y}`.
**Guarantee:** if calibration and test points are exchangeable, `P(y_true ∈ C(X) | Y=y) ≥ 1−α` for each class — in particular the injection miss rate ≤ α.
**Why Mondrian:** plain conformal gives *marginal* coverage; with 70 % benign data the injection class could be badly under-covered while the average looks fine.
**Questions**
1. *Why n+1 instead of n?* — Finite-sample correction: the test point is one more exchangeable draw; this makes the guarantee exact (≥) rather than approximate.
2. *When does it fail?* — Distribution shift. We measure empirical coverage on an OOD split with entirely unseen attack categories, and report it even when below target.
3. *What does "empty set" mean?* — Neither label is plausible at that α (the classifier is out of its depth); we escalate those too.
4. *Does the guarantee cover the whole cascade?* — No, only the classifier stage's confident decisions. The judge's mistakes are not covered.

## 11. `defenses/classifier.py`, `cascade.py`, `registry.py`, `pipeline.py`
**What:** DeBERTa-v3-small (CPU inference) or TF-IDF+LR backend; long texts are chunked and scored by the max chunk (an injection hidden at the end of a long document must not be diluted); cascade maps sets → allow / block / escalate; pipelines are built from whitelisted dict configs; unresolved escalation **fails closed**.
**Questions**
1. *Why TF-IDF at all if the spec says DeBERTa?* — It trains in seconds on CPU and doubles as an ablation showing the framework is classifier-agnostic; DeBERTa is the headline model.
2. *How do you choose α?* — It's a policy knob: smaller α = fewer missed injections but more escalations (cost). The Conformal page plots the trade-off.
3. *Why is the cascade not guaranteed to be faster than the judge?* — It is only if the escalation rate is low; we measure it.

## 12. `eval/metrics.py`, `experiment.py`, `export.py`
**What:** ASR (overall/category/vector/ID vs OOD) with 95 % percentile-bootstrap CIs, detection TPR/FPR/precision/F1, utility drop, latency (mean/p95) and LLM-calls overhead vs the `none` baseline; end-to-end and conformal-sweep experiments; CSV/LaTeX/PNG exports stamped with run id, model, seed, timestamp.
**Questions**
1. *Why bootstrap CIs?* — Rates from tens/hundreds of runs are noisy; CIs show whether two defenses really differ.
2. *What is "utility"?* — Share of legitimate requests not blocked (1 − FPR); it does not judge answer quality.
3. *How do you ensure no number is invented?* — Everything is computed from DB rows written during the run; summaries and exports are derived, never typed in.

## 13. `ml/*` — data and training
**What:** `prepare_data.py` pools licence-verified HF datasets + our payloads/benign sets, removes exact and near duplicates (TF-IDF cosine ≥ 0.90), splits **by group** (a payload and its mutations stay together), holds out whole attack categories as an OOD split, and audits zero text overlap across splits. `train_detector.py` fine-tunes with early stopping; `calibrate.py` stores calibration probabilities.
**Questions**
1. *Why pool the datasets' own train/test splits?* — Calibration and test sets must be exchangeable for the guarantee; mixing "official test" sets with random calibration sets would break that.
2. *Leakage risks?* — Mutated variants (handled by grouping), templated benign prompts (near-duplicate removal), labels from public datasets we did not audit (stated limitation).
3. *Why is the OOD set small?* — Only our own 64 payloads have category labels; it indicates trend, not precise estimates (CIs are wide).

## 14. `frontend/*` — dashboard
**What:** Next.js App Router; typed API client with CSRF header + one silent refresh; heatmap (category × defense), Attack Lab with canary highlighting, Defense Builder, Experiments with progress polling, Conformal charts (Recharts) with legend + table view, Admin with "Verify chain".
**Safe rendering:** all LLM output/payloads are React text nodes (no `dangerouslySetInnerHTML`); canary highlighting uses `<mark>` around text spans computed by the backend.
**Questions**
1. *Where do XSS risks remain?* — Third-party packages and the `'unsafe-inline'` allowance in script-src needed by Next hydration (nonce CSP would tighten).
2. *Colour choices?* — Categorical blue/orange/aqua validated for colour-blind separation; heatmap is a one-hue ramp with numbers in cells; charts have legends and a table view.
3. *Why check `can()` in the UI if the server enforces roles?* — Only to hide buttons that would 403.

## 15. Likely "big picture" questions
1. **What exactly is novel?** — (a) canary-oracle evaluation across encodings with forbidden-tool detection and no LLM grader; (b) using per-class conformal prediction sets to decide escalation in an injection-defense cascade, evaluated for coverage, escalation rate and latency vs judge-only; (c) both inside a securely engineered, reproducible testbed.
2. **Biggest weaknesses?** — Static payload set; small target-app zoo; local 7B-class LLMs; exchangeability assumption; canary measures leakage only; payload authors = baseline authors; public-dataset labels unaudited.
3. **What would you do next?** — Adaptive (optimising) attackers against the cascade; online recalibration under drift; bigger/more realistic targets; external audit-log anchoring.
