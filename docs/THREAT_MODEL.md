# PromptShield — Threat Model of the Platform

Scope: the **platform** (API, database, dashboard, experiment runner). The target apps are *deliberately vulnerable* test subjects and are out of scope for hardening — but the platform must stay safe while running them (see §4).

## 1. Assets and actors

| Asset | Why it matters |
|---|---|
| User accounts / sessions | Admin can create users, read the audit log; researchers run experiments |
| Audit log | Evidence of who did what; must be tamper-evident |
| Experiment data (results, payloads) | Research integrity; payloads are attack strings |
| LLM endpoint + credentials | Cost, availability; API key for hosted models |
| Canary tokens | Success oracle; random per run, not real secrets |
| Trained detector + calibration data | Integrity of the conformal guarantee |

Actors: anonymous internet user; authenticated `viewer` / `researcher` / `admin`; a malicious researcher; an attacker with DB write access (insider / SQL-level compromise); and — specially — *untrusted text* (attack payloads, RAG documents, e-mails, model output).

## 2. Trust boundaries (see ARCHITECTURE.md §3)

TB1 browser→API · TB2 API→DB · TB2→TB3 API→sandboxed target apps · TB3→TB4 apps→LLM/ML models.

## 3. STRIDE analysis

| | Threat | Mitigation in this codebase | Residual risk |
|---|---|---|---|
| **S**poofing | Credential stuffing / brute force | argon2id hashes; 5 failures → 15-min lockout (`api/auth.py`); per-IP *and* per-account login rate limits (`core/rate_limit.py`); identical error + equalised timing for unknown user (`core/security.py` dummy hash) | In-memory limiter is per-process (use Redis if replicated) |
| S | Stolen JWT / refresh token | 15-min access JWT, `httpOnly; Secure; SameSite=Strict` cookies; opaque refresh token stored only as SHA-256 hash, **rotated on every use**; re-use of a rotated token revokes the whole token family | Stolen token usable until expiry/rotation |
| S | JWT algorithm confusion (`alg:none`) | Algorithms pinned to HS256; `iss`, `exp`, `sub`, `type` required | Secret strength depends on `JWT_SECRET` (app refuses to start in production with the default) |
| **T**ampering | Edit/delete audit history | SHA-256 hash chain (`core/audit.py`), `/admin/audit/verify` finds modified or deleted-in-the-middle rows | An attacker who recomputes **all** later hashes, or truncates the tail, is not detected → anchor the head hash externally (documented limitation) |
| T | Cross-site request forgery | `SameSite=Strict` + double-submit CSRF token on every state-changing cookie-authenticated request + `Origin` check (`core/middleware.py`) | — |
| T | Mass assignment / unexpected fields | Every request model `extra="forbid"` with bounded string lengths (`api/schemas.py`); NUL bytes rejected | — |
| T | Tampering with defense configs | Stage types and parameters whitelisted (`defenses/registry.py`) — configs never reach `eval`/import | — |
| **R**epudiation | "I didn't run that experiment" | Login, failed login, lockout, refresh-reuse, role change, user create/disable, experiment run, lab run, config change, audit verify are all audited with actor id; passwords/tokens never logged | Read-only actions are not audited |
| **I**nformation disclosure | IDOR on experiments/configs | Ownership check in the query itself (`_visible_query`); other users' ids return **404**, not 403; viewers see only explicitly `shared` experiments | — |
| I | Secrets in logs | JSON logger redacts password/token/secret/cookie/canary keys and masks `CANARY-…`/JWT patterns in free text (`core/logging.py`) | Redaction is pattern-based |
| I | Path traversal when downloading exports | File names whitelisted + resolved path must stay inside the experiment folder | — |
| I | Verbose errors / docs | `/docs` and OpenAPI disabled when `APP_ENV=production`; generic auth errors | — |
| **D**enial of service | Request floods; huge bodies; expensive experiment spam | Rate limits (login/refresh/lab/experiment), 256 KiB body cap, per-field length caps, caps on experiment size (`max_payloads`, `n_variants`) | A researcher can still queue many allowed-size experiments; background jobs are in-process |
| D | LLM backend hangs | Client timeouts, bounded retries with backoff, run aborts after too many LLM errors | — |
| **E**levation of privilege | Viewer runs experiments / non-admin manages users | Roles enforced in FastAPI dependencies on every route (`core/rbac.py`), user re-read from DB each request (demotion/deactivation is immediate); matrix tested in `tests/test_security_suite.py` | — |
| E | **Prompt injection escaping the sandbox** (the platform-specific one) | Target tools are pure mocks: no file/network/process access (AST-tested in `tests/test_llm_and_tools.py`); worst outcome of a successful injection is a `ToolCall` log row | Real LLM output is untrusted data everywhere: rendered as text in the dashboard, never as HTML/markup |

## 4. Prompt-injection-specific considerations for the platform itself

1. **Attack payloads are stored, transported and displayed as inert text.** The dashboard never uses `dangerouslySetInnerHTML`; canary highlighting is done with React text nodes + `<mark>`.
2. **LLM output never drives platform actions.** Only the objective canary oracle decides success; no LLM judge result controls anything outside the experiment being measured.
3. **The LLM judge can itself be attacked.** The judged text is delimited and declared as data, JSON output is required, and unparseable output **fails closed** (counted as injection). This is a mitigation, not a proof.
4. **Canaries are random per run** (`secrets.token_hex`) and are not real credentials, so leaking one has no impact outside the experiment.
5. **Supply chain:** models are loaded from local `ml/artifacts` (user-trained). `transformers`/`torch` are only needed for DeBERTa inference.

## 5. Control → OWASP mapping

### OWASP Top 10 (2021)

| ID | Category | Controls |
|---|---|---|
| A01 | Broken Access Control | RBAC dependencies; ownership-scoped queries; 404 for foreign ids; CSRF; CORS pinned to one origin |
| A02 | Cryptographic Failures | argon2id; HS256 JWT with ≥256-bit secret from env; refresh tokens hashed (SHA-256); HSTS; Secure cookies |
| A03 | Injection | SQLAlchemy parameterised queries only; Pydantic validation; NUL/length limits; defense-config whitelist; tested with SQLi/XSS/template strings in every text field |
| A04 | Insecure Design | Threat model (this file); sandboxed mock tools; fail-closed judge/pipeline; hash-chained audit log by design |
| A05 | Security Misconfiguration | Security headers (CSP, HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy); docs off in production; app refuses default JWT secret in production; non-root containers; Postgres bound to loopback |
| A06 | Vulnerable & Outdated Components | Pinned version ranges; `npm audit` reviewed (remaining findings are in the Tailwind-3/PostCSS build chain — see README); recommended: Dependabot / `pip-audit` in CI |
| A07 | Identification & Authentication Failures | Lockout, rate limiting, argon2id + rehash on login, short-lived tokens, refresh rotation + reuse detection, no user enumeration |
| A08 | Software & Data Integrity Failures | Hash-chained audit log; reproducible seeded experiments with resolved defense config stored per run; exports stamped with run id/model/seed |
| A09 | Logging & Monitoring Failures | Structured JSON logs with redaction; security-event audit trail with verification endpoint |
| A10 | SSRF | No user-supplied URLs are ever fetched; `LLM_BASE_URL` is operator-set environment config; mock tools make no network calls |

### OWASP Top 10 for LLM Applications (2025 numbering — verify against the current OWASP page; v1.1 used different numbers)

| ID | Risk | How PromptShield relates |
|---|---|---|
| LLM01 | Prompt Injection | **The subject of the project:** 64 attack payloads (direct, indirect, obfuscated, multi-turn…), defenses, objective canary measurement |
| LLM02 | Sensitive Information Disclosure | Canary tokens model secrets in prompts; output guard + conformal cascade evaluated on preventing leakage |
| LLM03 | Supply Chain | Detector trained locally from licence-checked datasets (`ml/data/stats.json` records licences); no remote model code executed except via `transformers` |
| LLM04 | Data & Model Poisoning | Training data are deduplicated, grouped, licence-verified; data-poisoning attacks on the detector are **not** evaluated (limitation) |
| LLM05 | Improper Output Handling | Output guard; frontend renders model output as text; platform never executes model output |
| LLM06 | Excessive Agency | Email agent deliberately over-privileged (forbidden tools exposed); tools are mocks; forbidden-tool call = attack success; output guard blocks them pre-execution |
| LLM07 | System Prompt Leakage | `prompt_extraction` attack category; canary in system prompt |
| LLM08 | Vector & Embedding Weaknesses | RAG poisoning via planted documents (`indirect_injection` payloads) |
| LLM09 | Misinformation | Out of scope |
| LLM10 | Unbounded Consumption | Timeouts, retries cap, rate limits, experiment size caps |

## 6. Known limitations (honest list)

* Single-process rate limiter and in-process background jobs (no queue); restart loses running jobs.
* Audit chain cannot detect truncation of the newest rows or a full recompute by a privileged DB attacker without an external anchor.
* The canary oracle measures *leakage and forbidden actions*, not every possible harm (e.g. persuasion, misinformation).
* CSP for the Next.js frontend must allow inline scripts for hydration (`'unsafe-inline'`); a nonce-based CSP would be stricter.
* Cookie `Secure` flag: Safari does not accept Secure cookies over plain `http://localhost` — set `COOKIE_SECURE=false` only for such local testing.
