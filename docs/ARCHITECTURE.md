# PromptShield — Architecture

PromptShield is a testbed with two jobs: (1) **attack** deliberately vulnerable LLM apps with a library of prompt-injection payloads, and (2) **evaluate defenses** against those attacks, including a conformal-prediction-gated cascade.

> Status: all components below are implemented (Phases 0-8). "(Phase N)" tags show where each part was built.

## 1. Component diagram

```mermaid
flowchart LR
    subgraph Browser["User's browser"]
        UI["Next.js dashboard<br/>(Phase 7)"]
    end

    subgraph Compose["docker-compose network"]
        subgraph API["FastAPI backend"]
            SEC["Security layer<br/>auth · RBAC · rate limit · CSRF · headers<br/>(Phase 1)"]
            ROUTES["API routers<br/>auth · targets · attacks · defenses · experiments · admin"]
            AUDIT["Hash-chained audit log<br/>(Phase 1)"]
            EVAL["Evaluation harness<br/>runner · canary checker · metrics · export<br/>(Phases 3, 6)"]
            ATK["Attack library + mutator<br/>(Phase 3)"]
            TGT["Vulnerable target apps<br/>RAG bot · Email agent · Support bot<br/>+ mock tools (Phase 2)"]
            DEF["Defense pipeline<br/>sanitizer · spotlighting · output guard<br/>classifier · LLM judge · conformal cascade<br/>(Phases 4-5)"]
            LLMC["LLMClient<br/>OpenAI-compatible (Phase 2)"]
        end
        DB[("PostgreSQL 16<br/>users · audit log · experiments<br/>results · tool calls")]
    end

    subgraph Host["Host machine"]
        OLLAMA["Ollama<br/>qwen2.5:7b-instruct / llama3.1:8b"]
        MODEL["DeBERTa-v3-small detector<br/>+ conformal quantiles<br/>(CPU inference, trained offline)"]
    end

    UI -- "HTTPS, httpOnly cookies" --> SEC --> ROUTES
    ROUTES --> AUDIT --> DB
    ROUTES --> EVAL
    EVAL --> ATK
    EVAL --> TGT
    TGT <--> DEF
    TGT --> LLMC
    DEF --> LLMC
    DEF --> MODEL
    LLMC -- "HTTP, OpenAI-compatible" --> OLLAMA
    EVAL --> DB
    ROUTES --> DB
```

## 2. Data flow: one attack against one target

The defense pipeline wraps the target at two points: **input inspection** (before the user/untrusted content reaches the target LLM) and **output inspection** (before the response is returned or tools are executed).

```mermaid
sequenceDiagram
    autonumber
    participant R as Runner / Attack Lab
    participant P as Defense pipeline
    participant C as Conformal cascade
    participant J as LLM judge
    participant T as Target app
    participant L as LLM (Ollama)
    participant K as Canary checker
    participant D as DB

    R->>P: payload (direct text or planted in doc/email)
    P->>P: sanitize (NFKC, strip zero-width, decode+rescan)
    P->>C: inspect_input(text)
    C->>C: classifier p(injection) → conformal prediction set
    alt set = {benign}
        C-->>P: allow
    else set = {injection}
        C-->>P: block
    else set = {benign, injection} or empty
        C->>J: escalate (uncertain)
        J->>L: strict-rubric verdict request
        L-->>J: JSON verdict + confidence
        J-->>C: allow / block
        C-->>P: final decision
    end
    alt blocked
        P-->>R: refusal, no target call
    else allowed
        P->>T: run(user_input, context) [spotlighted]
        T->>L: chat completion (system prompt holds canary)
        L-->>T: text + requested tool calls
        T->>P: inspect_output(text, tool_calls)
        P-->>R: TargetResponse(text, tool_calls, latency)
    end
    R->>K: did canary appear (plain/b64/hex/reversed/spaced/partial) or a forbidden tool run?
    K-->>R: success = true/false (objective, no LLM judge)
    R->>D: store result, tool calls, latency, decisions
```

## 3. Trust boundaries

```mermaid
flowchart TB
    subgraph TB1["TB1 — Untrusted: internet / browser"]
        U["Users, attackers"]
    end
    subgraph TB2["TB2 — Platform (trusted, authenticated)"]
        A["FastAPI: authN/authZ, validation,<br/>rate limits, audit chain"]
        DBX[("PostgreSQL")]
    end
    subgraph TB3["TB3 — Experiment sandbox (deliberately vulnerable)"]
        TG["Target apps + mock tools<br/>(no real FS / network / email)"]
        UC["Untrusted content:<br/>attack payloads, RAG docs, emails"]
    end
    subgraph TB4["TB4 — Model services"]
        LL["Ollama / hosted LLM"]
        ML["Detector weights"]
    end

    U -- "TB1→TB2: cookies, CSRF token,<br/>schema-validated JSON" --> A
    A <--> DBX
    A -- "TB2→TB3: run experiment" --> TG
    UC -- "injected into prompts" --> TG
    TG -- "TB3→TB4: prompts" --> LL
    A -- "inference" --> ML
```

| Boundary | What crosses it | Controls |
|---|---|---|
| TB1 → TB2 | HTTP requests from browser | argon2id login, short-lived JWT + rotating refresh, httpOnly/Secure/SameSite=Strict cookies, CSRF check, RBAC dependency, Pydantic limits (`extra=forbid`), rate limits, CSP/HSTS headers, CORS pinned to frontend origin |
| TB2 ↔ DB | SQL | SQLAlchemy parameterised queries only; credentials from env; audit rows hash-chained |
| TB2 → TB3 | Experiment runs | Only `researcher`/`admin` may run; each run audited |
| Untrusted content → TB3 | Attack payloads, poisoned docs/emails | This is the *thing under test*; defenses sit here. Payloads are stored and rendered as inert text |
| TB3 → outside | Tool calls | Tools are pure mocks that write a `ToolCall` row; they cannot touch the real filesystem or network |
| TB3 → TB4 | Prompts to the LLM | Local Ollama by default; canaries are random per-run tokens, not real secrets |

**Key principle:** the target apps are *intentionally* insecure and live inside the sandbox boundary (TB3). The platform around them (TB2) is built to be secure. The two are never mixed: a successful injection can at worst make a mock tool log a row.

## 4. Deployment

| Service | Image / source | Port | Notes |
|---|---|---|---|
| `db` | `postgres:16` | 127.0.0.1:5432 | Named volume `pgdata`; healthcheck gates backend start |
| `backend` | `./backend` (python:3.11-slim, non-root) | 8000 | On start: `alembic upgrade head`, seed admin, serve. Mounts `ml/artifacts` (ro) and `results/` |
| `frontend` | `./frontend` (node:22-alpine, standalone build, non-root) | 3000 | Next.js dashboard |
| Ollama | **host**, not compose | 11434 | Reached from containers as `host.docker.internal` |

## 5. Cascade decision logic (core contribution)

```mermaid
flowchart TD
    X["input text"] --> S["sanitizer (optional): normalise, decode, rules"]
    S --> C["classifier: p = P(injection)"]
    C --> Q["Mondrian conformal set at alpha<br/>C = {y : 1 - p_y <= q_y}"]
    Q -->|"{benign}"| A["ALLOW - no LLM call"]
    Q -->|"{injection}"| B["BLOCK - no LLM call"]
    Q -->|"{benign,injection} or {}"| J["ESCALATE to LLM judge"]
    J -->|"benign"| A
    J -->|"injection / unparseable (fail-closed)"| B
```

## 6. Experiment data flow

`POST /experiments` (researcher/admin, rate-limited, audited) → row `queued` → background job → for each *(target × defense × attack|benign)*: fresh pipeline + fresh target (fresh canary) → `ExperimentResult` (+ `ToolCall` rows) → `metrics.full_summary` (bootstrap CIs) → `experiments.summary` JSON → `results/<run-id>/` exports. The dashboard reads only these stored results.
