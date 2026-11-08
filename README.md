# AgentFence

AgentFence is an open runtime enforcement gateway for tool-using AI agents. It
is the **action/tool plane** of an agentic AI firewall: prompt, retrieval, and
response filters reduce what reaches the model; AgentFence decides what the
model may do when it calls a tool.

Every tool call is treated as a transaction. The gateway authenticates a
task-scoped capability, evaluates deterministic default-deny policy, propagates
data labels and provenance, scans for encoded or split egress, optionally
escalates through a risk score, and routes sensitive actions to a hash-bound
human approval. Every decision is appended to an HMAC-authenticated audit chain.

The repository contains the FastAPI gateway, the embedded console, a simulated
tool sandbox, a 31-attack / 24-benign scenario suite, a reproducible evaluation
harness, and the test suite.

## Why this layer exists

Prompt injection creates an authorization problem, not only a content problem.
A model may be persuaded to use a permission it already holds. A content filter
can reduce the chance that the model is fooled, but it cannot decide whether the
resulting action is legitimate for the task, the data, and the destination.
AgentFence is the enforcement point for that decision.

It is deliberately scoped. It is not a complete AI firewall, a model safety
filter, a discovery platform, or a training-data defense. See
[`docs/positioning.md`](docs/positioning.md) for the four-plane model, the
OWASP ASI01–ASI10 coverage matrix, and the non-goals.

## What it enforces

- **Task-scoped capabilities.** Each task gets an explicit, expiring grant with
  allowed tools, paths, destinations, tables, call budgets, and rate limits.
- **Deterministic policy as final authority.** Default deny. The risk layer can
  tighten a decision but can never loosen it.
- **Provenance and taint.** Reads, writes, transforms, and round trips preserve
  trust and sensitivity labels through gateway-issued handles.
- **Encoding-aware DLP.** Base64, URL, hex, and split payloads are normalized,
  decoded, and reassembled across calls.
- **Human approval.** Sensitive actions pause on an exact preview and a
  single-use token bound to the resolved action hash.
- **Tamper-evident audit.** Every decision and effect is chained with HMAC.

## Quick start

Requirements: Python 3.11 or 3.12, [uv](https://docs.astral.sh/uv/), and
Node.js 20.19+ for the npm workflow.

```bash
uv sync --extra dev
uv run pytest
uv run agentfence demo          # end-to-end malicious-PDF walkthrough
uv run agentfence agent-demo    # scripted model through the enforcement loop
uv run agentfence serve --seed-demo
```

Without `uv`, install the same dependencies with
`python -m pip install -r requirements.txt`.

Open <http://127.0.0.1:8080>. On localhost the console pre-fills the demo admin
key. The default key and HMAC secret are for local development only; change
them before exposing the service:

```bash
uv run agentfence serve \
  --admin-key "replace-me" \
  --secret "replace-me-too" \
  --seed-demo
```

The server uses only simulated tools and canary credentials. No real email,
HTTP, database, or filesystem egress occurs outside the runtime sandbox.

## npm development

To run the console through Vite instead of the Python static server:

```bash
npm install
npm run dev
```

This starts FastAPI on <http://127.0.0.1:8080> and Vite on
<http://127.0.0.1:5173>. Vite proxies `/v1`, `/healthz`, `/docs`, and
`/openapi.json` to the API. Open the Vite URL for hot reload.

| Command | What it does |
|---|---|
| `npm run dev` | Start the API and Vite together |
| `npm run dev:api` | Start only the FastAPI gateway on :8080 |
| `npm run dev:web` | Start only Vite on :5173 |
| `npm run build` | Bundle the console into `frontend/dist` |
| `npm run preview` | Preview the bundle on :4173 with the API proxy |

The Python server remains the default deployment path: `uv run agentfence
serve` serves `frontend/index.html` directly. No Node build is required for
that mode. Set `AGENTFENCE_API_URL` to point the Vite proxy at a different API
origin, or use `npm run dev:web` when the gateway is already running.

## Console

The console is plain HTML, CSS, and JavaScript. FastAPI serves it directly from
`frontend/`; the npm workflow adds a Vite dev server for frontend work and a
bundling step. Neither mode needs a separate API process beyond the gateway.

| View | What it shows |
|---|---|
| Overview | Live decisions, effects, approvals, and audit health |
| Live demo | Curated B0–B5 attack lab with a fresh sandbox per run |
| Approvals | Pending actions with exact previews and hash-bound tokens |
| Audit log | Decision and effect chain with verification |
| Effects | Delivered simulated side effects |
| Experiments | Main matrix, ablations, detector sweeps, and latency |
| Coverage | Four firewall planes, OWASP ASI01–ASI10, best practices, non-goals |
| About | Scope, threat model, and operating notes |

## API

FastAPI serves interactive documentation at `/docs`. The main routes are:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Mode, enforcement, and audit-chain health |
| `POST` | `/v1/admin/tasks` | Create a task grant and bearer token |
| `GET` | `/v1/admin/tasks/{task_id}` | Inspect a grant |
| `POST` | `/v1/actions` | Submit a tool action for enforcement |
| `GET` | `/v1/admin/approvals` | List pending approvals |
| `POST` | `/v1/admin/approvals/{id}/approve` | Issue a single-use approval token |
| `POST` | `/v1/admin/approvals/{id}/deny` | Deny a pending action |
| `GET` | `/v1/admin/audit` | Read the audit chain |
| `GET` | `/v1/admin/audit/verify` | Verify the chain |
| `GET` | `/v1/admin/effects` | List delivered effects |
| `GET` | `/v1/admin/stats` | Dashboard counters |
| `GET` | `/v1/admin/results` | Experiment snapshots for the console |
| `GET` | `/v1/admin/demo/scenarios` | Curated demo catalogue |
| `POST` | `/v1/admin/demo/run` | Run a scenario in a fresh sandbox |
| `POST` | `/v1/admin/demo/seed` | Seed the live console |

Admin routes require the `X-Admin-Key` header. The action route requires a
bearer token from `/v1/admin/tasks`.

## Agent loop

`backend/llm/` is provider-neutral. An adapter returns one assistant turn; the
loop converts each requested tool call into a `ToolAction` and sends it through
the same `AgentFenceService.submit` path used by the HTTP API. There is no
adapter-to-tool shortcut.

```python
from backend.llm import Agent, ScriptedAdapter, tool_call
from backend.llm.base import LLMTurn
from backend.runtime.agent_loop import AgentLoop

agent = Agent(
    adapter=ScriptedAdapter([
        LLMTurn(tool_calls=(tool_call("file.read", {"path": "/project/docs/overview.md"}),)),
        LLMTurn(content="The overview is available."),
    ])
)
run = AgentLoop(service, agent, token).run("Read the overview.")
print(run.answer, run.executed, run.blocked)
```

`ScriptedAdapter` is deterministic and is what the tests and `agent-demo` use.
`CallableAdapter` wraps a function, so a real provider SDK can be connected
without changing the enforcement loop.

## Evaluation

The evaluation holds the model fixed and measures the enforcement layer. The
main matrix runs 31 attacks in seven classes and 24 benign tasks across eight
configurations, with five repeats of each cell.

```bash
# Main matrix: 2,200 episodes
uv run python -m experiments.run --out results/main --repeats 5

# Detector recall / false-positive sweep: 6,750 episodes
uv run python -m experiments.sweep --out results/sweep --trials 5

# Approval-policy sensitivity: B5 with every approval denied
uv run python -m experiments.run --out results/approval_deny \
  --modes B5 --repeats 5 --approval-mode deny_all
```

`results/` is generated locally and ignored by git. The console reads committed
snapshots in `frontend/results_*.json`, so it works without a prior experiment
run.

## Measured results

| Mode | ASR | TCR | False-block tasks | Approvals / benign |
|---|---:|---:|---:|---:|
| B0 (no protection) | 100.0% | 100.0% | 0 | 0.00 |
| B1 (prompt filter) | 83.9% | 100.0% | 0 | 0.00 |
| B2 (static RBAC) | 100.0% | 100.0% | 0 | 0.00 |
| B3 (risk-only block) | 45.2% | 95.8% | 1 | 0.00 |
| B4 (capabilities) | 61.3% | 95.8% | 1 | 0.00 |
| B5 (full) | 3.2% | 100.0% | 0 | 0.38 |
| B4T (capabilities + taint/DLP) | 3.2% | 66.7% | 8 | 0.00 |
| B4TR (B4T + risk block) | 3.2% | 62.5% | 9 | 0.00 |

The B5 residual is one semantic-paraphrase attack; a split attack also delivered
a 14-byte canary prefix before cross-call reassembly blocked the remainder.
B5's in-process end-to-end p50/p95/p99 latency is 0.20/1.57/2.78 ms. ASR and TCR
are scenario-level proportions over a fixed synthetic suite, not population
estimates.

## Repository layout

```text
backend/
  main.py                  FastAPI app, routes, and console serving
  cli.py                   demo, agent-demo, serve, verify-audit
  llm/                     base.py, adapter.py, agent.py
  runtime/                 agent_loop.py, interceptor.py, tool_executor.py
  security/                capabilities.py, policy_engine.py, risk_engine.py, approval.py
  audit/logger.py          HMAC-authenticated audit chain
  core/                    models, config, canonicalization, DLP, provenance
frontend/                  console HTML, CSS, JS, and result snapshots
experiments/               scenarios, runner, statistics, sweep, tables, figures
tests/                     grouped behavior tests plus detailed security tests
docs/positioning.md        four-plane model, OWASP coverage, non-goals
package.json               npm scripts and frontend dev dependencies
vite.config.js             Vite root, API proxy, and bundle output
requirements.txt           pip-installable dependency list
```

## Status and limitations

Research prototype. The evaluation holds the model fixed and measures the
enforcement layer; the included adapter is scripted, not a live model. Tools are
simulated, and latency excludes network and UI time. There is no container or
network isolation, no real LLM evaluation, and no human-approval user study;
approval experiments use a scripted approver. The gateway assumes trusted tool
adapters and does not verify model, plugin, or tool supply-chain artifacts.

The prototype is an action-plane enforcement mechanism. It should be deployed
alongside prompt, retrieval, and response controls, not as a replacement for
them.

## License

MIT. See [`LICENSE`](LICENSE).
