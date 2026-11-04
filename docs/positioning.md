# AgentFence as the Action Plane of an Agentic AI Firewall

AgentFence is not a complete AI firewall. It is the **action/tool enforcement
plane** of one. That plane is where an agent's intent becomes a side effect, and
it is the plane a content filter cannot enforce.

## 1. The five functions of an AI firewall

AgentFence implements part of each function and is strongest where an action
becomes consequential.

| AI-firewall function | What it means | AgentFence today | Status |
|---|---|---|---|
| Traffic inspection and filtering | Inspect prompts, API requests, and model outputs for harmful or non-compliant content | Injection score on action text and decoded variants; DLP on outgoing payloads | Partial: action-level, not full semantic model I/O |
| Prompt injection and data poisoning | Block or sanitize injected instructions; detect poisoned training or retrieval data | Task-scoped authority, provenance taint, confidential-egress ban; A1 suite | Partial: runtime injection containment, no training-data defense |
| Behavioral analysis | Baseline query frequency, input types, and output patterns; detect drift and probing | Call-rate, repeated-action, and budget anomaly factors; audit trail | Partial: per-task heuristics, no cross-session baseline |
| Compliance and data governance | Enforce GDPR/HIPAA-style rules; mask, redact, or block; retain audit evidence | Deterministic policy, DLP, approvals, HMAC audit chain | Strong on enforcement and evidence; no regulatory mapping or redaction |
| Threat intelligence and red teaming | Ingest indicators; run adversarial exercises; tune defenses | 31-scenario attack suite, detector sweeps, deny-all sensitivity run | Strong on reproducible red teaming; no live threat-intel feed |

The table lets the project claim depth without claiming breadth it does not
have.

## 2. The four LLM-firewall planes

1. **Prompt firewall** — screens and sanitizes user input before the model.
2. **Retrieval firewall** — protects the RAG pipeline from poisoned or
   untrusted context.
3. **Response firewall** — filters model output for leakage, toxicity, or
   policy violations.
4. **Agent/tool firewall** — constrains which tools, APIs, and side effects the
   model may invoke.

AgentFence is a full implementation of plane 4 and a partial implementation of
planes 1–3:

- **Prompt plane:** the injection detector scores action text, but does not
  sanitize or rewrite prompts.
- **Retrieval plane:** provenance labels fetched documents, web pages, and tool
  output as untrusted, and taint follows them into later actions. Embedding and
  persistent-memory poisoning are not checked.
- **Response plane:** DLP scans outgoing action payloads for credentials and
  PII. Tone, toxicity, and hallucination are out of scope.
- **Action plane:** capabilities, deterministic policy, approvals, and audit.
  This is the contribution.

This framing explains why a perfect prompt filter still leaves 80.7% attack
success in the evaluation: the violation is often in the relationship between
the action, the task, and the data, not in a suspicious string.

## 3. OWASP ASI01–ASI10 coverage

The mapping is deliberately conservative.

| Risk | AgentFence control | Status |
|---|---|---|
| **ASI01 Agent goal hijack** | Task-scoped capabilities, provenance taint, confidential-egress ban; A1 exercises injected content | Covered |
| **ASI02 Tool misuse and exploitation** | Least-privilege grants, path/destination scope, rate and call budgets; A2, A3, A6 | Covered |
| **ASI03 Tool-layer manipulation** | Trusted adapters assumed; no metadata or routing integrity check | Out of scope |
| **ASI04 Agentic supply chain** | No AIBOM/SBOM, signature verification, or dependency attestation | Out of scope |
| **ASI05 Unexpected code execution** | No code-execution tool in the prototype; no sandbox-escape defense | Out of scope |
| **ASI06 Memory and context poisoning** | Retrieved content is labelled untrusted and tainted; no embedding or persistent-memory integrity | Partial |
| **ASI07 Insecure inter-agent communication** | Single-agent gateway; no agent-to-agent authentication | Out of scope |
| **ASI08 Cascading failures** | Per-task budgets and approval gates; no cross-agent circuit breaker or rollback | Partial |
| **ASI09 Human-agent trust exploitation** | Exact preview, hash-bound single-use token, audit trail; no human-factors study | Covered |
| **ASI10 Rogue agents** | Scope, expiry, budgets, audit; no kill switch or rollback yet | Partial |

The value of the table is that it makes the gaps legible. AgentFence does not
pretend to solve supply-chain security, RCE, or multi-agent trust.

## 4. Best-practice alignment

1. **Capability-scoped tools and least privilege — implemented.** Every task
   receives an explicit grant; unnamed tools are denied; paths, destinations,
   tables, and budgets narrow the grant.
2. **Credentials and budgets bound to the action — implemented.** The bearer
   token commits to the full grant, and call/rate budgets travel with the task.
   A production system could shorten this further to per-action credentials.
3. **Separate instructions from content — partial.** Provenance labels
   untrusted content and taint follows it, but prompts are not sanitized or
   restructured into a typed instruction/data format.
4. **Human approval for high-impact actions — implemented.** Sensitive calls
   pause on a hash-bound, single-use token with an exact preview.
5. **AIBOM/SBOM and signatures — roadmap.** The gateway does not verify model,
   plugin, or tool artifacts.
6. **Kill switch and rollback — roadmap.** Task expiry is the current stop
   condition; operator revocation and state rollback are not implemented.

## 5. Category positioning

The commercial landscape clusters into five categories:

- **Runtime protection and posture management** — agent discovery, intent-based
  runtime defense, audit-ready reports.
- **Governance and audit** — registries, policy packs, regulatory frameworks,
  trace evaluation.
- **AI security posture management (AI-SPM)** — cloud discovery, AI-BOMs,
  attack-path analysis.
- **AI red teaming and model security** — model scanning, attack simulation,
  runtime detection.
- **Identity-centric agent governance** — agent identities, least privilege,
  access reviews.

AgentFence sits in the first category with a narrower and deeper claim: an open,
measured enforcement mechanism for the action plane, not a discovery or
governance platform. It complements the other categories rather than replacing
them.

## 6. Claims to avoid

- "AgentFence is a complete AI firewall." It is one plane.
- "AgentFence stops prompt injection." It contains the action, not the model's
  susceptibility.
- "AgentFence prevents data poisoning." It labels untrusted runtime content; it
  does not inspect training data.
- "AgentFence provides compliance." It provides enforceable policy and audit
  evidence; regulatory mapping is a separate layer.
- "AgentFence replaces a governance platform." It assumes the agent, tools, and
  policies are already known.

## 7. Sources

- OWASP Top 10 for LLM Applications (2025).
- OWASP Agentic AI — Threats and Mitigations (2025), ASI01–ASI10.
- NIST AI 100-2, *Adversarial Machine Learning: A Taxonomy and Terminology of
  Attacks and Mitigations* (2024).
