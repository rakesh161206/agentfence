/* AgentFence console: vanilla JS, no build step. */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const ROUTES = ["overview", "demo", "approvals", "audit", "effects", "experiments", "coverage", "about"];
const ROUTE_TITLES = {
  overview: "Home",
  demo: "Try a scenario",
  approvals: "Approvals",
  audit: "Decision log",
  effects: "Actions taken",
  experiments: "Test results",
  coverage: "What's covered",
  about: "About",
};
const MODES = ["B0", "B1", "B2", "B3", "B4", "B5"];
const MODE_LABELS = {
  B0: "no protection",
  B1: "prompt filter",
  B2: "static rules",
  B3: "risk score",
  B4: "permissions",
  B5: "full protection",
  B4T: "permissions + data tracking",
  B4TR: "permissions + data tracking + risk",
};
const MODE_DESCRIPTIONS = {
  B0: "No protection. Every action runs, so you can see what the attack does.",
  B1: "Screens text before the model sees it. Does not check what the agent does next.",
  B2: "Blocks known-bad tools and destinations with fixed rules.",
  B3: "Scores each action for risk and raises an alert when it looks dangerous.",
  B4: "Limits which tools, files, and destinations the agent may use.",
  B5: "Full protection: permissions, data tracking, risk checks, and human approval.",
};
const FAMILY_LABELS = {
  A1: "Goal hijack",
  A2: "Data theft",
  A3: "File access",
  A4: "Laundering",
  A5: "Hidden data",
  A6: "Tool misuse",
  A7: "Approval replay",
  BENIGN: "Normal task",
};
const POLICY_LABELS = {
  approve: "a person approves it",
  deny: "a person blocks it",
  leave: "it stays waiting",
};
const DECISION_LABELS = {
  ALLOW: "Allowed",
  BLOCK: "Blocked",
  REQUIRE_APPROVAL: "Needs approval",
  DENIED: "Denied",
  SKIPPED: "Skipped",
  PENDING: "Waiting",
};
const RULE_LABELS = {
  R1: "Bad request",
  R2: "File outside scope",
  R3: "Destination not allowed",
  R4: "Sensitive data leaving",
  R4b: "Split secret",
  R6: "Untrusted source",
  R7: "Risk too high",
  R8: "Needs approval",
  R9: "Approval mismatch",
  PF1: "Prompt injection",
};
const TOOL_LABELS = {
  "file.read": "Read a file",
  "file.write": "Write a file",
  "email.send": "Send an email",
  "http.get": "Fetch a web page",
  "http.post": "Send data to a website",
  "db.query": "Query the database",
  "data.derive": "Combine information",
};
const TOOL_ACTIONS = {
  "file.read": "read a file",
  "file.write": "write a file",
  "email.send": "send an email",
  "http.get": "fetch a web page",
  "http.post": "send data to a website",
  "db.query": "query the database",
  "data.derive": "combine information",
};
const EVENT_LABELS = {
  ACTION: "Action checked",
  APPROVAL_REQUESTED: "Sent for approval",
  APPROVAL_APPROVED: "Approved by a person",
  APPROVAL_DENIED: "Blocked by a person",
  TASK_CREATED: "Task started",
};
const RULE_DESCRIPTIONS = {
  R1: "Authentication, task validity, or malformed action.",
  R2: "Canonical path outside the task's path scope.",
  R3: "Destination or recipient outside the allow-list.",
  R4: "Confidential data leaving without an explicit grant.",
  R4b: "Cross-call reassembly exposed a split secret.",
  R6: "Untrusted provenance reached a high-risk tool.",
  R7: "Composite risk score exceeded the escalation threshold.",
  R8: "The capability requires human approval.",
  R9: "The approval token does not match the exact action.",
  PF1: "Prompt-injection filter flagged the content.",
  R6b: "Repeated identical action (loop protection).",
};

const isLocal = ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
const storedKey = sessionStorage.getItem("agentfence.adminKey");
const state = {
  key: storedKey || (isLocal ? "agentfence-admin-key" : ""),
  route: "overview",
  stats: null,
  approvals: [],
  selectedApproval: null,
  audit: [],
  auditVerification: null,
  effects: [],
  results: null,
  resultsError: "",
  scenarios: [],
  scenariosError: "",
  demo: {
    scenarioId: "a1-injection",
    mode: "B5",
    policy: "approve",
    result: null,
    comparison: null,
    running: false,
    runLabel: "",
  },
  filters: {
    auditDecision: "",
    auditSearch: "",
  },
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function num(value, digits = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

function pct(value, digits = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return `${(n * 100).toFixed(digits)}%`;
}

function ms(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(2)} ms`;
}

function bytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  if (n < 1024) return `${num(n)} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

function clock(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function shortHash(value, length = 12) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function decisionBadge(decision) {
  const value = decision || "—";
  return `<span class="badge ${esc(value)}">${esc(DECISION_LABELS[value] || value)}</span>`;
}

function riskLevel(score) {
  const value = Number(score) || 0;
  if (value >= 0.66) return "high";
  if (value >= 0.33) return "medium";
  return "low";
}

function toolLabel(tool) {
  if (!tool) return "—";
  return TOOL_LABELS[tool] || tool;
}

function familyLabel(family) {
  return FAMILY_LABELS[family] || family || "";
}

function toolAction(tool) {
  return TOOL_ACTIONS[tool] || "use a tool";
}

function eventLabel(event) {
  return EVENT_LABELS[event] || event || "";
}

function verdictClass(verdict) {
  return ["blocked", "leaked", "unsafe", "completed", "pending", "false_block"].includes(verdict)
    ? verdict
    : "pending";
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.key) headers["X-Admin-Key"] = state.key;
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_) {
      /* ignore non-JSON errors */
    }
    const error = new Error(`${response.status}: ${detail}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

let toastTimer = null;
function toast(message, kind = "") {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast show ${kind}`.trim();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.className = "toast";
  }, 4200);
}

function setKey(value) {
  state.key = value.trim();
  sessionStorage.setItem("agentfence.adminKey", state.key);
  $("#adminKey").classList.remove("invalid");
}

function updateChrome() {
  const stats = state.stats;
  const mode = stats ? stats.mode : "—";
  $("#modePill").textContent = stats ? `protection: ${mode}` : "offline";
  $("#modePill").className = `pill ${stats ? "ok" : "bad"}`;

  const verification = state.auditVerification || (stats && stats.audit);
  const chainOk = verification && verification.ok;
  $("#chainPill").textContent = verification
    ? (chainOk ? "chain: verified" : "chain: BROKEN")
    : "chain: ?";
  $("#chainPill").className = `pill ${verification ? (chainOk ? "ok" : "bad") : ""}`.trim();

  const side = $("#sideChain");
  side.className = `chain-card ${verification ? (chainOk ? "ok" : "bad") : ""}`.trim();
  side.innerHTML = `
    <span class="chain-dot"></span>
    <div>
      <strong>Audit chain</strong>
      <small>${verification ? (chainOk ? `${num(verification.entries)} entries · verified` : "verification failed") : "connecting…"}</small>
    </div>`;

  const pending = state.approvals.length;
  $("#navApprovals").textContent = pending;
  $("#navApprovals").className = `nav-count ${pending ? "" : "zero"}`.trim();
}

async function refreshLive({ silent = false } = {}) {
  try {
    const [stats, approvals, audit, effects] = await Promise.all([
      api("/v1/admin/stats"),
      api("/v1/admin/approvals?status=pending"),
      api("/v1/admin/audit?limit=300"),
      api("/v1/admin/effects"),
    ]);
    state.stats = stats;
    state.approvals = approvals;
    state.audit = audit.entries || [];
    state.auditVerification = audit.verification || stats.audit;
    state.effects = effects || [];
    updateChrome();
    if (["overview", "approvals", "audit", "effects"].includes(state.route)) {
      renderRoute();
    }
  } catch (error) {
    if (error.status === 401) {
      state.stats = null;
      updateChrome();
      $("#adminKey").classList.add("invalid");
      if (!silent) toast("Admin key rejected. Use agentfence-admin-key for the local demo.", "bad");
    } else if (!silent) {
      toast(error.message, "bad");
    }
  }
}

async function loadScenarios() {
  try {
    state.scenarios = await api("/v1/admin/demo/scenarios");
    state.scenariosError = "";
  } catch (error) {
    state.scenariosError = error.message;
  }
  if (state.route === "demo") renderDemoPage();
}

async function loadResults() {
  try {
    state.results = await api("/v1/admin/results");
    state.resultsError = "";
  } catch (error) {
    state.resultsError = error.message;
  }
  if (state.route === "overview" || state.route === "experiments") renderRoute();
}

function currentRoute() {
  const raw = window.location.hash.replace(/^#\/?/, "").split("?")[0];
  return ROUTES.includes(raw) ? raw : "overview";
}

function renderRoute({ scroll = false } = {}) {
  const route = currentRoute();
  state.route = route;
  $$(".page").forEach((page) => page.classList.toggle("active", page.id === `page-${route}`));
  $$("#nav button").forEach((button) => {
    const active = button.dataset.route === route;
    button.classList.toggle("active", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  });
  $("#crumb").textContent = ROUTE_TITLES[route];
  if (route === "overview") renderOverview();
  if (route === "demo") renderDemoPage();
  if (route === "approvals") renderApprovals();
  if (route === "audit") renderAudit();
  if (route === "effects") renderEffects();
  if (route === "experiments") renderExperiments();
  if (scroll) window.scrollTo({ top: 0, behavior: "smooth" });
}

/* ------------------------------------------------------------------ overview */

function renderOverview() {
  const main = state.results && state.results.main;
  const b5 = main && main.by_mode && main.by_mode.B5;
  const total = b5 ? Number(b5.attack.n_scenarios) : 31;
  const stopped = b5 ? Math.max(0, total - Number(b5.attack.successes)) : 30;
  const benign = b5 ? Number(b5.benign.n_scenarios) : 24;
  const completed = b5 ? Number(b5.benign.completed) : 24;
  const latency = b5 ? Number(b5.latency.end_to_end.p95) : 1.57;
  const asr = b5 ? Number(b5.attack.asr) : 0.032;

  const cards = [
    {
      value: `${num(stopped)} of ${num(total)}`,
      label: "attacks stopped",
      note: "Full protection let one carefully reworded attack through.",
      cls: "ok",
      icon: "✓",
    },
    {
      value: `${num(completed)} of ${num(benign)}`,
      label: "normal tasks completed",
      note: "No legitimate work was blocked.",
      cls: "ok",
      icon: "✓",
    },
    {
      value: `${latency.toFixed(1)} ms`,
      label: "per decision",
      note: "Fast enough to check every action.",
      cls: "",
      icon: "→",
    },
  ];
  $("#overviewKpis").innerHTML = cards.map((item) => `
    <div class="result-card ${item.cls}">
      <span class="result-icon">${item.icon}</span>
      <div class="result-value">${esc(item.value)}</div>
      <div class="result-label">${esc(item.label)}</div>
      <p>${esc(item.note)}</p>
    </div>`).join("");

  $("#overviewCompare").innerHTML = `
    <div class="compare-list">
      <div class="compare-row">
        <div class="compare-label"><strong>Without AgentFence</strong><span>No protection</span></div>
        <div class="compare-track"><span class="compare-fill bad" style="width:100%"></span></div>
        <div class="compare-value">100%</div>
      </div>
      <div class="compare-row">
        <div class="compare-label"><strong>With AgentFence</strong><span>Full protection</span></div>
        <div class="compare-track"><span class="compare-fill ok" style="width:${Math.max(2, asr * 100)}%"></span></div>
        <div class="compare-value">${pct(asr, 1)}</div>
      </div>
    </div>
    <p class="compare-note">Attacks that got through. Lower is better.</p>
    <div class="compare-foot">
      <span><strong>${num(completed)} of ${num(benign)}</strong> normal tasks completed</span>
      <span><strong>${num(b5 ? b5.benign.false_block_tasks : 0)}</strong> false blocks</span>
    </div>`;

  renderOverviewLive();
}

function renderOverviewLive() {
  const stats = state.stats;
  if (!stats) {
    $("#overviewLive").innerHTML = `
      <div class="empty-state" style="min-height:170px">
        <h2>Not connected</h2>
        <p>Enter the admin key in the top bar. The local demo key is <span class="mono">agentfence-admin-key</span>.</p>
      </div>`;
    return;
  }
  const decisions = stats.decisions || {};
  const entries = state.audit.slice().sort((a, b) => b.seq - a.seq).slice(0, 4);
  const recent = entries.length
    ? `<div class="recent-list">${entries.map((entry) => `
        <div class="recent-row">
          <span class="t">${esc(clock(entry.timestamp))}</span>
          <div>
            <div class="tool">${esc(entry.tool ? toolLabel(entry.tool) : eventLabel(entry.event))}</div>
            <div class="reason">${esc((entry.reasons || [])[0] || eventLabel(entry.event) || "")}</div>
          </div>
          ${decisionBadge(entry.decision || entry.event)}
        </div>`).join("")}</div>`
    : `<div class="notice">No activity yet. <button class="btn small primary" data-seed>Load sample activity</button></div>`;
  $("#overviewLive").innerHTML = `
    <div class="live-grid live-grid-3">
      <div class="live-stat"><div class="k">Blocked</div><div class="v bad">${num(decisions.block)}</div><div class="s">actions stopped</div></div>
      <div class="live-stat"><div class="k">Allowed</div><div class="v good">${num(decisions.allow)}</div><div class="s">actions that ran</div></div>
      <div class="live-stat"><div class="k">Waiting for a person</div><div class="v warn">${num(stats.approvals_pending)}</div><div class="s">pending approvals</div></div>
    </div>
    ${recent}
    <div class="live-foot">
      <span class="muted small">${stats.audit && stats.audit.ok ? "✓ Log verified" : "Log needs attention"}</span>
      <a class="link" href="#/audit">See all decisions →</a>
    </div>`;
}

/* ---------------------------------------------------------------------- demo */

function selectedScenario() {
  return state.scenarios.find((scenario) => scenario.id === state.demo.scenarioId) || null;
}

function renderDemoPage() {
  renderScenarioList();
  renderModePicker();
  const select = $("#policySelect");
  if (select) select.value = state.demo.policy;
  renderDemoPanel();
}

function renderScenarioList() {
  const list = $("#scenarioList");
  if (state.scenariosError) {
    list.innerHTML = `<div class="notice bad">${esc(state.scenariosError)}</div>`;
    $("#scenarioCount").textContent = "";
    return;
  }
  if (!state.scenarios.length) {
    list.innerHTML = `<p class="hint">Loading scenarios…</p>`;
    return;
  }
  $("#scenarioCount").textContent = `${state.scenarios.length} scenarios`;
  const attacks = state.scenarios.filter((scenario) => scenario.kind === "attack");
  const benign = state.scenarios.filter((scenario) => scenario.kind === "benign");
  const item = (scenario) => `
    <button class="scenario-item ${scenario.id === state.demo.scenarioId ? "active" : ""}" data-scenario="${esc(scenario.id)}">
      <div class="top">
        <span class="title">${esc(scenario.title)}</span>
        <span class="family ${esc(scenario.kind)}" title="${esc(scenario.family)}">${esc(familyLabel(scenario.family))}</span>
      </div>
      <div class="summary">${esc(scenario.summary)}</div>
    </button>`;
  list.innerHTML = `
    <div class="list-label">Attack scenarios</div>
    ${attacks.map(item).join("")}
    <div class="list-label">Benign controls</div>
    ${benign.map(item).join("")}`;
}

function renderModePicker() {
  $("#modePicker").innerHTML = MODES.map((mode) => `
    <button data-mode="${mode}" class="${mode === state.demo.mode ? "active" : ""}" title="${esc(MODE_LABELS[mode] || mode)}">${mode}</button>`).join("");
  const description = $("#modeDescription");
  if (description) {
    description.textContent = `${state.demo.mode} · ${MODE_LABELS[state.demo.mode]}. ${MODE_DESCRIPTIONS[state.demo.mode] || ""}`;
  }
}

function renderDemoPanel() {
  const panel = $("#demoResult");
  if (state.demo.running) {
    panel.className = "card result-empty";
    panel.innerHTML = `
      <div class="spinner" aria-hidden="true"></div>
      <h2>${esc(state.demo.runLabel || "Running scenario…")}</h2>
      <p>Building a fresh sandbox, creating the task grant, and replaying the action trace.</p>`;
    return;
  }
  if (
    state.demo.comparison
    && (state.demo.comparison.error || (state.demo.comparison.results && state.demo.comparison.results.length))
  ) {
    panel.className = "card";
    panel.innerHTML = renderComparison(state.demo.comparison);
    return;
  }
  if (state.demo.result) {
    panel.className = "card";
    panel.innerHTML = renderResult(state.demo.result);
    return;
  }
  const scenario = selectedScenario();
  if (!scenario) {
    panel.className = "card result-empty";
    panel.innerHTML = `<h2>Select a scenario</h2><p>The scenario catalogue is loading.</p>`;
    return;
  }
  panel.className = "card";
  panel.innerHTML = renderScenarioIntro(scenario);
}

function renderScenarioIntro(scenario) {
  return `
    <div class="demo-intro">
      <div class="demo-intro-head">
        <div>
          <span class="eyebrow">${esc(familyLabel(scenario.family))} · ${esc(scenario.kind)}</span>
          <h2>${esc(scenario.title)}</h2>
          <p>${esc(scenario.summary)}</p>
        </div>
        <span class="family ${esc(scenario.kind)}" title="${esc(scenario.family)}">${esc(familyLabel(scenario.family))}</span>
      </div>
      <div class="intro-grid">
        <div>
          <h3>Task</h3>
          <p>${esc(scenario.task)}</p>
          <h3>What the agent may use</h3>
          <div class="labels">${(scenario.capabilities || []).map((tool) => `<span class="label pub" title="${esc(tool)}">${esc(toolLabel(tool))}</span>`).join("")}</div>
        </div>
        <div>
          <h3>What to watch</h3>
          <p>${esc(scenario.expectation)}</p>
          <h3>How AgentFence responds</h3>
          <p>${esc(scenario.defense)}</p>
        </div>
      </div>
      <div class="intro-actions">
        <span class="muted small">${scenario.actions} steps · ${state.demo.mode} · if a person is asked: ${esc(POLICY_LABELS[state.demo.policy] || state.demo.policy)}</span>
      </div>
      <div class="intro-preview">
        <div><span>1</span><strong>Every action</strong><p>The exact tool call, file, or destination.</p></div>
        <div><span>2</span><strong>Each decision</strong><p>Allowed, blocked, or paused for a person.</p></div>
        <div><span>3</span><strong>The outcome</strong><p>What ran, what stopped, and whether data left.</p></div>
      </div>
      ${scenario.finding ? `<div class="finding ${scenario.id === "a5-paraphrase" || scenario.id === "a5-split" ? "warn" : ""}"><strong>Note.</strong> ${esc(scenario.finding)}</div>` : ""}
    </div>`;
}

async function runDemo() {
  if (state.demo.running) return;
  const scenario = selectedScenario();
  if (!scenario) {
    toast("Choose a scenario first.", "bad");
    return;
  }
  state.demo.running = true;
  state.demo.runLabel = `Running ${scenario.title} in ${state.demo.mode}…`;
  state.demo.result = null;
  state.demo.comparison = null;
  setDemoButtonsDisabled(true);
  renderDemoPanel();
  try {
    const result = await api("/v1/admin/demo/run", {
      method: "POST",
      body: JSON.stringify({
        scenario_id: scenario.id,
        mode: state.demo.mode,
        approval_policy: state.demo.policy,
      }),
    });
    state.demo.result = result;
    toast(`${scenario.title}: ${result.headline}`, result.verdict === "blocked" || result.verdict === "completed" ? "ok" : "bad");
  } catch (error) {
    state.demo.result = {
      error: error.message,
      scenario: { title: scenario.title, family: scenario.family },
      mode: state.demo.mode,
      headline: "Demo failed",
      verdict: "unsafe",
      summary: {},
      steps: [],
      effects: [],
    };
    toast(error.message, "bad");
  } finally {
    state.demo.running = false;
    setDemoButtonsDisabled(false);
    renderDemoPanel();
    revealDemoResult();
  }
}

function revealDemoResult() {
  if (window.innerWidth > 980) return;
  requestAnimationFrame(() => {
    document.querySelector("#demoResult")?.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

async function runComparison() {
  if (state.demo.running) return;
  const scenario = selectedScenario();
  if (!scenario) {
    toast("Choose a scenario first.", "bad");
    return;
  }
  state.demo.running = true;
  state.demo.result = null;
  state.demo.comparison = { results: [], running: true, scenario: scenario.title };
  setDemoButtonsDisabled(true);
  try {
    for (const mode of MODES) {
      state.demo.runLabel = `Running ${mode} (${MODES.indexOf(mode) + 1}/${MODES.length})…`;
      renderDemoPanel();
      const result = await api("/v1/admin/demo/run", {
        method: "POST",
        body: JSON.stringify({
          scenario_id: scenario.id,
          mode,
          approval_policy: state.demo.policy,
        }),
      });
      state.demo.comparison.results.push(result);
    }
    state.demo.comparison.running = false;
    toast(`Compared ${scenario.title} across B0–B5.`, "ok");
  } catch (error) {
    state.demo.comparison = { results: [], running: false, error: error.message };
    toast(error.message, "bad");
  } finally {
    state.demo.running = false;
    setDemoButtonsDisabled(false);
    renderDemoPanel();
    revealDemoResult();
  }
}

function setDemoButtonsDisabled(disabled) {
  const run = $("#runDemo");
  const compare = $("#compareDemo");
  if (run) run.disabled = disabled;
  if (compare) compare.disabled = disabled;
}

function renderComparison(comparison) {
  if (comparison.error) {
    return `<div class="empty-state"><h2>Comparison failed</h2><p>${esc(comparison.error)}</p></div>`;
  }
  const rows = comparison.results.map((result) => {
    const summary = result.summary || {};
    const best = result.mode === "B5";
    return `
      <tr data-compare-mode="${esc(result.mode)}" class="${best ? "best" : ""}">
        <td class="mono">${esc(result.mode)}</td>
        <td><span class="badge ${esc(verdictClass(result.verdict).toUpperCase())}" style="border:0;padding:0;background:transparent;color:${verdictColor(result.verdict)}">${esc(result.verdict)}</span></td>
        <td class="mono">${num(summary.blocked)} / ${num(summary.actions)}</td>
        <td class="mono">${num(summary.unsafe_executed)}</td>
        <td class="mono">${num(summary.leak_bytes)} B</td>
        <td class="mono">${ms(summary.latency_ms)}</td>
      </tr>`;
  }).join("");
  return `
    <div class="card-head">
      <div>
        <h2>${esc(comparison.scenario || "Scenario")} across configurations</h2>
        <p class="card-sub">Same action trace, six policy configurations. Click a row to open its trace.</p>
      </div>
      <span class="chip">${comparison.results.length} runs</span>
    </div>
    <div class="table-wrap" style="border:0">
      <table class="comparison-table">
        <thead><tr><th>Mode</th><th>Verdict</th><th>Blocked</th><th>Unsafe exec.</th><th>Leak</th><th>Latency</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="finding"><strong>Read it this way.</strong> B0 shows what the attack does without enforcement. B5 shows what the full stack does. The intermediate rows isolate which layer changes the outcome.</div>`;
}

function verdictColor(verdict) {
  if (verdict === "blocked" || verdict === "completed") return "#2E6B40";
  if (verdict === "pending" || verdict === "false_block") return "#8A5A00";
  return "#A32A2A";
}

function approvalChip(result) {
  const summary = result.summary || {};
  const requested = Number(summary.approvals_requested || 0);
  const used = Number(summary.approvals_used || 0);
  if (!requested) return "no approval needed";
  if (used) return `${used} approval${used === 1 ? "" : "s"} used`;
  if (result.approval_policy === "deny") return `${requested} approval${requested === 1 ? "" : "s"} denied`;
  if (result.approval_policy === "leave") return `${requested} approval${requested === 1 ? "" : "s"} pending`;
  return `${requested} approval${requested === 1 ? "" : "s"} requested`;
}

function verdictSummary(result) {
  if (result.verdict === "blocked") return "AgentFence stopped the attack before it could do harm.";
  if (result.verdict === "completed") return "The task was legitimate, so it completed normally.";
  if (result.verdict === "pending") return "The action is paused and waiting for a person to decide.";
  if (result.verdict === "false_block") return "A legitimate action was blocked. That is a false alarm.";
  if (result.verdict === "leaked" || result.verdict === "unsafe") return "The attack got through. This is a known limitation, not a success.";
  return "";
}

function renderResult(result) {
  if (result.error) {
    return `<div class="empty-state"><h2>Demo failed</h2><p>${esc(result.error)}</p></div>`;
  }
  const summary = result.summary || {};
  const scenario = result.scenario || {};
  const findingClass = ["leaked", "unsafe", "false_block"].includes(result.verdict) ? "warn" : "";
  const steps = (result.steps || []).map(renderStep).join("");
  const effects = renderResultEffects(result.effects || []);
  return `
    <div class="verdict ${verdictClass(result.verdict)}">
      <div>
        <span class="eyebrow">${esc(familyLabel(scenario.family))} · ${esc(result.mode)} · ${esc(MODE_LABELS[result.mode] || "")}</span>
        <h2>${esc(result.headline)}</h2>
        <p>${esc(result.subhead || "")}</p>
        <p class="verdict-summary">${esc(verdictSummary(result))}</p>
      </div>
      <div class="verdict-side">
        <div class="mode-big">${esc(result.mode)}</div>
        <div class="tiny">${esc(scenario.title || "")}</div>
      </div>
    </div>
    <div class="result-stats">
      <div class="result-stat"><div class="k">Actions checked</div><div class="v">${num(summary.actions)}</div></div>
      <div class="result-stat"><div class="k">Ran</div><div class="v">${num(summary.executed)}</div></div>
      <div class="result-stat"><div class="k">Blocked</div><div class="v">${num(summary.blocked)}</div></div>
      <div class="result-stat"><div class="k">Unsafe actions ran</div><div class="v">${num(summary.unsafe_executed)}</div></div>
      <div class="result-stat"><div class="k">Data leaked</div><div class="v">${bytes(summary.leak_bytes)}</div></div>
      <div class="result-stat"><div class="k">Time</div><div class="v">${ms(summary.latency_ms)}</div></div>
    </div>
    <div class="card-head tight" style="margin-top:4px">
      <h2>What the agent tried to do</h2>
      <span class="chip">${esc(approvalChip(result))}</span>
    </div>
    <div class="trace">${steps || `<p class="muted">No actions were submitted.</p>`}</div>
    ${effects}
    ${result.finding ? `<div class="finding ${findingClass}"><strong>${findingClass ? "Known limitation." : "Why this happens."}</strong> ${esc(result.finding)}</div>` : ""}
    <div class="audit-foot">
      <span class="${summary.audit_ok ? "ok" : ""}">${summary.audit_ok ? "✓ record verified" : "✗ record check failed"}</span>
      <span>${num(summary.audit_entries)} log entries</span>
      <details class="inline-details">
        <summary>Technical details</summary>
        <span>head ${esc(shortHash(summary.audit_head, 20))} · task ${esc(shortHash(result.task_id, 16))}</span>
      </details>
    </div>`;
}

function renderStep(step) {
  const rules = Array.from(new Set((step.reasons || []).map((reason) => reason.rule_id).filter((rule) => rule && rule !== "-")));
  const reasonText = (step.reasons || []).map((reason) => reason.reason).filter(Boolean).join(" · ");
  const approval = step.approval ? `
    <div class="approval-box">
      <strong>${step.approval.status === "approved" ? "Approved by a person" : step.approval.status === "denied" ? "Denied by a person" : "Waiting for a person"}</strong>
      ${step.approval.token_used ? " · the approval was used once" : ""}
      ${step.approval.detail ? ` · ${esc(step.approval.detail)}` : ""}
    </div>` : "";
  const effect = step.effect && step.effect.bytes > 0 ? `
    <div class="effect-box ${step.executed ? "" : "ok"}">
      ${step.executed ? "Sent" : "Stopped"}: ${num(step.effect.bytes)} B → ${esc(step.effect.destination)}
    </div>` : "";
  return `
    <div class="trace-step ${esc(step.decision)}">
      <div class="trace-dot">${num(step.index)}</div>
      <div class="trace-body">
        <div class="trace-top">
          <span class="trace-tool" title="${esc(step.tool)}">${esc(toolLabel(step.tool))}</span>
          <span class="trace-label">${esc(step.label)}</span>
          ${decisionBadge(step.decision)}
        </div>
        <div class="trace-meta">${esc(step.preview || "")} · ${esc(riskLevel(step.risk))} risk · ${ms(step.latency_ms)}</div>
        ${reasonText ? `<div class="trace-reason">${esc(reasonText)} ${rules.map((rule) => `<span class="rule" title="${esc(RULE_DESCRIPTIONS[rule] || rule)}">${esc(rule)}</span>`).join(" ")}</div>` : ""}
        ${approval}
        ${effect}
      </div>
    </div>`;
}

function renderResultEffects(effects) {
  if (!effects.length) return "";
  const rows = effects.map((effect) => `
    <tr>
      <td class="mono" title="${esc(effect.tool)}">${esc(toolLabel(effect.tool))}</td>
      <td class="mono">${esc(effect.destination)}</td>
      <td class="mono">${num(effect.bytes)} B</td>
      <td>${effect.delivered ? `<span class="badge ALLOW">Delivered</span>` : `<span class="badge DENIED">Stopped</span>`}</td>
      <td class="mono">${esc(shortHash(effect.content_hash, 18))}</td>
    </tr>`).join("");
  return `
    <div class="card-head tight" style="margin-top:16px"><h2>What left the sandbox</h2><span class="chip">${effects.length}</span></div>
    <div class="table-wrap" style="border:1px solid var(--line)">
      <table>
        <thead><tr><th>Tool</th><th>Sent to</th><th>Size</th><th>Status</th><th>Receipt</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/* ----------------------------------------------------------------- approvals */

function renderApprovals() {
  const approvals = state.approvals;
  $("#approvalCount").textContent = approvals.length;
  const list = $("#approvalList");
  if (!approvals.length) {
    list.innerHTML = `<div class="empty-state" style="min-height:200px"><p>No pending approvals. Sensitive actions will appear here with an exact, hash-bound preview.</p><button class="btn small primary" data-seed style="margin-top:12px">Load sample activity</button></div>`;
    $("#approvalDetail").innerHTML = `
      <div class="empty-state">
        <h2>Nothing waiting</h2>
        <p>Try the A7 approval-replay scenario in the <a href="#/demo">demo lab</a>, or load sample activity to populate the queue.</p>
      </div>`;
    return;
  }
  if (!state.selectedApproval || !approvals.some((approval) => approval.approval_id === state.selectedApproval)) {
    state.selectedApproval = approvals[0].approval_id;
  }
  list.innerHTML = approvals.map((approval) => {
    const preview = approval.preview || {};
    const active = approval.approval_id === state.selectedApproval ? "active" : "";
    const score = Number((preview.risk || {}).score || 0);
    return `
      <button class="approval-item ${active}" data-approval="${esc(approval.approval_id)}">
        <div class="top"><span class="tool" title="${esc(preview.tool)}">${esc(toolLabel(preview.tool))}</span><span class="risk">${esc(riskLevel(score))} risk</span></div>
        <div class="dest">To: ${esc(destinationLabel(preview.destination))}</div>
        <div class="dest">${esc(preview.task_description || "").slice(0, 100)}</div>
      </button>`;
  }).join("");
  renderApprovalDetail();
}

function destinationLabel(destination) {
  if (!destination) return "internal";
  return destination.value || destination.host || (destination.recipients || []).join(", ") || "internal";
}

function labelChips(labels) {
  if (!labels || !labels.length) return `<span class="muted tiny">no data labels</span>`;
  return labels.map((label) => {
    const cls = label.sensitivity === "confidential" ? "conf" : label.trust === "untrusted" ? "untrusted" : "pub";
    const text = label.sensitivity === "confidential" ? "Confidential data" : label.trust === "untrusted" ? "Unverified source" : "Public data";
    return `<span class="label ${cls}">${esc(text)}</span>`;
  }).join("");
}

function renderApprovalDetail() {
  const approval = state.approvals.find((item) => item.approval_id === state.selectedApproval);
  if (!approval) return;
  const preview = approval.preview || {};
  const risk = preview.risk || {};
  const score = Number(risk.score || 0);
  const reasonList = (preview.reasons && preview.reasons.length ? preview.reasons : risk.reasons) || [];
  const reasons = reasonList.map((reason) => `<li>${esc(reason)}</li>`).join("");
  const attachments = (preview.attachments || []).map((attachment) => `
    <div class="attachment">
      <strong>${esc(attachment.filename)}</strong> · ${num(attachment.bytes)} bytes
      <pre>${esc(attachment.content_preview || "")}</pre>
    </div>`).join("");
  const decoded = preview.decoded_preview ? `<h3>Decoded content</h3><pre>${esc(preview.decoded_preview)}</pre>` : "";
  const content = preview.content ? `<pre>${esc(preview.content)}</pre>` : `<p class="muted small">Nothing will be sent.</p>`;
  $("#approvalDetail").innerHTML = `
    <div class="detail">
      <div class="card-head tight">
        <div>
          <h2>${esc(toolLabel(preview.tool))}</h2>
          <div class="meta">${esc(clock(approval.created_at))} · ${esc(riskLevel(score))} risk</div>
        </div>
        <span class="pill warn">waiting for you</span>
      </div>
      <p class="detail-summary">The agent wants to <strong>${esc(toolAction(preview.tool))}</strong>. Target: <strong>${esc(destinationLabel(preview.destination))}</strong>. AgentFence paused it so you can check the exact action first.</p>
      <div class="labels">${labelChips(preview.labels)}</div>
      <h3>What the agent is trying to do</h3>
      <div class="small">${esc(preview.task_description)}</div>
      <h3>Why it was paused</h3>
      <div><strong>${esc(riskLevel(score))} risk</strong> <span class="muted small">(${score.toFixed(2)} out of 1.00)</span></div>
      <ul class="muted small">${reasons || "<li>This action needs a person to confirm it.</li>"}</ul>
      <h3>What will be sent · ${num(preview.bytes_out)} bytes</h3>
      ${content}
      ${decoded}
      ${attachments ? `<h3>Attachments</h3>${attachments}` : ""}
      <div class="actions">
        <button class="btn primary" id="approveBtn">Approve this action</button>
        <button class="btn ghost danger" id="denyBtn">Block it</button>
      </div>
      <div id="approvalNotice"></div>
      <details class="more">
        <summary>Technical details</summary>
        <h3>Action fingerprint</h3>
        <div class="mono">${esc(preview.action_hash)}</div>
        <div class="mono muted">preview ${esc(preview.preview_hash)}</div>
        <div class="mono muted">approval ${esc(approval.approval_id)}</div>
      </details>
    </div>`;
  $("#approveBtn").addEventListener("click", () => decideApproval("approve"));
  $("#denyBtn").addEventListener("click", () => decideApproval("deny"));
}

async function decideApproval(verb) {
  const approval = state.approvals.find((item) => item.approval_id === state.selectedApproval);
  if (!approval) return;
  const notice = $("#approvalNotice");
  notice.className = "notice";
  notice.textContent = `${verb === "approve" ? "Approving" : "Denying"}…`;
  try {
    const result = await api(`/v1/admin/approvals/${approval.approval_id}/${verb}`, { method: "POST" });
    notice.className = "notice ok";
    notice.textContent = verb === "approve"
      ? "Approved. This action can run once, exactly as shown."
      : "Blocked. The action will not run.";
    toast(verb === "approve" ? "Action approved." : "Action blocked.", "ok");
    setTimeout(() => refreshLive({ silent: true }), 500);
  } catch (error) {
    notice.className = "notice bad";
    notice.textContent = error.message;
  }
}

/* --------------------------------------------------------------------- audit */

function filteredAudit() {
  const search = state.filters.auditSearch.trim().toLowerCase();
  return state.audit
    .slice()
    .sort((a, b) => b.seq - a.seq)
    .filter((entry) => {
      if (state.filters.auditDecision && entry.decision !== state.filters.auditDecision) return false;
      if (!search) return true;
      const haystack = [
        entry.event,
        entry.tool,
        entry.decision,
        (entry.rule_ids || []).join(" "),
        (entry.reasons || []).join(" "),
        entry.agent_id,
        entry.task_id,
      ].join(" ").toLowerCase();
      return haystack.includes(search);
    });
}

function renderAudit() {
  const rows = filteredAudit();
  const table = $("#auditTable");
  if (!rows.length) {
    table.innerHTML = `<tbody><tr><td class="empty-row" colspan="7">No entries match this filter. ${state.audit.length ? "" : "Run a scenario or load sample activity."}</td></tr></tbody>`;
    return;
  }
  table.innerHTML = `
    <thead><tr><th>No.</th><th>Time</th><th>What happened</th><th>Decision</th><th>Action</th><th>Risk</th><th>Why</th></tr></thead>
    <tbody>${rows.map((entry) => {
      const rules = (entry.rule_ids || []).filter((rule) => rule && rule !== "-");
      const reason = (entry.reasons || [])[0] || "";
      return `
      <tr data-audit-seq="${entry.seq}">
        <td class="mono">${entry.seq}</td>
        <td class="mono">${esc(clock(entry.timestamp))}</td>
        <td>${esc(eventLabel(entry.event))}</td>
        <td>${decisionBadge(entry.decision)}</td>
        <td class="mono" title="${esc(entry.tool)}">${esc(toolLabel(entry.tool))}</td>
        <td class="mono" title="Risk score ${Number(entry.risk_score || 0).toFixed(2)}">${esc(riskLevel(entry.risk_score))}</td>
        <td class="reason-cell">${rules.length ? `<span class="rule-cell">${esc(rules.join(", "))}</span> ` : ""}${esc(reason)}</td>
      </tr>`;
    }).join("")}</tbody>`;
}

function openAuditEntry(seq) {
  const entry = state.audit.find((item) => item.seq === Number(seq));
  if (!entry) return;
  $("#auditDialogTitle").textContent = `Entry #${entry.seq} · ${entry.event}`;
  $("#auditDialogBody").textContent = JSON.stringify(entry, null, 2);
  const dialog = $("#auditDialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

async function verifyAudit() {
  const result = $("#verifyResult");
  result.textContent = "Verifying…";
  result.className = "muted small";
  try {
    const verification = await api("/v1/admin/audit/verify");
    state.auditVerification = verification;
    updateChrome();
    result.textContent = verification.ok
      ? `✓ The log is intact. ${num(verification.entries)} entries, in order.`
      : `✗ The log does not match. ${verification.error || "An entry may have been changed."}`;
    result.className = verification.ok ? "small ok-text" : "small notice bad";
    toast(verification.ok ? "Decision log verified." : "Decision log check failed.", verification.ok ? "ok" : "bad");
  } catch (error) {
    result.textContent = error.message;
    result.className = "small notice bad";
  }
}

/* ------------------------------------------------------------------- effects */

function renderEffects() {
  const effects = state.effects || [];
  const egress = effects.filter((effect) => ["email.send", "http.post"].includes(effect.tool));
  const delivered = effects.filter((effect) => effect.delivered).length;
  const destinations = new Set(effects.map((effect) => effect.destination).filter(Boolean)).size;
  $("#effectKpis").innerHTML = [
    { key: "Actions taken", value: num(effects.length), sub: "tool calls that actually ran", cls: "" },
    { key: "Data sent out", value: bytes(egress.reduce((sum, effect) => sum + Number(effect.bytes_out || 0), 0)), sub: `${egress.length} email or web request${egress.length === 1 ? "" : "s"}`, cls: "warn" },
    { key: "Reached destination", value: num(delivered), sub: "actions delivered successfully", cls: "good" },
    { key: "Places data went", value: num(destinations), sub: "unique destinations", cls: "" },
  ].map((item) => `
    <div class="kpi ${item.cls}">
      <div class="k">${esc(item.key)}</div>
      <div class="v">${esc(item.value)}</div>
      <div class="s">${esc(item.sub)}</div>
    </div>`).join("");

  const table = $("#effectTable");
  if (!effects.length) {
    table.innerHTML = `<tbody><tr><td class="empty-row" colspan="7">No actions have run yet. Blocked actions appear in the decision log instead.</td></tr></tbody>`;
    return;
  }
  table.innerHTML = `
    <thead><tr><th>Time</th><th>Task</th><th>Tool</th><th>Sent to</th><th>Size</th><th>Status</th><th>Receipt</th></tr></thead>
    <tbody>${effects.slice().reverse().map((effect) => `
      <tr>
        <td class="mono">${esc(clock(effect.timestamp))}</td>
        <td class="mono">${esc(shortHash(effect.task_id, 12))}</td>
        <td class="mono" title="${esc(effect.tool)}">${esc(toolLabel(effect.tool))}</td>
        <td class="mono">${esc(effect.destination)}</td>
        <td class="mono">${num(effect.bytes_out)} B</td>
        <td>${effect.delivered ? `<span class="badge ALLOW">Delivered</span>` : `<span class="badge DENIED">Stopped</span>`}</td>
        <td class="mono">${esc(shortHash(effect.content_hash, 18))}</td>
      </tr>`).join("")}</tbody>`;
}

/* --------------------------------------------------------------- experiments */

function renderExperiments() {
  const data = state.results;
  if (!data || !data.main) {
    $("#experimentKpis").innerHTML = "";
    $("#modeTable").innerHTML = `<div class="empty-state"><h2>Results unavailable</h2><p>${esc(state.resultsError || "Run the experiment suite to generate results/main/summary.json.")}</p></div>`;
    $("#sweepChart").innerHTML = "";
    $("#familyHeatmap").innerHTML = "";
    $("#latencyTable").innerHTML = "";
    $("#ruleCoverage").innerHTML = "";
    $("#denyCallout").innerHTML = `<h2>No evaluation data</h2><p>Start the gateway from the repository root, or copy the results snapshot into the package static directory.</p>`;
    return;
  }
  const main = data.main;
  const b5 = main.by_mode.B5;
  const episodes = main.modes.reduce((sum, mode) => sum + Number(main.by_mode[mode].n_episodes || 0), 0);
  const sweep = data.sweep || {};
  const sweepEpisodes = Number((sweep.manifest || {}).recall_records || 0) + Number((sweep.manifest || {}).fpr_records || 0);
  $("#experimentKpis").innerHTML = [
    { key: "Test runs", value: num(episodes), sub: `${main.modes.length} protection levels · 5 repeats`, cls: "" },
    { key: "Attack scenarios", value: num(b5.attack.n_scenarios), sub: "seven attack types", cls: "bad" },
    { key: "Normal tasks", value: num(b5.benign.n_scenarios), sub: "utility and false-alarm tests", cls: "good" },
    { key: "Detector tests", value: num(sweepEpisodes), sub: "recall × false-positive grid", cls: "" },
  ].map((item) => `
    <div class="kpi ${item.cls}">
      <div class="k">${esc(item.key)}</div>
      <div class="v">${esc(item.value)}</div>
      <div class="s">${esc(item.sub)}</div>
    </div>`).join("");

  renderModeTable(main);
  renderSweepChart(sweep);
  renderFamilyHeatmap(main);
  renderLatencyTable(main);
  renderRuleCoverage(b5);
  renderDenyCallout(data.deny_all);
}

function barCell(value, color) {
  const width = Math.max(1.5, Number(value || 0) * 100);
  return `<div class="bar-cell"><div class="bar-track"><span class="bar-fill" style="width:${width}%;background:${color}"></span></div><span>${pct(value, 1)}</span></div>`;
}

function renderModeTable(main) {
  const rows = main.modes.map((mode) => {
    const data = main.by_mode[mode];
    const best = mode === "B5";
    const tag = ["B4T", "B4TR"].includes(mode) ? "variant" : MODE_LABELS[mode] || "";
    return `
      <div class="mode-row ${best ? "best" : ""}">
        <div class="mode-name">${esc(mode)}<span class="tag">${esc(tag)}</span></div>
        ${barCell(data.attack.asr, "#A32A2A")}
        ${barCell(data.benign.tcr, "#2E6B40")}
        <div class="num">${num(data.benign.false_block_tasks)}</div>
        <div class="num">${Number(data.latency.end_to_end.p95 || 0).toFixed(2)} ms</div>
      </div>`;
  }).join("");
  $("#modeTable").innerHTML = `
    <div class="mode-row head"><div>Protection</div><div>Attacks got through</div><div>Normal tasks done</div><div class="num">False blocks</div><div class="num">Slowest 5%</div></div>
    ${rows}`;
}

function renderSweepChart(sweep) {
  const recall = (sweep && sweep.recall) || [];
  if (!recall.length) {
    $("#sweepChart").innerHTML = `<p class="muted small">Detector sweep data unavailable.</p>`;
    return;
  }
  const series = ["B1", "B3", "B5"].map((mode) => ({
    mode,
    points: recall
      .filter((row) => row.mode === mode)
      .sort((a, b) => a.detector_recall - b.detector_recall)
      .map((row) => ({ x: Number(row.detector_recall), y: Number(row.asr) })),
  }));
  const width = 560;
  const height = 250;
  const left = 44;
  const top = 14;
  const right = 14;
  const bottom = 32;
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  const colors = { B1: "#8A5A00", B3: "#A32A2A", B5: "#2E6B40" };
  const x = (value) => left + plotW * value;
  const y = (value) => top + plotH * (1 - value);
  const parts = [`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack success as detector recall varies">`];
  for (let index = 0; index <= 4; index += 1) {
    const gy = top + (plotH * index) / 4;
    parts.push(`<line x1="${left}" y1="${gy}" x2="${width - right}" y2="${gy}" stroke="rgba(35,29,21,.14)"/>`);
    parts.push(`<text x="${left - 8}" y="${gy + 3}" text-anchor="end" fill="#756B5C" font-family="ui-monospace, monospace" font-size="8">${(1 - index / 4) * 100}%</text>`);
  }
  for (let index = 0; index <= 4; index += 1) {
    const gx = left + (plotW * index) / 4;
    parts.push(`<text x="${gx}" y="${height - 10}" text-anchor="middle" fill="#756B5C" font-family="ui-monospace, monospace" font-size="8">${(index / 4).toFixed(2)}</text>`);
  }
  series.forEach((item) => {
    if (!item.points.length) return;
    const path = item.points.map((point, index) => `${index === 0 ? "M" : "L"} ${x(point.x).toFixed(1)} ${y(point.y).toFixed(1)}`).join(" ");
    parts.push(`<path d="${path}" fill="none" stroke="${colors[item.mode]}" stroke-width="2" opacity=".9"/>`);
    item.points.forEach((point) => {
      parts.push(`<circle cx="${x(point.x)}" cy="${y(point.y)}" r="2.5" fill="${colors[item.mode]}"/>`);
    });
  });
  parts.push("</svg>");
  $("#sweepChart").innerHTML = `
    <div class="chart-legend">
      <span><i style="background:#8A5A00"></i>Prompt filter</span>
      <span><i style="background:#A32A2A"></i>Risk score</span>
      <span><i style="background:#2E6B40"></i>Full protection</span>
    </div>
    ${parts.join("")}
    <div class="axis-label">detector recall (higher is better) →</div>`;
}

function heatColor(value) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  const hue = 145 - 145 * v;
  const light = 93 - 30 * v;
  return `background:hsl(${hue} 58% ${light}%);`;
}

function renderFamilyHeatmap(main) {
  const families = ["A1", "A2", "A3", "A4", "A5", "A6", "A7"];
  const modes = main.modes;
  const head = `<tr><th>Family</th>${modes.map((mode) => `<th class="${mode === "B5" ? "b5" : ""}">${esc(mode)}</th>`).join("")}</tr>`;
  const rows = families.map((family) => {
    const cells = modes.map((mode) => {
      const data = main.by_mode[mode].attack.by_family[family];
      if (!data) return `<td class="${mode === "B5" ? "b5" : ""}">—</td>`;
      return `<td class="${mode === "B5" ? "b5" : ""}" style="${heatColor(data.asr)}" title="${esc(mode)} ${esc(family)}: ${data.successes}/${data.n_scenarios}">${num(data.successes)}/${num(data.n_scenarios)}</td>`;
    }).join("");
    return `<tr><td class="family-name"><span class="mono">${esc(family)}</span> ${esc(FAMILY_LABELS[family] || "")}</td>${cells}</tr>`;
  }).join("");
  $("#familyHeatmap").innerHTML = `<table class="heatmap"><thead>${head}</thead><tbody>${rows}</tbody></table>`;
}

function renderLatencyTable(main) {
  const rows = main.modes.map((mode) => {
    const latency = main.by_mode[mode].latency;
    return `<tr>
      <td class="mono">${esc(mode)}</td>
      <td class="mono">${Number(latency.decision.p50).toFixed(2)}</td>
      <td class="mono">${Number(latency.decision.p95).toFixed(2)}</td>
      <td class="mono">${Number(latency.end_to_end.p50).toFixed(2)}</td>
      <td class="mono">${Number(latency.end_to_end.p95).toFixed(2)}</td>
      <td class="mono">${Number(latency.end_to_end.p99).toFixed(2)}</td>
    </tr>`;
  }).join("");
  $("#latencyTable").innerHTML = `
    <table>
      <thead><tr><th>Protection</th><th>Check: typical</th><th>Check: slowest 5%</th><th>Total: typical</th><th>Total: slowest 5%</th><th>Total: slowest 1%</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderRuleCoverage(b5) {
  const counts = (b5.rules && b5.rules.counts) || {};
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    $("#ruleCoverage").innerHTML = `<p class="muted small">No rule counts in this snapshot.</p>`;
    return;
  }
  const max = Math.max(...entries.map(([, value]) => value), 1);
  $("#ruleCoverage").innerHTML = entries.map(([rule, count]) => `
    <div class="rule-bar">
      <span class="name" title="${esc(rule)}">${esc(RULE_LABELS[rule] || rule)}</span>
      <div class="track"><div class="fill" style="width:${(count / max) * 100}%"></div></div>
      <span class="n">${num(count)}</span>
      <span class="desc">${esc(RULE_DESCRIPTIONS[rule] || "Rule hit")}</span>
    </div>`).join("");
}

function renderDenyCallout(denyAll) {
  const b5 = denyAll && denyAll.by_mode && denyAll.by_mode.B5;
  if (!b5) {
    $("#denyCallout").innerHTML = `<h2>Approvals help legitimate work get through</h2><p>When every approval is denied, full protection still stops almost every attack, but normal task completion falls sharply. The rules do the blocking; approvals protect usefulness.</p>`;
    return;
  }
  $("#denyCallout").innerHTML = `
    <h2>Approvals help legitimate work get through</h2>
    <p>When every approval is denied (${num(b5.n_episodes)} test runs), full protection still stopped <strong>${pct(1 - b5.attack.asr, 1)}</strong> of attacks. But normal task completion fell to <strong>${pct(b5.benign.tcr, 1)}</strong> because legitimate actions could not get a person's approval. The rules do the blocking; approvals protect usefulness.</p>`;
}

/* ----------------------------------------------------------------------- seed */

async function seedLive() {
  try {
    toast("Loading sample activity into the live gateway…");
    const result = await api("/v1/admin/demo/seed", { method: "POST" });
    await refreshLive({ silent: true });
    toast(`Seeded ${result.runs.length} runs · ${result.pending_approvals} pending approval(s).`, "ok");
    if (state.route === "approvals" || state.route === "overview") renderRoute();
  } catch (error) {
    toast(error.message, "bad");
  }
}

/* ----------------------------------------------------------------------- init */

function bindEvents() {
  $$("#nav button").forEach((button) => {
    button.addEventListener("click", () => {
      window.location.hash = `#/${button.dataset.route}`;
    });
  });
  window.addEventListener("hashchange", () => renderRoute({ scroll: true }));

  $("#refreshBtn").addEventListener("click", async () => {
    $("#refreshBtn").classList.add("spinning");
    await Promise.allSettled([refreshLive(), loadScenarios(), loadResults()]);
    setTimeout(() => $("#refreshBtn").classList.remove("spinning"), 400);
  });

  $("#connectBtn").addEventListener("click", () => {
    setKey($("#adminKey").value);
    refreshLive();
    loadScenarios();
    loadResults();
  });
  $("#adminKey").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      setKey(event.target.value);
      refreshLive();
    }
  });
  $("#adminKey").addEventListener("change", (event) => {
    setKey(event.target.value);
    refreshLive();
  });

  document.addEventListener("click", (event) => {
    const seed = event.target.closest("[data-seed]");
    if (seed) {
      event.preventDefault();
      seedLive();
      return;
    }
    const scenario = event.target.closest("[data-scenario]");
    if (scenario) {
      state.demo.scenarioId = scenario.dataset.scenario;
      state.demo.result = null;
      state.demo.comparison = null;
      renderScenarioList();
      renderDemoPanel();
      return;
    }
    const mode = event.target.closest("[data-mode]");
    if (mode) {
      state.demo.mode = mode.dataset.mode;
      renderModePicker();
      if (state.demo.result) {
        state.demo.result = null;
        state.demo.comparison = null;
        renderDemoPanel();
      }
      return;
    }
    const compareRow = event.target.closest("[data-compare-mode]");
    if (compareRow) {
      const result = state.demo.comparison.results.find((item) => item.mode === compareRow.dataset.compareMode);
      if (result) {
        state.demo.mode = result.mode;
        state.demo.result = result;
        state.demo.comparison = null;
        renderModePicker();
        renderDemoPanel();
      }
      return;
    }
  });

  $("#runDemo").addEventListener("click", runDemo);
  $("#compareDemo").addEventListener("click", runComparison);
  $("#policySelect").addEventListener("change", (event) => {
    state.demo.policy = event.target.value;
  });

  $("#approvalList").addEventListener("click", (event) => {
    const item = event.target.closest("[data-approval]");
    if (!item) return;
    state.selectedApproval = item.dataset.approval;
    renderApprovals();
  });

  $("#verifyAudit").addEventListener("click", verifyAudit);
  $("#auditDecision").addEventListener("change", (event) => {
    state.filters.auditDecision = event.target.value;
    renderAudit();
  });
  $("#auditSearch").addEventListener("input", (event) => {
    state.filters.auditSearch = event.target.value;
    renderAudit();
  });
  $("#auditTable").addEventListener("click", (event) => {
    const row = event.target.closest("[data-audit-seq]");
    if (row) openAuditEntry(row.dataset.auditSeq);
  });
  $("#auditDialogClose").addEventListener("click", () => $("#auditDialog").close());
  $("#auditDialog").addEventListener("click", (event) => {
    if (event.target === $("#auditDialog")) $("#auditDialog").close();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && $("#auditDialog").open) $("#auditDialog").close();
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  $("#adminKey").value = state.key;
  bindEvents();
  if (!window.location.hash) window.location.hash = "#/overview";
  renderRoute();
  await Promise.allSettled([refreshLive({ silent: true }), loadScenarios(), loadResults()]);
  renderRoute();

  setInterval(() => {
    if (document.hidden || state.demo.running) return;
    if (["overview", "approvals", "audit", "effects"].includes(state.route)) {
      refreshLive({ silent: true });
    }
  }, 5000);
});
