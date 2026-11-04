/* AgentFence console: vanilla JS, no build step. */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const ROUTES = ["overview", "demo", "approvals", "audit", "effects", "experiments", "coverage", "about"];
const ROUTE_TITLES = {
  overview: "Overview",
  demo: "Live demo",
  approvals: "Approvals",
  audit: "Audit log",
  effects: "Effects",
  experiments: "Experiments",
  coverage: "Coverage",
  about: "About",
};
const MODES = ["B0", "B1", "B2", "B3", "B4", "B5"];
const MODE_LABELS = {
  B0: "no defense",
  B1: "prompt filter",
  B2: "static RBAC",
  B3: "risk only",
  B4: "capabilities",
  B5: "full",
  B4T: "cap + taint",
  B4TR: "cap + taint + risk",
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
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function shortHash(value, length = 12) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function decisionBadge(decision) {
  const value = decision || "—";
  return `<span class="badge ${esc(value)}">${esc(value)}</span>`;
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
  $("#modePill").textContent = stats ? mode : "offline";
  $("#modePill").className = `pill ${stats ? "ok" : "bad"}`;
  $("#liveMode").textContent = stats ? mode : "—";

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
  const kpis = b5 ? [
    {
      key: "Attack success",
      value: pct(b5.attack.asr, 1),
      sub: `${num(b5.attack.successes)} of ${num(b5.attack.n_scenarios)} attacks · B5`,
      cls: "good",
    },
    {
      key: "Task completion",
      value: pct(b5.benign.tcr, 1),
      sub: `${num(b5.benign.completed)} of ${num(b5.benign.n_scenarios)} benign tasks`,
      cls: "good",
    },
    {
      key: "False blocks",
      value: num(b5.benign.false_block_tasks),
      sub: "on the 24-task benign suite",
      cls: "good",
    },
    {
      key: "p95 latency",
      value: ms(b5.latency.end_to_end.p95),
      sub: `decision p95 ${ms(b5.latency.decision.p95)}`,
      cls: "",
    },
  ] : [
    { key: "Attack success", value: "3.2%", sub: "1 of 31 attacks · B5", cls: "good" },
    { key: "Task completion", value: "100%", sub: "24 of 24 benign tasks", cls: "good" },
    { key: "False blocks", value: "0", sub: "on the 24-task benign suite", cls: "good" },
    { key: "p95 latency", value: "1.57 ms", sub: "decision p95 1.16 ms", cls: "" },
  ];
  $("#overviewKpis").innerHTML = kpis.map((item) => `
    <div class="kpi ${item.cls}">
      <div class="k">${esc(item.key)}</div>
      <div class="v">${esc(item.value)}</div>
      <div class="s">${esc(item.sub)}</div>
    </div>`).join("");

  renderOverviewChart();
  renderLiveSummary();
  renderRecentDecisions();
}

function renderOverviewChart() {
  const main = state.results && state.results.main;
  if (!main) {
    $("#overviewChart").innerHTML = `<div class="empty-state"><p>Experiment summary unavailable. Start the gateway from the repository root or check <span class="mono">results/main</span>.</p></div>`;
    return;
  }
  const rows = ["B0", "B1", "B2", "B3", "B4", "B5"].map((mode) => {
    const data = main.by_mode[mode];
    return {
      mode,
      asr: data.attack.asr,
      tcr: data.benign.tcr,
      highlight: mode === "B5",
    };
  });
  $("#overviewChart").innerHTML = `
    <div class="chart-legend">
      <span><i style="background:#fb7185"></i>Attack success (ASR)</span>
      <span><i style="background:#34d399"></i>Task completion (TCR)</span>
    </div>
    ${groupedBarChart(rows)}`;
}

function groupedBarChart(rows) {
  const width = 620;
  const rowHeight = 42;
  const top = 24;
  const left = 44;
  const right = 76;
  const height = top + rows.length * rowHeight + 8;
  const plotWidth = width - left - right;
  const parts = [];
  parts.push(`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack success and task completion by configuration">`);
  for (let index = 0; index <= 4; index += 1) {
    const x = left + (plotWidth * index) / 4;
    parts.push(`<line x1="${x}" y1="${top - 8}" x2="${x}" y2="${height - 8}" stroke="rgba(148,163,184,.12)" stroke-width="1"/>`);
    parts.push(`<text x="${x}" y="12" text-anchor="middle" fill="#64748b" font-family="ui-monospace, monospace" font-size="9">${index * 25}%</text>`);
  }
  rows.forEach((row, index) => {
    const y = top + index * rowHeight;
    if (row.highlight) {
      parts.push(`<rect x="0" y="${y - 2}" width="${width}" height="${rowHeight - 2}" rx="6" fill="rgba(52,211,153,.045)"/>`);
    }
    parts.push(`<text x="0" y="${y + 15}" fill="${row.highlight ? "#e8eefc" : "#94a3b8"}" font-family="ui-monospace, monospace" font-size="10">${row.mode}</text>`);
    parts.push(`<rect x="${left}" y="${y + 3}" width="${Math.max(2, plotWidth * row.asr)}" height="10" rx="4" fill="#fb7185" opacity="${row.highlight ? 1 : 0.5}"/>`);
    parts.push(`<rect x="${left}" y="${y + 19}" width="${Math.max(2, plotWidth * row.tcr)}" height="10" rx="4" fill="#34d399" opacity="${row.highlight ? 1 : 0.42}"/>`);
    parts.push(`<text x="${left + plotWidth + 8}" y="${y + 12}" fill="#cbd5e1" font-family="ui-monospace, monospace" font-size="9">${pct(row.asr, 1)}</text>`);
    parts.push(`<text x="${left + plotWidth + 8}" y="${y + 28}" fill="#cbd5e1" font-family="ui-monospace, monospace" font-size="9">${pct(row.tcr, 1)}</text>`);
  });
  parts.push("</svg>");
  return parts.join("");
}

function renderLiveSummary() {
  const stats = state.stats;
  if (!stats) {
    $("#liveSummary").innerHTML = `
      <div class="empty-state" style="min-height:220px">
        <h2>Gateway not connected</h2>
        <p>Enter the admin key in the top bar. The local demo key is <span class="mono">agentfence-admin-key</span>.</p>
      </div>`;
    return;
  }
  const decisions = stats.decisions || {};
  $("#liveSummary").innerHTML = `
    <div class="live-grid">
      <div class="live-stat"><div class="k">Blocked</div><div class="v bad">${num(decisions.block)}</div></div>
      <div class="live-stat"><div class="k">Executed</div><div class="v good">${num(decisions.allow)}</div></div>
      <div class="live-stat"><div class="k">Pending</div><div class="v warn">${num(stats.approvals_pending)}</div></div>
      <div class="live-stat"><div class="k">Effects</div><div class="v">${num(stats.effects)}</div></div>
    </div>
    <div class="live-foot">
      <span class="muted small">${stats.audit && stats.audit.ok ? "Audit chain verified" : "Audit chain needs attention"}</span>
      <div class="hero-actions">
        <a class="btn ghost small" href="#/approvals">Approvals</a>
        <a class="btn ghost small" href="#/audit">Audit</a>
      </div>
    </div>
    ${state.audit.length === 0 ? `
      <div class="notice" style="margin-top:14px">
        The live gateway has no activity yet.
        <button class="btn small primary" data-seed style="margin-left:8px">Load sample activity</button>
      </div>` : ""}`;
}

function renderRecentDecisions() {
  const entries = state.audit.slice().sort((a, b) => b.seq - a.seq).slice(0, 6);
  if (!entries.length) {
    $("#recentDecisions").innerHTML = `
      <div class="empty-state" style="min-height:180px">
        <p>No decisions yet. Run a scenario in the <a href="#/demo">demo lab</a> or load sample activity into the live gateway.</p>
        <button class="btn small primary" data-seed style="margin-top:12px">Load sample activity</button>
      </div>`;
    return;
  }
  $("#recentDecisions").innerHTML = `<div class="recent-list">${entries.map((entry) => `
    <div class="recent-row">
      <span class="t">${esc(clock(entry.timestamp))}</span>
      <div>
        <div class="tool">${esc(entry.tool || entry.event)}</div>
        <div class="reason">${esc((entry.reasons || [])[0] || entry.event || "")}</div>
      </div>
      ${decisionBadge(entry.decision || entry.event)}
    </div>`).join("")}</div>`;
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
        <span class="family ${esc(scenario.kind)}">${esc(scenario.family)}</span>
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
          <span class="eyebrow">${esc(scenario.family)} · ${esc(scenario.kind)}</span>
          <h2>${esc(scenario.title)}</h2>
          <p>${esc(scenario.summary)}</p>
        </div>
        <span class="family ${esc(scenario.kind)}">${esc(scenario.family)}</span>
      </div>
      <div class="intro-grid">
        <div>
          <h3>Task</h3>
          <p>${esc(scenario.task)}</p>
          <h3>Granted capabilities</h3>
          <div class="labels">${(scenario.capabilities || []).map((tool) => `<span class="label pub mono">${esc(tool)}</span>`).join("")}</div>
        </div>
        <div>
          <h3>What to watch</h3>
          <p>${esc(scenario.expectation)}</p>
          <h3>Defense</h3>
          <p>${esc(scenario.defense)}</p>
        </div>
      </div>
      <div class="intro-actions">
        <span class="muted small">${scenario.actions} actions · ${state.demo.mode} · approval policy: ${esc(state.demo.policy)}</span>
        <button class="btn primary" id="runDemoInline">Run this scenario</button>
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
  const inline = $("#runDemoInline");
  if (inline) inline.disabled = disabled;
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
  if (verdict === "blocked" || verdict === "completed") return "#34d399";
  if (verdict === "pending" || verdict === "false_block") return "#fbbf24";
  return "#fb7185";
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
        <span class="eyebrow">${esc(scenario.family || "")} · ${esc(result.mode)} · policy ${esc(result.approval_policy)}</span>
        <h2>${esc(result.headline)}</h2>
        <p>${esc(result.subhead || "")}</p>
      </div>
      <div class="verdict-side">
        <div class="mode-big">${esc(result.mode)}</div>
        <div class="tiny">${esc(scenario.title || "")}</div>
      </div>
    </div>
    <div class="result-stats">
      <div class="result-stat"><div class="k">Actions</div><div class="v">${num(summary.actions)}</div></div>
      <div class="result-stat"><div class="k">Executed</div><div class="v">${num(summary.executed)}</div></div>
      <div class="result-stat"><div class="k">Blocked</div><div class="v">${num(summary.blocked)}</div></div>
      <div class="result-stat"><div class="k">Unsafe exec.</div><div class="v">${num(summary.unsafe_executed)}</div></div>
      <div class="result-stat"><div class="k">Leak</div><div class="v">${bytes(summary.leak_bytes)}</div></div>
      <div class="result-stat"><div class="k">Latency</div><div class="v">${ms(summary.latency_ms)}</div></div>
    </div>
    <div class="card-head tight" style="margin-top:4px">
      <h2>Action trace</h2>
      <span class="chip">${esc(approvalChip(result))}</span>
    </div>
    <div class="trace">${steps || `<p class="muted">No actions were submitted.</p>`}</div>
    ${effects}
    ${result.finding ? `<div class="finding ${findingClass}"><strong>${findingClass ? "Known limitation." : "Why this happens."}</strong> ${esc(result.finding)}</div>` : ""}
    <div class="audit-foot">
      <span class="${summary.audit_ok ? "ok" : ""}">${summary.audit_ok ? "✓ audit chain verified" : "✗ audit chain failed"}</span>
      <span>${num(summary.audit_entries)} entries</span>
      <span>head ${esc(shortHash(summary.audit_head, 20))}</span>
      <span>task ${esc(shortHash(result.task_id, 16))}</span>
    </div>`;
}

function renderStep(step) {
  const rules = Array.from(new Set((step.reasons || []).map((reason) => reason.rule_id).filter((rule) => rule && rule !== "-")));
  const reasonText = (step.reasons || []).map((reason) => `${reason.rule_id}: ${reason.reason}`).join(" · ");
  const approval = step.approval ? `
    <div class="approval-box">
      <strong>Approval ${esc(step.approval.status)}</strong>
      · ${esc(step.approval.id ? shortHash(step.approval.id, 18) : "")}
      · token ${step.approval.token_used ? "used" : "not used"}
      · final ${esc(step.approval.final_decision || "")}
      ${step.approval.detail ? ` · ${esc(step.approval.detail)}` : ""}
    </div>` : "";
  const effect = step.effect && step.effect.bytes > 0 ? `
    <div class="effect-box ${step.executed ? "" : "ok"}">
      Effect: ${num(step.effect.bytes)} B → ${esc(step.effect.destination)} · ${esc(step.effect.content_hash)}
    </div>` : "";
  return `
    <div class="trace-step ${esc(step.decision)}">
      <div class="trace-dot">${num(step.index)}</div>
      <div class="trace-body">
        <div class="trace-top">
          <span class="trace-tool">${esc(step.tool)}</span>
          <span class="trace-label">${esc(step.label)}</span>
          ${decisionBadge(step.decision)}
        </div>
        <div class="trace-meta">${esc(step.preview || "")} · risk ${Number(step.risk || 0).toFixed(2)} · ${ms(step.latency_ms)}</div>
        ${rules.length ? `<div class="trace-reasons">${rules.map((rule) => `<span class="rule" title="${esc(RULE_DESCRIPTIONS[rule] || rule)}">${esc(rule)}</span>`).join("")}</div>` : ""}
        ${reasonText ? `<div class="trace-reason">${esc(reasonText)}</div>` : ""}
        ${approval}
        ${effect}
      </div>
    </div>`;
}

function renderResultEffects(effects) {
  if (!effects.length) return "";
  const rows = effects.map((effect) => `
    <tr>
      <td class="mono">${esc(effect.tool)}</td>
      <td class="mono">${esc(effect.destination)}</td>
      <td class="mono">${num(effect.bytes)} B</td>
      <td>${effect.delivered ? `<span class="badge ALLOW">delivered</span>` : `<span class="badge DENIED">held</span>`}</td>
      <td class="mono">${esc(effect.content_hash)}</td>
    </tr>`).join("");
  return `
    <div class="card-head tight" style="margin-top:16px"><h2>Effects</h2><span class="chip">${effects.length}</span></div>
    <div class="table-wrap" style="border:1px solid var(--line)">
      <table>
        <thead><tr><th>Tool</th><th>Destination</th><th>Bytes</th><th>Status</th><th>Content hash</th></tr></thead>
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
    return `
      <button class="approval-item ${active}" data-approval="${esc(approval.approval_id)}">
        <div class="top"><span class="tool">${esc(preview.tool)}</span><span class="risk">risk ${Number((preview.risk || {}).score || 0).toFixed(2)}</span></div>
        <div class="dest">${esc(destinationLabel(preview.destination))}</div>
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
    const taint = label.trust === "untrusted" ? " · untrusted" : "";
    return `<span class="label ${cls}">${esc(label.sensitivity)}${esc(taint)}</span>`;
  }).join("");
}

function renderApprovalDetail() {
  const approval = state.approvals.find((item) => item.approval_id === state.selectedApproval);
  if (!approval) return;
  const preview = approval.preview || {};
  const risk = preview.risk || {};
  const reasons = (preview.reasons || []).map((reason) => `<li>${esc(reason)}</li>`).join("");
  const attachments = (preview.attachments || []).map((attachment) => `
    <div class="attachment">
      <strong>${esc(attachment.filename)}</strong> · ${num(attachment.bytes)} bytes<br>
      <span class="mono muted">${esc(attachment.content_hash)}</span>
      <pre>${esc(attachment.content_preview || "")}</pre>
    </div>`).join("");
  const decoded = preview.decoded_preview ? `<h3>Decoded content</h3><pre>${esc(preview.decoded_preview)}</pre>` : "";
  const content = preview.content ? `<h3>Exact content</h3><pre>${esc(preview.content)}</pre>` : `<p class="muted small">No body content.</p>`;
  $("#approvalDetail").innerHTML = `
    <div class="detail">
      <div class="card-head tight">
        <div>
          <h2>${esc(preview.tool)}</h2>
          <div class="meta">${esc(approval.approval_id)} · ${esc(clock(approval.created_at))}</div>
        </div>
        <span class="pill warn">awaiting human</span>
      </div>
      <div class="labels">${labelChips(preview.labels)}</div>
      <h3>Task</h3>
      <div class="small">${esc(preview.task_description)}</div>
      <h3>Destination</h3>
      <div class="mono">${esc(destinationLabel(preview.destination))}</div>
      <h3>Risk</h3>
      <div><strong>${Number(risk.score || 0).toFixed(2)}</strong> <span class="muted small">${esc((risk.reasons || []).join("; "))}</span></div>
      <ul class="muted small">${reasons}</ul>
      <h3>Action hash</h3>
      <div class="mono">${esc(preview.action_hash)}</div>
      <div class="mono muted">preview ${esc(preview.preview_hash)}</div>
      <h3>Payload · ${num(preview.bytes_out)} bytes</h3>
      ${content}
      ${decoded}
      ${attachments ? `<h3>Attachments</h3>${attachments}` : ""}
      <div class="actions">
        <button class="btn primary" id="approveBtn">Approve exact action</button>
        <button class="btn ghost" id="denyBtn" style="border-color:rgba(251,113,133,.35);color:#fecdd3">Deny</button>
      </div>
      <div id="approvalNotice"></div>
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
      ? `Approved. Token bound to ${shortHash(result.action_hash, 20)} is valid for one execution.`
      : "Denied. The action cannot execute.";
    toast(verb === "approve" ? "Action approved." : "Action denied.", "ok");
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
    table.innerHTML = `<tbody><tr><td class="empty-row" colspan="8">No audit entries match this filter. ${state.audit.length ? "" : "Run a scenario or load sample activity."}</td></tr></tbody>`;
    return;
  }
  table.innerHTML = `
    <thead><tr><th>#</th><th>Time</th><th>Event</th><th>Decision</th><th>Tool</th><th>Rules</th><th>Risk</th><th>Reason</th></tr></thead>
    <tbody>${rows.map((entry) => `
      <tr data-audit-seq="${entry.seq}">
        <td class="mono">${entry.seq}</td>
        <td class="mono">${esc(clock(entry.timestamp))}</td>
        <td>${esc(entry.event)}</td>
        <td>${decisionBadge(entry.decision)}</td>
        <td class="mono">${esc(entry.tool)}</td>
        <td class="rule-cell">${esc((entry.rule_ids || []).join(", "))}</td>
        <td class="mono">${Number(entry.risk_score || 0).toFixed(2)}</td>
        <td class="reason-cell">${esc((entry.reasons || [])[0] || "")}</td>
      </tr>`).join("")}</tbody>`;
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
      ? `OK · ${num(verification.entries)} entries · head ${shortHash(verification.head, 20)}`
      : `FAILED · ${verification.error || "chain mismatch"}`;
    result.className = verification.ok ? "small" : "small notice bad";
    toast(verification.ok ? "Audit chain verified." : "Audit chain verification failed.", verification.ok ? "ok" : "bad");
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
    { key: "Effects", value: num(effects.length), sub: "recorded tool executions", cls: "" },
    { key: "Egress bytes", value: bytes(egress.reduce((sum, effect) => sum + Number(effect.bytes_out || 0), 0)), sub: `${egress.length} email/POST effect${egress.length === 1 ? "" : "s"}`, cls: "warn" },
    { key: "Delivered", value: num(delivered), sub: "side effects that reached a destination", cls: "good" },
    { key: "Destinations", value: num(destinations), sub: "unique destinations", cls: "" },
  ].map((item) => `
    <div class="kpi ${item.cls}">
      <div class="k">${esc(item.key)}</div>
      <div class="v">${esc(item.value)}</div>
      <div class="s">${esc(item.sub)}</div>
    </div>`).join("");

  const table = $("#effectTable");
  if (!effects.length) {
    table.innerHTML = `<tbody><tr><td class="empty-row" colspan="7">No effects recorded yet.</td></tr></tbody>`;
    return;
  }
  table.innerHTML = `
    <thead><tr><th>Time</th><th>Task</th><th>Tool</th><th>Destination</th><th>Bytes</th><th>Status</th><th>Content hash</th></tr></thead>
    <tbody>${effects.slice().reverse().map((effect) => `
      <tr>
        <td class="mono">${esc(clock(effect.timestamp))}</td>
        <td class="mono">${esc(shortHash(effect.task_id, 12))}</td>
        <td class="mono">${esc(effect.tool)}</td>
        <td class="mono">${esc(effect.destination)}</td>
        <td class="mono">${num(effect.bytes_out)}</td>
        <td>${effect.delivered ? `<span class="badge ALLOW">delivered</span>` : `<span class="badge DENIED">held</span>`}</td>
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
    { key: "Main episodes", value: num(episodes), sub: `${main.modes.length} configurations · 5 repeats`, cls: "" },
    { key: "Attack scenarios", value: num(b5.attack.n_scenarios), sub: "seven families", cls: "bad" },
    { key: "Benign tasks", value: num(b5.benign.n_scenarios), sub: "utility and false-block suite", cls: "good" },
    { key: "Detector sweep", value: num(sweepEpisodes), sub: "recall × false-positive grid", cls: "" },
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
    const tag = ["B4T", "B4TR"].includes(mode) ? "ablation" : MODE_LABELS[mode] || "";
    return `
      <div class="mode-row ${best ? "best" : ""}">
        <div class="mode-name">${esc(mode)}<span class="tag">${esc(tag)}</span></div>
        ${barCell(data.attack.asr, "#fb7185")}
        ${barCell(data.benign.tcr, "#34d399")}
        <div class="num">${num(data.benign.false_block_tasks)}</div>
        <div class="num">${Number(data.latency.end_to_end.p95 || 0).toFixed(2)}</div>
      </div>`;
  }).join("");
  $("#modeTable").innerHTML = `
    <div class="mode-row head"><div>Config</div><div>ASR</div><div>TCR</div><div class="num">FB</div><div class="num">p95</div></div>
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
  const colors = { B1: "#fbbf24", B3: "#fb7185", B5: "#34d399" };
  const x = (value) => left + plotW * value;
  const y = (value) => top + plotH * (1 - value);
  const parts = [`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack success as detector recall varies">`];
  for (let index = 0; index <= 4; index += 1) {
    const gy = top + (plotH * index) / 4;
    parts.push(`<line x1="${left}" y1="${gy}" x2="${width - right}" y2="${gy}" stroke="rgba(148,163,184,.12)"/>`);
    parts.push(`<text x="${left - 8}" y="${gy + 3}" text-anchor="end" fill="#64748b" font-family="ui-monospace, monospace" font-size="8">${(1 - index / 4) * 100}%</text>`);
  }
  for (let index = 0; index <= 4; index += 1) {
    const gx = left + (plotW * index) / 4;
    parts.push(`<text x="${gx}" y="${height - 10}" text-anchor="middle" fill="#64748b" font-family="ui-monospace, monospace" font-size="8">${(index / 4).toFixed(2)}</text>`);
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
      <span><i style="background:#fbbf24"></i>B1 prompt filter</span>
      <span><i style="background:#fb7185"></i>B3 risk only</span>
      <span><i style="background:#34d399"></i>B5 full</span>
    </div>
    ${parts.join("")}
    <div class="axis-label">detector recall →</div>`;
}

function heatColor(value) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  const hue = 145 - 145 * v;
  const light = 24 + 16 * v;
  return `background:hsl(${hue} 52% ${light}% / ${0.4 + 0.42 * v});`;
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
    return `<tr><td class="family-name">${esc(family)}</td>${cells}</tr>`;
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
      <thead><tr><th>Mode</th><th>Decision p50</th><th>Decision p95</th><th>E2E p50</th><th>E2E p95</th><th>E2E p99</th></tr></thead>
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
      <span class="name">${esc(rule)}</span>
      <div class="track"><div class="fill" style="width:${(count / max) * 100}%"></div></div>
      <span class="n">${num(count)}</span>
      <span class="desc">${esc(RULE_DESCRIPTIONS[rule] || "Rule hit")}</span>
    </div>`).join("");
}

function renderDenyCallout(denyAll) {
  const b5 = denyAll && denyAll.by_mode && denyAll.by_mode.B5;
  if (!b5) {
    $("#denyCallout").innerHTML = `<h2>Approvals are a utility valve</h2><p>When every approval is denied, B5 still blocks 96.8% of attacks but task completion falls sharply. The approval channel buys utility, not security.</p>`;
    return;
  }
  $("#denyCallout").innerHTML = `
    <h2>Approvals are a utility valve, not a security crutch</h2>
    <p>In the deny-all sensitivity run (${num(b5.n_episodes)} episodes), B5 still held attack success to <strong>${pct(b5.attack.asr, 1)}</strong> but task completion fell to <strong>${pct(b5.benign.tcr, 1)}</strong> with ${num(b5.benign.false_block_tasks)} false-block tasks. The security layer does the blocking; the approval channel recovers legitimate work.</p>`;
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
    if (event.target.closest("#runDemoInline")) {
      runDemo();
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
