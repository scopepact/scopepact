const ui = {
  runtime: document.querySelector("#runtime-status"),
  exportButton: document.querySelector("#export-button"),
  runSelectedButton: document.querySelector("#run-selected-button"),
  runSuiteButton: document.querySelector("#run-suite-button"),
  copyButton: document.querySelector("#copy-button"),
  categoryFilter: document.querySelector("#category-filter"),
  scenarioList: document.querySelector("#scenario-list"),
  scenarioCount: document.querySelector("#scenario-count"),
  suiteValue: document.querySelector("#suite-value"),
  testValue: document.querySelector("#test-value"),
  decisionValue: document.querySelector("#decision-value"),
  invariantValue: document.querySelector("#invariant-value"),
  elapsedValue: document.querySelector("#elapsed-value"),
  category: document.querySelector("#scenario-category"),
  title: document.querySelector("#execution-title"),
  conformanceBadge: document.querySelector("#conformance-badge"),
  decisionBadge: document.querySelector("#decision-badge"),
  outcomeBand: document.querySelector("#outcome-band"),
  outcomeTitle: document.querySelector("#outcome-title"),
  outcomeMessage: document.querySelector("#outcome-message"),
  pulse: document.querySelector("#route-pulse"),
  checkCount: document.querySelector("#check-count"),
  checkList: document.querySelector("#check-list"),
  evidenceContent: document.querySelector("#evidence-content"),
  tabs: [...document.querySelectorAll(".tab")],
  kernelTitle: document.querySelector("#kernel-title"),
  kernelMessage: document.querySelector("#kernel-message"),
  decisionCode: document.querySelector("#decision-code"),
};

const state = {
  scenarios: [],
  results: new Map(),
  selectedId: null,
  currentResult: null,
  evidenceTab: "overview",
  suite: null,
  busy: false,
};

function selectedScenario() {
  return state.scenarios.find((scenario) => scenario.id === state.selectedId) ?? null;
}

function setBusy(busy) {
  state.busy = busy;
  ui.runSelectedButton.disabled = busy || !state.selectedId;
  ui.runSuiteButton.disabled = busy;
  ui.exportButton.disabled = busy || state.results.size === 0;
  ui.copyButton.disabled = busy || !state.currentResult;
  ui.pulse.classList.toggle("active", busy);
}

function decisionLabel(decision) {
  if (decision === "accepted") return "ACCEPTED";
  if (decision === "rejected") return "BLOCKED";
  return "PENDING";
}

function decisionCode(reason) {
  if (!reason) return "--";
  return reason.toUpperCase().replace(/[^A-Z0-9]+/gu, "_").replace(/^_|_$/gu, "");
}

function truncate(value, length = 18) {
  if (value === null || value === undefined) return "--";
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function element(name, className, text) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderCatalog() {
  const category = ui.categoryFilter.value;
  const visible = state.scenarios.filter(
    (scenario) => category === "all" || scenario.category === category,
  );
  ui.scenarioCount.textContent = String(visible.length);
  const rows = visible.map((scenario) => {
    const result = state.results.get(scenario.id);
    const button = element("button", "scenario-row");
    button.type = "button";
    button.classList.toggle("selected", scenario.id === state.selectedId);
    button.dataset.scenarioId = scenario.id;
    button.setAttribute("aria-pressed", String(scenario.id === state.selectedId));

    const indicator = element("span", `scenario-indicator ${result?.status ?? "idle"}`);
    indicator.setAttribute("aria-hidden", "true");
    const copy = element("span", "scenario-copy");
    copy.append(
      element("strong", "", scenario.title),
      element("span", "", `${scenario.category} · ${scenario.invariant}`),
    );
    const expected = element(
      "span",
      `expected-decision ${scenario.expected_decision}`,
      scenario.expected_decision === "accepted" ? "ACCEPT" : "BLOCK",
    );
    button.append(indicator, copy, expected);
    button.addEventListener("click", () => selectScenario(scenario.id));
    return button;
  });
  ui.scenarioList.replaceChildren(...rows);
}

function renderChecks(checks = []) {
  ui.checkCount.textContent = `${checks.length} ${checks.length === 1 ? "check" : "checks"}`;
  if (checks.length === 0) {
    ui.checkList.replaceChildren(element("p", "empty-state", "No verification evidence yet."));
    return;
  }
  const rows = checks.map((check, index) => {
    const row = element("div", "check-row");
    const ordinal = element("span", "check-index", String(index + 1).padStart(2, "0"));
    const copy = element("span", "check-copy");
    copy.append(element("strong", "", check.label));
    const context = check.runtime ?? `JavaScript · attempt ${check.attempt ?? 1}`;
    copy.append(element("span", "", check.detail ? `${context} · ${check.detail}` : context));
    const status = element("span", `check-status ${check.status}`, check.status.toUpperCase());
    row.append(ordinal, copy, status);
    return row;
  });
  ui.checkList.replaceChildren(...rows);
}

function appendDefinition(target, label, value) {
  const wrapper = element("div", "evidence-row");
  wrapper.append(element("dt", "", label), element("dd", "", value));
  target.append(wrapper);
}

function envelopeFacts(envelope) {
  return [
    ["Version", `${envelope.protocol_major}.${envelope.protocol_minor}`],
    ["Session", envelope.session],
    ["Interaction", envelope.interaction],
    ["Sequence", envelope.sequence],
    ["Sender", envelope.sender],
    ["Audience", envelope.audience],
    ["Policy epoch", envelope.policy_epoch],
    ["Message kind", envelope.message_kind],
    ["Schema digest", envelope.payload_schema],
    ["Payload digest", envelope.payload_digest],
  ];
}

function evidenceValue() {
  if (!state.currentResult) return null;
  if (state.evidenceTab === "envelope") return state.currentResult.offer?.envelope ?? null;
  if (state.evidenceTab === "payload") return state.currentResult.offer?.payload ?? null;
  if (state.evidenceTab === "raw") return state.currentResult;
  return {
    scenario: state.currentResult.scenario,
    status: state.currentResult.status,
    decision: state.currentResult.decision,
    reason: state.currentResult.reason,
    runtimes: state.currentResult.runtimes,
  };
}

function renderEvidence() {
  ui.tabs.forEach((tab) => {
    const active = tab.dataset.tab === state.evidenceTab;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  const scenario = selectedScenario();
  const result = state.currentResult;
  if (!scenario) {
    ui.evidenceContent.replaceChildren(element("p", "empty-state", "No scenario selected."));
    return;
  }
  if (state.evidenceTab === "overview") {
    const list = element("dl", "evidence-list");
    appendDefinition(list, "Rule", scenario.rule);
    appendDefinition(list, "Expected", scenario.expected);
    appendDefinition(list, "Why it matters", scenario.impact);
    appendDefinition(list, "Implementations", result?.runtimes?.join(" → ") ?? "Python → JavaScript");
    appendDefinition(list, "Observed", result ? result.reason : "Not run");
    ui.evidenceContent.replaceChildren(list);
    return;
  }
  if (!result) {
    ui.evidenceContent.replaceChildren(element("p", "empty-state", "Run this case to inspect evidence."));
    return;
  }
  if (state.evidenceTab === "envelope") {
    const envelope = result.offer?.envelope;
    if (!envelope) {
      ui.evidenceContent.replaceChildren(element("p", "empty-state", "No envelope was produced."));
      return;
    }
    const facts = element("dl", "frame-facts");
    envelopeFacts(envelope).forEach(([label, value]) => {
      const wrapper = element("div", "");
      const term = element("dt", "", label);
      const detail = element("dd", "", truncate(value));
      detail.title = String(value ?? "");
      wrapper.append(term, detail);
      facts.append(wrapper);
    });
    const pre = element("pre", "", JSON.stringify(envelope, null, 2));
    ui.evidenceContent.replaceChildren(facts, pre);
    return;
  }
  const value = state.evidenceTab === "payload" ? result.offer?.payload : result;
  ui.evidenceContent.replaceChildren(element("pre", "", JSON.stringify(value, null, 2)));
}

function renderPending(scenario) {
  state.currentResult = null;
  ui.category.textContent = scenario.category.toUpperCase();
  ui.title.textContent = scenario.title;
  ui.testValue.textContent = "NOT RUN";
  ui.testValue.className = "";
  ui.decisionValue.textContent = "--";
  ui.decisionValue.className = "";
  ui.invariantValue.textContent = scenario.invariant;
  ui.elapsedValue.textContent = "--";
  ui.conformanceBadge.textContent = "NOT RUN";
  ui.conformanceBadge.className = "badge";
  ui.decisionBadge.textContent = scenario.expected_decision === "accepted" ? "EXPECT ACCEPT" : "EXPECT BLOCK";
  ui.decisionBadge.className = `badge decision ${scenario.expected_decision}`;
  ui.outcomeBand.className = "outcome-band";
  ui.outcomeTitle.textContent = "No evidence yet";
  ui.outcomeMessage.textContent = scenario.expected;
  ui.kernelTitle.textContent = "Awaiting verification";
  ui.kernelMessage.textContent = scenario.rule;
  ui.decisionCode.textContent = "--";
  renderChecks();
  renderEvidence();
  setBusy(state.busy);
}

function renderResult(result) {
  state.currentResult = result;
  const scenario = result.scenario;
  const passed = result.status === "passed";
  const blocked = result.decision === "rejected";
  ui.category.textContent = scenario.category.toUpperCase();
  ui.title.textContent = scenario.title;
  ui.testValue.textContent = passed ? "PASS" : "FAIL";
  ui.testValue.className = passed ? "positive" : "negative";
  ui.decisionValue.textContent = decisionLabel(result.decision);
  ui.decisionValue.className = blocked ? "blocked" : "positive";
  ui.invariantValue.textContent = scenario.invariant;
  ui.elapsedValue.textContent = `${result.elapsed_ms} ms`;
  ui.conformanceBadge.textContent = passed ? "PASS" : "FAIL";
  ui.conformanceBadge.className = `badge ${result.status}`;
  ui.decisionBadge.textContent = decisionLabel(result.decision);
  ui.decisionBadge.className = `badge decision ${result.decision}`;
  ui.outcomeBand.className = `outcome-band ${passed ? "passed" : "failed"}`;
  ui.outcomeTitle.textContent = passed
    ? blocked
      ? "Blocked as expected"
      : "Accepted as expected"
    : "Unexpected protocol result";
  ui.outcomeMessage.textContent = result.reason;
  ui.kernelTitle.textContent = blocked ? "Effect path blocked" : "Message admitted";
  ui.kernelMessage.textContent = scenario.impact;
  ui.decisionCode.textContent = decisionCode(result.reason);
  renderChecks(result.checks);
  renderEvidence();
  renderCatalog();
  setBusy(state.busy);
}

function selectScenario(id) {
  state.selectedId = id;
  const result = state.results.get(id);
  if (result) renderResult(result);
  else renderPending(selectedScenario());
  renderCatalog();
}

async function requestJson(path, options) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.reason || "Protocol test failed");
  return payload;
}

function showError(error) {
  ui.testValue.textContent = "ERROR";
  ui.testValue.className = "negative";
  ui.conformanceBadge.textContent = "ERROR";
  ui.conformanceBadge.className = "badge failed";
  ui.outcomeBand.className = "outcome-band failed";
  ui.outcomeTitle.textContent = "Test runner error";
  ui.outcomeMessage.textContent = error.message;
}

async function runSelected() {
  if (!state.selectedId || state.busy) return;
  setBusy(true);
  ui.testValue.textContent = "RUNNING";
  ui.conformanceBadge.textContent = "RUNNING";
  ui.outcomeTitle.textContent = "Verifying signed frame";
  try {
    const result = await requestJson("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario_id: state.selectedId }),
    });
    state.results.set(state.selectedId, result);
    renderResult(result);
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

async function runSuite() {
  if (state.busy) return;
  setBusy(true);
  ui.suiteValue.textContent = "RUNNING";
  try {
    const suite = await requestJson("/api/suite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    state.suite = suite;
    suite.results.forEach((result) => state.results.set(result.scenario.id, result));
    ui.suiteValue.textContent = `${suite.passed}/${suite.total} ${suite.status.toUpperCase()}`;
    ui.suiteValue.className = suite.status === "passed" ? "positive" : "negative";
    const selected = state.results.get(state.selectedId) ?? suite.results[0];
    state.selectedId = selected.scenario.id;
    renderResult(selected);
  } catch (error) {
    ui.suiteValue.textContent = "ERROR";
    ui.suiteValue.className = "negative";
    showError(error);
  } finally {
    setBusy(false);
  }
}

function reportPayload() {
  return {
    protocol: "ScopePact v0.1",
    generated_at: new Date().toISOString(),
    suite: state.suite
      ? { status: state.suite.status, passed: state.suite.passed, total: state.suite.total }
      : null,
    results: [...state.results.values()],
  };
}

function exportReport() {
  const blob = new Blob([`${JSON.stringify(reportPayload(), null, 2)}\n`], {
    type: "application/json",
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "scopepact-conformance-report.json";
  link.click();
  URL.revokeObjectURL(link.href);
}

async function copyEvidence() {
  const value = evidenceValue();
  if (!value) return;
  await navigator.clipboard.writeText(JSON.stringify(value, null, 2));
  ui.copyButton.textContent = "Copied";
  window.setTimeout(() => { ui.copyButton.textContent = "Copy JSON"; }, 1_200);
}

ui.runSelectedButton.addEventListener("click", runSelected);
ui.runSuiteButton.addEventListener("click", runSuite);
ui.exportButton.addEventListener("click", exportReport);
ui.copyButton.addEventListener("click", () => { copyEvidence().catch(showError); });
ui.categoryFilter.addEventListener("change", renderCatalog);
ui.tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    state.evidenceTab = tab.dataset.tab;
    renderEvidence();
  });
});

async function start() {
  try {
    const [health, catalog] = await Promise.all([
      requestJson("/api/health"),
      requestJson("/api/scenarios"),
    ]);
    const ready = health.status === "ready";
    ui.runtime.className = `runtime-status ${ready ? "ready" : "error"}`;
    ui.runtime.lastElementChild.textContent = ready ? "LOCAL READY" : "RUNTIME MISSING";
    state.scenarios = catalog.scenarios;
    const categories = [...new Set(state.scenarios.map((scenario) => scenario.category))].sort();
    ui.categoryFilter.append(
      ...categories.map((category) => {
        const option = document.createElement("option");
        option.value = category;
        option.textContent = category;
        return option;
      }),
    );
    ui.suiteValue.textContent = `0/${health.scenario_count} NOT RUN`;
    state.selectedId = state.scenarios[0]?.id ?? null;
    renderCatalog();
    if (state.selectedId) renderPending(selectedScenario());
    if (ready && state.selectedId) await runSelected();
  } catch (error) {
    ui.runtime.className = "runtime-status error";
    ui.runtime.lastElementChild.textContent = "OFFLINE";
    showError(error);
  }
}

start();
