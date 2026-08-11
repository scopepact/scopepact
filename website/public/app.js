const cases = {
  allowed: {
    method: "CLIENT → GUARD",
    resource: "/workspace/project/README.md",
    decision: "ALLOWED",
    reason: "Decision and budget reservation were synchronized before forwarding.",
    rule: "project-file-writes",
    effect: "105e4fee84141175…",
    receipt: "Ed25519 verified",
    commit: "Synced before forward",
    state: "STATE V3 · SEQUENCE 1",
    className: "allowed",
  },
  blocked: {
    method: "CLIENT → GUARD",
    resource: "/etc/hosts",
    decision: "BLOCKED",
    reason: "The resource is outside the granted project prefix and never reaches the child.",
    rule: "no matching grant",
    effect: "f8a811343be8b105…",
    receipt: "Ed25519 verified",
    commit: "Blocked receipt synced",
    state: "STATE V3 · SEQUENCE 2",
    className: "blocked",
  },
  duplicate: {
    method: "RESTART → REPLAY",
    resource: "/workspace/project/README.md",
    decision: "SUPPRESSED",
    reason: "Recovered durable state recognizes the effect and prevents a second execution.",
    rule: "project-file-writes",
    effect: "105e4fee84141175…",
    receipt: "Ed25519 verified",
    commit: "Original reservation retained",
    state: "RECOVERED · DUPLICATE",
    className: "duplicate",
  },
  child: {
    method: "SERVER → GUARD",
    resource: "child output exceeds 4 MiB",
    decision: "STOPPED",
    reason: "Invalid child output terminates the proxy instead of crossing the trust boundary.",
    rule: "MCP output boundary",
    effect: "no admitted effect",
    receipt: "Redacted failure event",
    commit: "State unchanged",
    state: "CHILD TERMINATED · FAIL CLOSED",
    className: "failure",
  },
};

const decisionOutput = document.querySelector("#decision-output");
const caseButtons = [...document.querySelectorAll("[data-case]")];

function renderCase(caseId) {
  const selected = cases[caseId];
  document.querySelector("#demo-method").textContent = selected.method;
  document.querySelector("#demo-resource").textContent = selected.resource;
  document.querySelector("#demo-decision").textContent = selected.decision;
  document.querySelector("#demo-reason").textContent = selected.reason;
  document.querySelector("#demo-rule").textContent = selected.rule;
  document.querySelector("#demo-effect").textContent = selected.effect;
  document.querySelector("#demo-receipt").textContent = selected.receipt;
  document.querySelector("#demo-commit").textContent = selected.commit;
  document.querySelector("#demo-state").textContent = selected.state;
  decisionOutput.className = `decision-output ${selected.className}`;

  caseButtons.forEach((button) => {
    const active = button.dataset.case === caseId;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

caseButtons.forEach((button) => {
  button.addEventListener("click", () => renderCase(button.dataset.case));
});

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const temporary = document.createElement("textarea");
  temporary.value = value;
  temporary.setAttribute("readonly", "");
  temporary.style.position = "fixed";
  temporary.style.opacity = "0";
  document.body.appendChild(temporary);
  temporary.select();
  document.execCommand("copy");
  temporary.remove();
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.querySelector(`#${button.dataset.copyTarget}`);
    try {
      await copyText(target.textContent);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Select command";
      window.getSelection()?.selectAllChildren(target);
    }
    window.setTimeout(() => { button.textContent = "Copy"; }, 1_200);
  });
});

document.querySelector("#current-year").textContent = String(new Date().getFullYear());
