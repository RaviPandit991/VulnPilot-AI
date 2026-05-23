async function refreshScans() {
  const resp = await fetch("/api/scans");
  const data = await resp.json();
  const tbody = document.querySelector("#scans-table tbody");
  tbody.innerHTML = "";
  for (const scan of data) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${scan.id}</td>
      <td>${scan.target}</td>
      <td>${scan.operator}</td>
      <td>${scan.mode}</td>
      <td>${scan.status}</td>
      <td>${scan.started_at ?? ""}</td>
    `;
    tr.addEventListener("click", () => loadDetail(scan.id));
    tbody.appendChild(tr);
  }
}

async function loadDetail(id) {
  const resp = await fetch(`/api/scans/${id}`);
  const data = await resp.json();
  document.getElementById("detail-card").hidden = false;
  document.getElementById("detail").textContent = JSON.stringify(data, null, 2);
}

document.getElementById("scan-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const form = new FormData(ev.target);
  const payload = Object.fromEntries(form.entries());
  const status = document.getElementById("form-status");
  status.textContent = "Queueing...";
  const resp = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    status.textContent = `Error: ${err.error ?? resp.statusText}`;
    return;
  }
  const data = await resp.json();
  status.textContent = `Queued scan #${data.id}`;
  refreshScans();
});

refreshScans();
setInterval(refreshScans, 5000);


// ---------------------------------------------------------------------------
// Exploit panel
// ---------------------------------------------------------------------------
let exploitTemplates = [];

async function loadExploitCatalog() {
  const select = document.getElementById("exploit-template-select");
  const banner = document.getElementById("exploit-status-banner");
  try {
    const resp = await fetch("/api/exploit/catalog");
    const data = await resp.json();
    exploitTemplates = data.templates || [];

    select.innerHTML = "";
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "-- select a template --";
    select.appendChild(placeholder);

    for (const tpl of exploitTemplates) {
      const opt = document.createElement("option");
      opt.value = tpl.id;
      opt.textContent = `${tpl.id}  (port ${tpl.default_port}, ${tpl.risk})`;
      select.appendChild(opt);
    }

    // Server-side gating banner
    const messages = [];
    if (!data.exploit_enabled) {
      messages.push(
        "Server does NOT have VULNPILOT_ALLOW_EXPLOIT=1. Runs will be rejected."
      );
    }
    if (data.force_check_only) {
      messages.push(
        "Server config has exploit.force_check_only=true. 'Actually exploit' will be downgraded to check-only."
      );
    }
    if (messages.length > 0) {
      banner.hidden = false;
      banner.textContent = messages.join(" ");
    } else {
      banner.hidden = true;
    }
  } catch (err) {
    select.innerHTML = '<option value="">Failed to load catalog</option>';
  }
}

function showTemplateMeta(templateId) {
  const meta = document.getElementById("exploit-template-meta");
  const tpl = exploitTemplates.find((t) => t.id === templateId);
  if (!tpl) {
    meta.hidden = true;
    meta.innerHTML = "";
    return;
  }
  const cves = (tpl.cve_ids || []).join(", ") || "none mapped";
  const products = (tpl.targets_product || []).join(", ") || "any";
  meta.hidden = false;
  meta.innerHTML = `
    <div><strong>${tpl.title}</strong></div>
    <div>Module: <code>${tpl.module}</code></div>
    <div>Default port: ${tpl.default_port} (${tpl.service})</div>
    <div>Risk: <strong>${tpl.risk}</strong> &middot; CVEs: ${cves}</div>
    <div>Targets: ${products}</div>
    <div>Default payload: <code>${tpl.default_payload || "(none)"}</code></div>
    <div>Supports check action: ${tpl.supports_check ? "yes" : "no"}</div>
    ${tpl.notes ? `<div>Notes: ${tpl.notes}</div>` : ""}
  `;
}

function updatePayloadFieldsVisibility() {
  const checkOnly = document.querySelector(
    "input[name='check_only']:checked"
  )?.value === "true";
  document.getElementById("exploit-payload-fields").hidden = checkOnly;
}

document
  .getElementById("exploit-template-select")
  .addEventListener("change", (ev) => showTemplateMeta(ev.target.value));

document
  .querySelectorAll("input[name='check_only']")
  .forEach((el) => el.addEventListener("change", updatePayloadFieldsVisibility));

document.getElementById("exploit-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const form = new FormData(ev.target);
  const status = document.getElementById("exploit-status");
  const resultEl = document.getElementById("exploit-result");
  status.className = "status";
  status.textContent = "Running... (check actions usually finish in <30s)";
  resultEl.hidden = true;

  // Build JSON payload, normalizing types
  const payload = {
    target: form.get("target"),
    operator: form.get("operator"),
    authorization_ref: form.get("authorization_ref"),
    template_id: form.get("template_id"),
    confirmation: form.get("confirmation"),
    check_only: form.get("check_only") === "true",
    force: form.get("force") === "on",
  };
  const port = form.get("port");
  if (port) payload.port = parseInt(port, 10);
  const msfPayload = form.get("payload");
  if (msfPayload) payload.payload = msfPayload;
  const lhost = form.get("lhost");
  if (lhost) payload.lhost = lhost;
  const lport = form.get("lport");
  if (lport) payload.lport = parseInt(lport, 10);

  try {
    const resp = await fetch("/api/exploit/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) {
      status.className = "status bad";
      status.textContent = `Error: ${data.error ?? resp.statusText}`;
      return;
    }
    const o = data.outcome;
    const cls = ["vulnerable", "session-opened"].includes(o.status)
      ? "bad"
      : ["not-vulnerable", "completed"].includes(o.status)
      ? "ok"
      : "warn";
    status.className = `status ${cls}`;
    status.textContent =
      `Scan #${data.scan_id}: ${o.module} -> ${o.status.toUpperCase()} ` +
      `(action=${o.action}, ${o.duration_seconds.toFixed(1)}s)` +
      (o.session_id ? ` session=${o.session_id}` : "");
    resultEl.hidden = false;
    resultEl.textContent = JSON.stringify(o, null, 2);
    refreshScans();
  } catch (err) {
    status.className = "status bad";
    status.textContent = `Network error: ${err.message}`;
  }
});

loadExploitCatalog();
