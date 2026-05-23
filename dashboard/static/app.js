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
