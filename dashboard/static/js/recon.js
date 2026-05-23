// Recon page - Discover -> Scope -> Act
function reconPage() {
  return {
    // Form / scan state
    form: { target: '', scanType: 'standard', operator: 'web-user' },
    running: false,
    latestScanId: null,
    latestScanStatus: '',
    pollHandle: null,
    stats: { progress: 0 },

    // Data
    services: [],
    expanded: {},          // {service_id: bool}
    actionOutput: {},      // {service_id: text}
    filterText: '',
    logs: [],

    // Step 03 tab state
    activeTab: 'scope',    // 'scope' | 'exploit'
    exploitOutput: {},     // {service_id: text} - separate buffer so the
                           // Scope tab's actionOutput doesn't get clobbered
    exploitsAllowed: false,// mirrors VULNPILOT_ALLOW_EXPLOIT on the server

    // Modal
    cveModal: null,
    modalCves: [],

    init() {
      this.refresh();
      this.pollHandle = setInterval(() => this.refresh(), 2500);
    },

    destroy() {
      if (this.pollHandle) clearInterval(this.pollHandle);
    },

    // -------- Computed --------
    scanStatusLabel() {
      if (this.running) return `running… ${this.stats.progress || 0}%`;
      if (this.latestScanStatus === 'complete') return 'last scan: complete';
      if (this.latestScanStatus === 'partial')  return 'last scan: partial';
      if (this.latestScanStatus === 'error')    return 'last scan: error';
      if (this.services.length) return `${this.services.length} services discovered`;
      return 'idle';
    },

    filteredServices() {
      if (!this.filterText) return this.services;
      const q = this.filterText.toLowerCase();
      return this.services.filter(s =>
        String(s.port).includes(q) ||
        (s.name || '').toLowerCase().includes(q) ||
        (s.product || '').toLowerCase().includes(q) ||
        (s.version || '').toLowerCase().includes(q)
      );
    },

    scopedServices() {
      return this.services.filter(s => s.in_scope);
    },

    scopeCount() {
      return this.scopedServices().length;
    },

    // -------- Actions --------
    async startScan() {
      if (!this.form.target || this.running) return;
      this.running = true;
      this.stats.progress = 5;

      // Apply scan type to nmap_args via a query field on the request - the
      // backend currently uses config defaults; we send mode as a hint.
      const profileMap = { quick: 'safe', standard: 'safe', deep: 'audit' };
      const payload = {
        target: this.form.target,
        operator: this.form.operator || 'web-user',
        mode: profileMap[this.form.scanType] || 'safe',
        authorization_ref: 'ui-engagement',
        scan_profile: this.form.scanType,
      };
      try {
        const resp = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
          this.appendLog('error', data.error || resp.statusText);
          this.running = false;
          return;
        }
        this.latestScanId = data.id;
        this.appendLog('success', `Scan #${data.id} queued against ${this.form.target}.`);
      } catch (e) {
        this.appendLog('error', 'Network error: ' + e.message);
        this.running = false;
      }
    },

    async refresh() {
      try {
        const [logs, snap] = await Promise.all([
          fetch('/api/logs?lines=80').then(r => r.ok ? r.json() : []),
          fetch('/api/scans/latest/services').then(r => r.ok ? r.json() : { services: [] }),
        ]);
        // Merge log lines
        const seen = new Set(this.logs.map(l => l.time + '|' + l.message));
        for (const line of logs) {
          const k = `[${line.time}]|${line.message}`;
          if (!seen.has(k)) {
            this.logs.push({ time: `[${line.time}]`, severity: line.severity, message: line.message });
          }
        }
        if (this.logs.length > 500) this.logs.splice(0, this.logs.length - 500);

        // Merge service list (preserve local UI state for in_scope toggling responsiveness)
        const incoming = snap.services || [];
        const localScope = new Map(this.services.map(s => [s.id, s.in_scope]));
        this.services = incoming.map(s => ({
          ...s,
          in_scope: localScope.has(s.id) ? localScope.get(s.id) : s.in_scope,
        }));

        // Refresh exploit-mode flag every poll so unsetting the env var
        // and restarting the dashboard locks down the UI without a
        // manual page reload.
        if (typeof snap.exploits_allowed === 'boolean') {
          this.exploitsAllowed = snap.exploits_allowed;
        }

        if (snap.scan) {
          this.latestScanId = snap.scan.id;
          this.latestScanStatus = snap.scan.status;
          if (snap.scan.status === 'running' || snap.scan.status === 'queued') {
            this.running = true;
            this.stats.progress = Math.min(95, (this.stats.progress || 0) + 6);
          } else {
            if (this.running) {
              this.stats.progress = 100;
              this.appendLog('success', `Scan #${snap.scan.id} ${snap.scan.status} — ${this.services.length} services.`);
            }
            this.running = false;
          }
        }
      } catch (_) { /* silent */ }
    },

    async toggleScope(svc, checked) {
      svc.in_scope = checked;  // optimistic
      try {
        const resp = await fetch(`/api/services/${svc.id}/scope`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ in_scope: !!checked }),
        });
        if (!resp.ok) throw new Error(await resp.text());
      } catch (e) {
        this.appendLog('error', `Failed to update scope for ${svc.port}: ${e.message}`);
      }
    },

    async addAllToScope() {
      for (const s of this.services) {
        if (!s.in_scope) await this.toggleScope(s, true);
      }
    },

    async addRiskyToScope() {
      for (const s of this.services) {
        if (!s.in_scope && s.cve_count > 0 && (s.max_cvss >= 7.0)) {
          await this.toggleScope(s, true);
        }
      }
      this.appendLog('ai', `Added ${this.scopeCount()} risky services (CVSS ≥ 7) to scope.`);
    },

    async action(svc, name) {
      this.actionOutput[svc.id] = '⟳ ' + name + '...';
      try {
        const resp = await fetch(`/api/services/${svc.id}/action`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: name }),
        });
        const data = await resp.json();
        this.actionOutput[svc.id] = data.output || JSON.stringify(data, null, 2);
        this.appendLog('info', `[${svc.port}/${svc.name}] action ${name} → ${data.status || 'done'}`);
      } catch (e) {
        this.actionOutput[svc.id] = 'Error: ' + e.message;
      }
    },

    async runAllChecks() {
      for (const s of this.scopedServices()) {
        await this.action(s, 'check');
      }
    },

    // -------- Exploit tab --------
    // Pop a confirm() before firing anything destructive. We deliberately
    // use the browser-native dialog instead of a custom modal so it can't
    // be auto-dismissed by stray clicks - the operator must read the
    // module name and click OK.
    confirmAndExploit(svc, action) {
      if (!this.exploitsAllowed) {
        this.exploitOutput[svc.id] =
          'Blocked: VULNPILOT_ALLOW_EXPLOIT=1 must be set before launching the dashboard.';
        return;
      }
      if (!svc.recommended_exploit_module ||
          svc.recommended_exploit_module === 'manual review') {
        this.exploitOutput[svc.id] = 'No exploit module registered for this service.';
        return;
      }
      const verb = action === 'run' ? 'RUN EXPLOIT' : 'check';
      const msg =
        `${verb} against ${svc.port}/${svc.name} on the live target?\n\n` +
        `Module: ${svc.recommended_exploit_module}\n\n` +
        (action === 'run'
           ? 'This is a destructive action. The target may crash, reboot, or be left in an exploited state. Continue?'
           : 'This runs the module\'s check action only. No payload is fired. Continue?');
      if (!window.confirm(msg)) return;
      this.runExploit(svc, action);
    },

    async runExploit(svc, action) {
      this.exploitOutput[svc.id] = '⟳ exploit ' + action + '...';
      try {
        const resp = await fetch(`/api/services/${svc.id}/exploit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, confirm: true }),
        });
        const data = await resp.json();
        this.exploitOutput[svc.id] =
          (data.module ? `module: ${data.module}\n` : '') +
          (data.duration_seconds !== undefined ? `duration: ${data.duration_seconds}s\n` : '') +
          (data.run_id !== undefined ? `run #${data.run_id}\n` : '') +
          `status: ${data.status || 'unknown'}\n\n` +
          (data.output || JSON.stringify(data, null, 2));
        // Map MSF status -> log severity so the live log strip is readable.
        const sev = data.status === 'vulnerable' || data.status === 'completed'
          ? 'success'
          : (data.status === 'error' ? 'error'
            : (data.status === 'blocked' || data.status === 'skipped' ? 'warn'
              : 'info'));
        this.appendLog(sev,
          `[${svc.port}/${svc.name}] EXPLOIT ${action} → ${data.status || 'done'}`);
      } catch (e) {
        this.exploitOutput[svc.id] = 'Network error: ' + e.message;
        this.appendLog('error', `Exploit ${action} failed: ${e.message}`);
      }
    },

    async showCves(svc) {
      this.cveModal = svc;
      this.modalCves = [];
      try {
        const data = await fetch(`/api/services/${svc.id}/cves`).then(r => r.json());
        this.modalCves = Array.isArray(data) ? data : [];
      } catch (e) {
        this.appendLog('error', 'Failed to load CVEs: ' + e.message);
      }
    },

    patchInfo(svc) {
      const top = (svc.top_cves || [])[0];
      if (top) window.open('https://nvd.nist.gov/vuln/detail/' + top.cve_id, '_blank');
    },

    downloadReport() {
      if (!this.latestScanId) return;
      window.open(`/api/scans/${this.latestScanId}/report.json`, '_blank');
    },

    // -------- Logging --------
    appendLog(severity, message) {
      const t = new Date().toISOString().replace('T', ' ').slice(0, 19);
      this.logs.push({ time: `[${t}]`, severity, message });
      if (this.logs.length > 500) this.logs.shift();
    },
  };
}
