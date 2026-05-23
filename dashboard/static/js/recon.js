// Recon page (Attack Control Center) - Alpine component
function reconPage() {
  return {
    tabs: [
      { key: 'recon',     label: 'Reconnaissance' },
      { key: 'enum',      label: 'Enumeration' },
      { key: 'vuln',      label: 'Vulnerability Scan' },
      { key: 'exploit',   label: 'Exploitation' },
      { key: 'post',      label: 'Post Exploitation' },
      { key: 'priv',      label: 'Privilege Escalation' },
      { key: 'persist',   label: 'Persistence' },
      { key: 'report',    label: 'Reporting' },
    ],
    activeTab: 'recon',

    form: {
      target: '',
      domain: '',
      os: 'Auto-detect',
      portStart: '1',
      portEnd: '65535',
      scanType: 'intense',
      exploitMode: 'safe',
      payload: 'None',
      auth: '',
      proxy: '',
      ai: true,
      intensity: 4,
    },

    // Live state
    running: false,
    paused: false,
    searchOpen: false,
    consoleInput: '',
    showAi: false,
    latestScanId: null,
    pollHandle: null,

    // Filters
    logFilter: '',
    scopeRiskFilter: '',
    scopeAttackFilter: '',

    // Stats
    stats: { progress: 0, portsDone: 0, portsTotal: 0, vulns: 0, exploits: 0 },

    // Logs (in-memory ring buffer; merged with /api/logs polled output)
    logs: [],
    aiRecommendation:
      'Configure a target to receive tailored recommendations. The AI engine ranks findings by CVSS, exploitability, and rule-pack matches.',

    // Scope (CVE cards)
    scope: [],
    _gauges: {},

    init() {
      this.refresh();
      this.pollHandle = setInterval(() => this.refresh(), 2000);
      this.$watch('scope', () => this.$nextTick(() => this.renderGauges()));
    },

    destroy() {
      if (this.pollHandle) clearInterval(this.pollHandle);
    },

    intensityLabel() {
      return ['', 'LEVEL 1', 'LEVEL 2', 'LEVEL 3', 'AI OPTIMISED'][this.form.intensity] || '';
    },

    commandPreview() {
      const f = this.form;
      const flags = {
        quick:   '-T4 --top-ports 100',
        intense: '-sV -sC -T4 -A',
        stealth: '-sS -T2 -f',
        full:    '-sV -sC -p-',
      }[f.scanType] || '-sV -sC';
      const range = (f.portStart && f.portEnd && f.scanType !== 'full') ? `-p ${f.portStart}-${f.portEnd}` : '';
      const ai = f.ai ? '--ai-scan' : '';
      const intensity = ` --intensity ${this.intensityLabel().toLowerCase().replace(/\s/g,'-')}`;
      const tgt = f.target || '<target>';
      return `vulnpilot_ai > ${tgt} ${flags} ${range} ${ai}${intensity}`.replace(/\s+/g,' ').trim();
    },

    resetForm() {
      this.form.target = '';
      this.form.domain = '';
      this.form.auth = '';
      this.stats = { progress: 0, portsDone: 0, portsTotal: 0, vulns: 0, exploits: 0 };
      this.appendLog('info', 'Form reset.');
    },

    async startScan() {
      if (!this.form.target) return;
      this.running = true;
      this.stats = { progress: 5, portsDone: 0, portsTotal: 1000, vulns: 0, exploits: 0 };
      this.appendLog('info', `Queueing scan against ${this.form.target}...`);

      const payload = {
        target: this.form.target,
        operator: 'web-user',
        mode: this.form.exploitMode || 'safe',
        authorization_ref: 'ui-engagement',
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
        this.appendLog('success', `Scan #${data.id} queued.`);
      } catch (e) {
        this.appendLog('error', 'Network error: ' + e.message);
        this.running = false;
      }
    },

    stopScan() {
      // Backend support TBD - emit a UI signal for now
      this.appendLog('warn', 'Stop requested (backend cancellation not yet wired).');
      this.running = false;
    },

    smartEnumeration() {
      this.activeTab = 'enum';
      this.appendLog('ai', 'Smart enumeration mode selected. AI will pick safest enum modules.');
    },

    generateReport() {
      if (!this.latestScanId) return;
      window.open(`/api/scans/${this.latestScanId}/report.json`, '_blank');
    },

    saveWorkspace() {
      this.appendLog('success', 'Workspace state snapshotted to localStorage.');
      try {
        localStorage.setItem('vulnpilot.workspace', JSON.stringify(this.form));
      } catch {}
    },

    showPoc(card) {
      this.appendLog('ai', `POC summary for <b>${card.cve_id}</b>: ${card.summary || 'no description'}`);
    },

    patchInfo(card) {
      const url = `https://nvd.nist.gov/vuln/detail/${card.cve_id}`;
      window.open(url, '_blank');
    },

    exportLogs() {
      const blob = new Blob([this.logs.map(l => `${l.time} [${l.severity}] ${l.message}`).join('\n')], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'vulnpilot-logs.txt';
      a.click();
    },

    echoConsole() {
      if (!this.consoleInput.trim()) return;
      this.appendLog('info', `> ${this.consoleInput}`);
      this.consoleInput = '';
    },

    appendLog(severity, message) {
      const now = new Date();
      const t = now.toISOString().replace('T',' ').slice(0,19);
      this.logs.push({ time: `[${t}]`, severity, message });
      if (this.logs.length > 500) this.logs.shift();
      this.$nextTick(() => {
        const el = this.$refs.logBox;
        if (el && !this.paused) el.scrollTop = el.scrollHeight;
      });
    },

    filteredLogs() {
      if (!this.logFilter) return this.logs;
      return this.logs.filter(l => l.severity === this.logFilter);
    },

    filteredScope() {
      let out = this.scope;
      if (this.scopeRiskFilter) {
        out = out.filter(c => (c.severity || '').toLowerCase() === this.scopeRiskFilter);
      }
      return out;
    },

    async refresh() {
      if (this.paused) return;
      try {
        const [logs, scopeData, scans] = await Promise.all([
          fetch('/api/logs?lines=50').then(r => r.ok ? r.json() : []),
          fetch('/api/scope').then(r => r.ok ? r.json() : { findings: [], stats: {} }),
          fetch('/api/scans').then(r => r.ok ? r.json() : []),
        ]);

        // Merge backend log lines (newer than what we have)
        const existing = new Set(this.logs.map(l => l.time + l.message));
        for (const line of logs) {
          const key = `[${line.time}]` + line.message;
          if (!existing.has(key)) {
            this.logs.push({ time: `[${line.time}]`, severity: line.severity, message: line.message });
          }
        }
        if (this.logs.length > 500) this.logs.splice(0, this.logs.length - 500);

        this.scope = scopeData.findings || [];

        // Update stats from current scan if running
        const latest = scans[0];
        if (latest) {
          this.latestScanId = latest.id;
          if (latest.status === 'running' || latest.status === 'queued') {
            this.running = true;
            this.stats.progress = Math.min(95, (this.stats.progress || 0) + 7);
          } else {
            this.running = false;
            this.stats.progress = 100;
          }
        }
        if (scopeData.stats) {
          this.stats.vulns = scopeData.stats.total_findings || 0;
          this.stats.exploits = scopeData.stats.exploitable || 0;
        }
        if (scopeData.recommendation) this.aiRecommendation = scopeData.recommendation;
      } catch (e) {
        // network errors silenced; the UI shows last known state
      }
    },

    renderGauges() {
      const colorFor = (cvss) => {
        if (cvss === null || cvss === undefined) return ['#475569', '#1e293b'];
        if (cvss >= 9) return ['#ef4444', '#1e293b'];
        if (cvss >= 7) return ['#f97316', '#1e293b'];
        if (cvss >= 4) return ['#eab308', '#1e293b'];
        return ['#3b82f6', '#1e293b'];
      };

      for (const card of this.scope) {
        const id = 'g_' + (card.cve_id + card.port).replace(/[^a-z0-9]/gi, '_');
        const el = document.getElementById(id);
        if (!el) continue;
        const value = card.cvss === null || card.cvss === undefined ? 0 : card.cvss;
        const [c1, c2] = colorFor(card.cvss);

        if (this._gauges[id]) {
          this._gauges[id].destroy();
        }
        this._gauges[id] = new Chart(el, {
          type: 'doughnut',
          data: {
            datasets: [{
              data: [value, 10 - value],
              backgroundColor: [c1, c2],
              borderWidth: 0,
              cutout: '72%',
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 600 },
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            rotation: -135,
            circumference: 270,
          },
        });
      }
    },
  };
}
