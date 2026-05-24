// Nuclei tab - Alpine component.
// Drives the local `nuclei` CLI through /api/nuclei/*.
function nucleiPage() {
  return {
    // -------- server-side state --------
    status: { installed: false, version: '', template_count: 0, message: '' },
    presets: [],            // [{id, label, icon, description, include}]
    history: [],            // recent ExploitRun rows for nuclei runs

    // -------- form / UI state --------
    allSeverities: ['critical', 'high', 'medium', 'low', 'info'],
    form: {
      target: '',
      operator: 'web-user',
      authorization_ref: 'lab-engagement',
      confirm_authorized: false,
      presets: ['cves'],         // start with the highest-signal preset
      severities: ['critical', 'high'],
    },
    running: false,
    lastRun: null,             // {run_id, target, presets, severities,
                               //  duration_seconds, return_code, findings,
                               //  severity_counts, stderr_excerpt, error}
    refreshHandle: null,

    // -------------------------------------------------- lifecycle
    async init() {
      await Promise.all([this.loadStatus(), this.loadPresets(), this.refreshHistory()]);
      // Auto-fill target from latest scan if blank.
      if (!this.form.target) {
        try {
          const data = await fetch('/api/exploit/catalog')
            .then(r => r.ok ? r.json() : null);
          if (data && data.scan && data.scan.target) {
            this.form.target = data.scan.target;
          }
        } catch (_) { /* ignore */ }
      }
      // Poll history every 6s (cheap)
      this.refreshHandle = setInterval(() => this.refreshHistory(), 6000);
      this.$nextTick(() => window.lucide && window.lucide.createIcons());
    },

    destroy() {
      if (this.refreshHandle) clearInterval(this.refreshHandle);
    },

    // -------------------------------------------------- loaders
    async loadStatus() {
      try {
        this.status = await fetch('/api/nuclei/status')
          .then(r => r.ok ? r.json() : {installed: false, message: 'fetch failed'});
      } catch (e) {
        this.status = { installed: false, message: 'fetch error: ' + e };
      }
    },

    async loadPresets() {
      try {
        this.presets = await fetch('/api/nuclei/presets')
          .then(r => r.ok ? r.json() : []);
      } catch (_) { this.presets = []; }
    },

    async refreshHistory() {
      try {
        this.history = await fetch('/api/nuclei/runs?limit=30')
          .then(r => r.ok ? r.json() : []);
      } catch (_) { /* silent */ }
    },

    // -------------------------------------------------- preset / severity
    togglePreset(id) {
      const i = this.form.presets.indexOf(id);
      if (i >= 0) this.form.presets.splice(i, 1);
      else this.form.presets.push(id);
    },

    toggleSeverity(sev) {
      const i = this.form.severities.indexOf(sev);
      if (i >= 0) this.form.severities.splice(i, 1);
      else this.form.severities.push(sev);
    },

    // -------------------------------------------------- run guards
    canRun() {
      if (this.running) return false;
      if (!this.status.installed) return false;
      if (!this.form.confirm_authorized) return false;
      if (!this.form.target.trim()) return false;
      if (!this.form.presets.length) return false;
      if (!this.form.severities.length) return false;
      return true;
    },

    blockReason() {
      if (!this.status.installed) return 'install nuclei first';
      if (!this.form.target.trim()) return 'enter a target';
      if (!this.form.confirm_authorized) return 'tick the authorization box';
      if (!this.form.presets.length) return 'pick at least one preset';
      if (!this.form.severities.length) return 'pick at least one severity';
      return '';
    },

    // -------------------------------------------------- the actual run
    async runScan() {
      if (!this.canRun()) return;
      this.running = true;
      this.lastRun = null;

      const body = {
        target: this.form.target.trim(),
        presets: [...this.form.presets],
        severities: [...this.form.severities],
        confirm_authorized: !!this.form.confirm_authorized,
        operator: this.form.operator || 'web-user',
        authorization_ref: this.form.authorization_ref || '',
      };

      try {
        const resp = await fetch('/api/nuclei/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const data = await resp.json();
        if (!resp.ok) {
          this.lastRun = {
            run_id: '—', target: body.target,
            presets: body.presets, severities: body.severities,
            duration_seconds: 0, return_code: -1, findings: [],
            severity_counts: {}, stderr_excerpt: '',
            error: data.error || ('HTTP ' + resp.status),
          };
        } else {
          this.lastRun = data;
        }
      } catch (e) {
        this.lastRun = {
          run_id: '—', target: body.target,
          presets: body.presets, severities: body.severities,
          duration_seconds: 0, return_code: -1, findings: [],
          severity_counts: {}, stderr_excerpt: '',
          error: 'network error: ' + e,
        };
      } finally {
        this.running = false;
        this.refreshHistory();
        this.$nextTick(() => window.lucide && window.lucide.createIcons());
      }
    },

    // -------------------------------------------------- history viewer
    async loadRun(runId) {
      try {
        const data = await fetch('/api/nuclei/runs/' + runId)
          .then(r => r.ok ? r.json() : null);
        if (!data) return;
        // History endpoint returns the audit summary, not the full
        // structured findings - so we render it as a single read-only
        // "previous run" card with the text result.
        this.lastRun = {
          run_id: data.id,
          target: '(historical run)',
          presets: [], severities: [],
          duration_seconds: 0, return_code: 0,
          findings: [],
          severity_counts: {},
          stderr_excerpt: data.result || '',
          error: '',
          historical: true,
        };
        this.$nextTick(() => window.lucide && window.lucide.createIcons());
      } catch (e) {
        console.error('loadRun failed', e);
      }
    },

    // -------------------------------------------------- styling helpers
    severitySev(sev) {
      // Map nuclei severity names -> existing sev-* CSS classes.
      switch ((sev || '').toLowerCase()) {
        case 'critical': return 'critical';
        case 'high':     return 'high';
        case 'medium':   return 'medium';
        case 'low':      return 'low';
        case 'info':     return 'info';
        default:         return 'info';
      }
    },
  };
}
