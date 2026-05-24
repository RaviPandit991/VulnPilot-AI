// Sessions tab - Alpine component.
// Drives the live msfrpcd sessions through /api/sessions/*.
function sessionsPage() {
  return {
    // -------- server-side state --------
    meta: { msf_enabled: false, error: '' },
    sessions: [],            // [{sid, type, target_host, ...}]
    quickActions: [],        // [{id, label, icon}]
    audit: [],               // recent ExploitRun rows where action starts with session_

    // -------- UI state --------
    selected: null,          // currently-selected session object
    auth: false,             // sticky authorization checkbox
    cmdInput: '',
    running: false,
    currentCmd: '',          // for spinner label
    scrollback: [],          // [{kind: 'cmd'|'out'|'err'|'sys', text}]
    history: [],             // command-history ring for arrow keys
    historyIdx: -1,          // -1 = not navigating
    killTarget: null,        // session being confirmed for kill
    loading: false,
    refreshHandle: null,
    lastAuditAt: '',

    // -------------------------------------------------- lifecycle
    async init() {
      await this.loadQuickActions();
      await this.refresh();
      // Restore stickier UI bits from sessionStorage
      try {
        const saved = sessionStorage.getItem('vulnpilot.sessions.auth');
        if (saved === '1') this.auth = true;
      } catch (_) {}
      this.refreshHandle = setInterval(() => this.refresh({silent: true}), 5000);
      this.$watch('auth', v => {
        try {
          sessionStorage.setItem('vulnpilot.sessions.auth', v ? '1' : '0');
        } catch (_) {}
      });
      this.$nextTick(() => window.lucide && window.lucide.createIcons());
    },

    destroy() {
      if (this.refreshHandle) clearInterval(this.refreshHandle);
    },

    // -------------------------------------------------- loaders
    async loadQuickActions() {
      try {
        this.quickActions = await fetch('/api/sessions/quick-actions')
          .then(r => r.ok ? r.json() : []);
      } catch (_) { this.quickActions = []; }
    },

    async refresh({silent} = {}) {
      if (!silent) this.loading = true;
      try {
        const resp = await fetch('/api/sessions');
        const data = await resp.json();
        if (!resp.ok) {
          this.meta = {msf_enabled: false, error: data.hint || data.error || 'unreachable'};
          this.sessions = [];
        } else {
          this.meta = {msf_enabled: !!data.msf_enabled, error: ''};
          this.sessions = data.sessions || [];
          // If the selected session disappeared, clear selection.
          if (this.selected && !this.sessions.find(s => s.sid === this.selected.sid)) {
            this.appendSys(`session #${this.selected.sid} no longer present`);
            this.selected = null;
          }
        }
      } catch (e) {
        this.meta = {msf_enabled: false, error: 'fetch error: ' + e};
        this.sessions = [];
      } finally {
        this.loading = false;
        this.refreshAudit();
        this.$nextTick(() => window.lucide && window.lucide.createIcons());
      }
    },

    async refreshAudit() {
      // Reuse the existing /api/exploit/runs endpoint and filter to
      // session_* actions (no separate audit endpoint needed).
      try {
        const all = await fetch('/api/exploit/runs?limit=80')
          .then(r => r.ok ? r.json() : []);
        this.audit = (all || []).filter(r =>
          (r.action || '').startsWith('session_'));
        const top = this.audit[0];
        this.lastAuditAt = top
          ? (top.created_at || '').slice(0, 19).replace('T', ' ')
          : '';
      } catch (_) {}
    },

    // -------------------------------------------------- selection
    select(s) {
      if (this.selected && this.selected.sid === s.sid) return;
      this.selected = s;
      this.scrollback = [];
      this.history = [];
      this.historyIdx = -1;
      this.appendSys(
        `connected to session #${s.sid} (${s.type}) on ` +
        `${s.target_host}:${s.target_port}`
      );
      this.$nextTick(() => window.lucide && window.lucide.createIcons());
    },

    // -------------------------------------------------- scrollback helpers
    appendCmd(text)  { this.scrollback.push({kind: 'cmd', text}); this.scrollDown(); },
    appendOut(text)  { this.scrollback.push({kind: 'out', text: text || '(no output)'}); this.scrollDown(); },
    appendErr(text)  { this.scrollback.push({kind: 'err', text}); this.scrollDown(); },
    appendSys(text)  { this.scrollback.push({kind: 'sys', text}); this.scrollDown(); },

    scrollDown() {
      this.$nextTick(() => {
        const el = this.$refs.scroll;
        if (el) el.scrollTop = el.scrollHeight;
      });
    },

    clearScrollback() {
      this.scrollback = [];
      if (this.selected) {
        this.appendSys(`cleared. still attached to session #${this.selected.sid}`);
      }
    },

    // -------------------------------------------------- command exec
    async submitCommand() {
      const cmd = (this.cmdInput || '').trim();
      if (!cmd || !this.selected || this.running) return;
      if (!this.auth) {
        this.appendErr('refusing - tick the authorization box at the top first');
        return;
      }
      this.history.unshift(cmd);
      if (this.history.length > 100) this.history.pop();
      this.historyIdx = -1;
      this.cmdInput = '';
      this.appendCmd(cmd);
      await this.execOnSelected(cmd);
    },

    async execOnSelected(cmd) {
      this.running = true;
      this.currentCmd = cmd.length > 30 ? cmd.slice(0, 30) + '...' : cmd;
      try {
        const resp = await fetch(`/api/sessions/${encodeURIComponent(this.selected.sid)}/exec`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            command: cmd,
            confirm_authorized: this.auth,
            timeout: 10,
          }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          this.appendErr(data.error || ('HTTP ' + resp.status));
        } else {
          if (data.output) this.appendOut(data.output);
          else this.appendSys('(empty output, ' + data.duration_seconds + 's)');
          if (data.error) this.appendErr(data.error);
        }
      } catch (e) {
        this.appendErr('network error: ' + e);
      } finally {
        this.running = false;
        this.currentCmd = '';
        this.refreshAudit();
      }
    },

    // -------------------------------------------------- quick actions
    async runQuick(actionId) {
      if (!this.selected || this.running) return;
      this.running = true;
      this.currentCmd = actionId;
      this.appendSys(`▶ quick action: ${actionId}`);
      try {
        const resp = await fetch(
          `/api/sessions/${encodeURIComponent(this.selected.sid)}/quick/${actionId}`,
          {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({timeout: 10}),
          }
        );
        const data = await resp.json();
        if (!resp.ok) {
          this.appendErr(data.error || ('HTTP ' + resp.status));
        } else {
          for (const r of (data.results || [])) {
            this.appendCmd(r.command);
            if (r.output) this.appendOut(r.output);
            if (r.error) this.appendErr(r.error);
          }
          this.appendSys(`◀ quick action complete (run #${data.run_id})`);
        }
      } catch (e) {
        this.appendErr('network error: ' + e);
      } finally {
        this.running = false;
        this.currentCmd = '';
        this.refreshAudit();
      }
    },

    // -------------------------------------------------- arrow-key history
    recallHistory(direction) {
      if (!this.history.length) return;
      // direction = -1 means up (older), +1 means down (newer)
      this.historyIdx = Math.max(-1,
        Math.min(this.history.length - 1, this.historyIdx + (direction === -1 ? 1 : -1)));
      this.cmdInput = this.historyIdx >= 0
        ? this.history[this.historyIdx]
        : '';
    },

    // -------------------------------------------------- kill flow
    confirmKill() {
      if (!this.selected || !this.auth) return;
      this.killTarget = this.selected;
      this.$nextTick(() => window.lucide && window.lucide.createIcons());
    },

    async doKill() {
      const target = this.killTarget;
      this.killTarget = null;
      if (!target) return;
      try {
        const resp = await fetch(`/api/sessions/${encodeURIComponent(target.sid)}/kill`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({confirm_authorized: this.auth}),
        });
        const data = await resp.json();
        if (!resp.ok) {
          this.appendErr('kill failed: ' + (data.error || resp.status));
        } else if (data.killed) {
          this.appendSys(`session #${target.sid} terminated`);
          this.selected = null;
        } else {
          this.appendErr(`session #${target.sid}: kill returned non-success`);
        }
      } catch (e) {
        this.appendErr('kill network error: ' + e);
      } finally {
        this.refresh({silent: true});
      }
    },

    // -------------------------------------------------- formatting
    formatOpened(epoch) {
      if (!epoch) return '—';
      const ms = epoch > 1e12 ? epoch : epoch * 1000;  // tolerate sec OR ms
      const diff = (Date.now() - ms) / 1000;
      if (diff < 60)   return Math.round(diff) + 's ago';
      if (diff < 3600) return Math.round(diff / 60) + 'm ago';
      if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
      return Math.round(diff / 86400) + 'd ago';
    },
  };
}
