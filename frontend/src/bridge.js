// Unified IPC Bridge: uses native Wails bindings (window.go.main.App) when inside the desktop window,
// and falls back transparently to REST + SSE (/api/*) when accessed in --web mode.

const hasWails = () => typeof window !== 'undefined' && window.go && window.go.main && window.go.main.App;

async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

export const backend = {
  async getModules() {
    if (hasWails()) return window.go.main.App.GetModules();
    return apiFetch('/api/modules');
  },

  async getSettings() {
    if (hasWails()) return window.go.main.App.GetSettings();
    return apiFetch('/api/settings');
  },

  async saveSettings(cfg) {
    if (hasWails()) return window.go.main.App.SaveSettings(cfg);
    return apiFetch('/api/settings', { method: 'POST', body: JSON.stringify(cfg) });
  },

  async startScan(req) {
    if (hasWails()) return window.go.main.App.StartScan(req);
    return apiFetch('/api/scans', { method: 'POST', body: JSON.stringify(req) });
  },

  async cancelScan(scanId) {
    if (hasWails()) return window.go.main.App.CancelScan(scanId || '');
    return apiFetch('/api/scans/cancel', { method: 'POST', body: JSON.stringify({ scanId: scanId || '' }) });
  },

  async getScan(scanId) {
    if (hasWails()) return window.go.main.App.GetScan(scanId);
    return apiFetch(`/api/scans?id=${encodeURIComponent(scanId)}`);
  },

  async listScans() {
    if (hasWails()) return window.go.main.App.ListScans();
    return apiFetch('/api/scans');
  },

  async deleteScan(scanId) {
    if (hasWails()) return window.go.main.App.DeleteScan(scanId);
    return apiFetch(`/api/scans?id=${encodeURIComponent(scanId)}`, { method: 'DELETE' });
  },

  async clearHistory() {
    if (hasWails()) return window.go.main.App.ClearHistory();
    return apiFetch('/api/scans?id=all', { method: 'DELETE' });
  },

  async listAuditLogs() {
    if (hasWails()) return window.go.main.App.ListAuditLogs();
    return apiFetch('/api/audit');
  },

  async getCVEDatasetMeta() {
    if (hasWails()) return window.go.main.App.GetCVEDatasetMeta();
    return apiFetch('/api/cve');
  },

  async refreshCVEDataset() {
    if (hasWails()) return window.go.main.App.RefreshCVEDataset();
    return apiFetch('/api/cve', { method: 'POST', body: JSON.stringify({ action: 'refresh' }) });
  },

  async importCVEDataset(rawJson) {
    if (hasWails()) return window.go.main.App.ImportCVEDataset(rawJson);
    return apiFetch('/api/cve', { method: 'POST', body: JSON.stringify({ action: 'import', rawJson }) });
  },

  async exportReport(scanId, format) {
    if (hasWails()) return window.go.main.App.ExportReport(scanId, format);
    return apiFetch(`/api/export?scanId=${encodeURIComponent(scanId)}&format=${encodeURIComponent(format)}`);
  },

  async startSandboxTarget() {
    if (hasWails()) return window.go.main.App.StartSandboxTarget();
    const data = await apiFetch('/api/sandbox', { method: 'POST' });
    return data.url;
  },

  subscribeProgress(callback) {
    if (typeof window !== 'undefined' && window.runtime && window.runtime.EventsOn) {
      const off = window.runtime.EventsOn('scan:progress', (ev) => {
        callback(ev);
      });
      return () => {
        if (typeof off === 'function') off();
      };
    }

    // Fallback to Server-Sent Events in --web mode
    if (typeof EventSource !== 'undefined') {
      const es = new EventSource('/api/events');
      es.onmessage = (e) => {
        try {
          const parsed = JSON.parse(e.data);
          callback(parsed);
        } catch (_) {}
      };
      return () => es.close();
    }
    return () => {};
  },
};
