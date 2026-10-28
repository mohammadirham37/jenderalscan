import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  Search,
  Play,
  Square,
  History,
  Settings,
  FileText,
  Check,
  Copy,
  ExternalLink,
  Trash2,
  RefreshCw,
  Lock,
  Activity,
  FileSpreadsheet,
} from 'lucide-react';
import { backend } from './bridge';
import { translations } from './i18n';

const SEVERITY_META = {
  High: {
    color: 'var(--sev-high)',
    bg: 'var(--sev-high-bg)',
    label: 'High',
  },
  Medium: {
    color: 'var(--sev-medium)',
    bg: 'var(--sev-medium-bg)',
    label: 'Medium',
  },
  Low: {
    color: 'var(--sev-low)',
    bg: 'var(--sev-low-bg)',
    label: 'Low',
  },
  Info: {
    color: 'var(--sev-info)',
    bg: 'var(--sev-info-bg)',
    label: 'Info',
  },
};

export default function App() {
  const [activeTab, setActiveTab] = useState('new'); // 'new' | 'progress' | 'results' | 'history' | 'audit' | 'settings'
  const [modules, setModules] = useState([]);
  const [settings, setSettings] = useState({
    maxWorkers: 5,
    rateLimitRps: 10,
    timeoutSeconds: 10,
    maxRetries: 1,
    userAgent: 'JenderalScan/1.0 (+https://jenderalscan.local; Non-Intrusive Security Audit)',
    customHeaders: {},
    proxyUrl: '',
    verifyTls: false,
    strictScopeLock: true,
    language: 'id',
    theme: 'dark',
  });

  // Scan setup state
  const [targetUrl, setTargetUrl] = useState('');
  const [profile, setProfile] = useState('Quick');
  const [selectedModules, setSelectedModules] = useState([
    'headers',
    'tls',
    'cookies',
    'paths',
    'fingerprint',
    'cve',
  ]);
  const [authorizedConfirm, setAuthorizedConfirm] = useState(false);
  const [authorizationNote, setAuthorizationNote] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  // Live progress & active report state
  const [progress, setProgress] = useState(null);
  const [activeResult, setActiveResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [resultsSubtab, setResultsSubtab] = useState('findings'); // 'findings' | 'tech' | 'fixed'

  // Filters on report screen
  const [searchQuery, setSearchQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [modFilter, setModFilter] = useState('ALL');
  const [diffFilter, setDiffFilter] = useState('ALL');
  const [copiedId, setCopiedId] = useState('');

  // History, Audit & CVE state
  const [historyList, setHistoryList] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [customHeadersText, setCustomHeadersText] = useState('{}');
  const [cveMeta, setCveMeta] = useState(null);
  const [cveImportJson, setCveImportJson] = useState('');
  const [toast, setToast] = useState(null);

  const lang = settings.language === 'en' ? 'en' : 'id';
  const t = translations[lang];
  const isEN = lang === 'en';

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => {
      setToast((prev) => (prev === msg ? null : prev));
    }, 4500);
  };

  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === 'light') {
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
    }
  }, [settings.theme]);

  useEffect(() => {
    async function init() {
      try {
        const [mods, cfg, scans, logs, cve] = await Promise.all([
          backend.getModules(),
          backend.getSettings(),
          backend.listScans(),
          backend.listAuditLogs(),
          backend.getCVEDatasetMeta(),
        ]);
        if (Array.isArray(mods)) setModules(mods);
        if (cfg) {
          setSettings(cfg);
          setCustomHeadersText(JSON.stringify(cfg.customHeaders || {}, null, 2));
        }
        if (Array.isArray(scans)) {
          setHistoryList(scans);
          if (scans.length > 0 && !activeResult) {
            const firstFull = await backend.getScan(scans[0].id);
            if (firstFull) {
              setActiveResult(firstFull);
              if (firstFull.findings && firstFull.findings.length > 0) {
                setSelectedFinding(firstFull.findings[0]);
              }
            }
          }
        }
        if (Array.isArray(logs)) setAuditLogs(logs);
        if (cve) setCveMeta(cve);
      } catch (err) {
        console.error('Initialization error:', err);
      }
    }
    init();

    const unsubscribe = backend.subscribeProgress((ev) => {
      setProgress(ev);
    });
    return () => unsubscribe();
  }, []);

  const handleProfileChange = (newProfile) => {
    setProfile(newProfile);
    if (newProfile === 'Quick') {
      setSelectedModules(['headers', 'tls', 'cookies', 'paths', 'fingerprint', 'cve']);
    } else if (newProfile === 'Full') {
      setSelectedModules([
        'headers',
        'tls',
        'cookies',
        'paths',
        'fingerprint',
        'cve',
        'cors',
        'disclosure',
        'dns',
        'ports',
      ]);
    }
  };

  const toggleModuleInCustom = (modId) => {
    setProfile('Custom');
    setSelectedModules((prev) =>
      prev.includes(modId) ? prev.filter((x) => x !== modId) : [...prev, modId]
    );
  };

  const handleSetLanguage = async (nextLang) => {
    const nextCfg = { ...settings, language: nextLang };
    setSettings(nextCfg);
    try {
      await backend.saveSettings(nextCfg);
    } catch (_) {}
  };

  const handleSetTheme = async (nextTheme) => {
    const nextCfg = { ...settings, theme: nextTheme };
    setSettings(nextCfg);
    try {
      await backend.saveSettings(nextCfg);
    } catch (_) {}
  };

  const handleUseSandbox = async () => {
    try {
      const url = await backend.startSandboxTarget();
      setTargetUrl(url);
      setAuthorizedConfirm(true);
      setAuthorizationNote('Local Educational Sandbox (127.0.0.1)');
      showToast(`${t.sandboxReadyMsg} ${url}`);
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleStartScan = async (e) => {
    if (e) e.preventDefault();
    if (!authorizedConfirm || !targetUrl.trim() || isScanning) return;

    setIsScanning(true);
    setProgress({
      scanId: 'starting',
      targetUrl: targetUrl.trim(),
      status: 'running',
      progressPct: 0,
      elapsedMs: 0,
      requestsSent: 0,
      moduleStatuses: selectedModules.map((m) => ({
        module: m,
        name: m,
        status: 'waiting',
        findings: 0,
      })),
      summary: { high: 0, medium: 0, low: 0, info: 0, total: 0 },
    });
    setActiveTab('progress');

    try {
      const result = await backend.startScan({
        targetUrl: targetUrl.trim(),
        profile,
        modules: selectedModules,
        authorizedConfirm,
        authorizationNote,
      });

      setActiveResult(result);
      if (result && result.findings && result.findings.length > 0) {
        setSelectedFinding(result.findings[0]);
      } else {
        setSelectedFinding(null);
      }
      setResultsSubtab('findings');
      setActiveTab('results');

      const [scans, logs] = await Promise.all([backend.listScans(), backend.listAuditLogs()]);
      if (Array.isArray(scans)) setHistoryList(scans);
      if (Array.isArray(logs)) setAuditLogs(logs);
    } catch (err) {
      showToast(err.message || String(err));
      setActiveTab('new');
    } finally {
      setIsScanning(false);
    }
  };

  const handleCancelScan = async () => {
    try {
      await backend.cancelScan(progress?.scanId || '');
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleOpenHistoryScan = async (scanId) => {
    try {
      const fullScan = await backend.getScan(scanId);
      setActiveResult(fullScan);
      if (fullScan.findings && fullScan.findings.length > 0) {
        setSelectedFinding(fullScan.findings[0]);
      } else {
        setSelectedFinding(null);
      }
      setResultsSubtab('findings');
      setActiveTab('results');
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await backend.deleteScan(scanId);
      const scans = await backend.listScans();
      setHistoryList(scans || []);
      if (activeResult && activeResult.id === scanId) {
        setActiveResult(null);
        setSelectedFinding(null);
      }
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleClearHistory = async () => {
    try {
      await backend.clearHistory();
      setHistoryList([]);
      setActiveResult(null);
      setSelectedFinding(null);
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleExport = async (format) => {
    if (!activeResult) return;
    try {
      const payload = await backend.exportReport(activeResult.id, format);
      const byteCharacters = atob(payload.contentBase64);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: payload.mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = payload.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast(`${t.exportSavedPrefix} ${payload.savedPath || payload.filename}`);
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    try {
      let parsedHeaders = {};
      if (customHeadersText.trim()) {
        parsedHeaders = JSON.parse(customHeadersText);
      }
      const updated = await backend.saveSettings({
        ...settings,
        customHeaders: parsedHeaders,
      });
      setSettings(updated);
      showToast(t.settingsSavedMsg);
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleRefreshCVE = async () => {
    try {
      const meta = await backend.refreshCVEDataset();
      setCveMeta(meta);
      showToast(isEN ? 'CVE database refreshed.' : 'Basis data CVE disegarkan.');
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const handleImportCVE = async () => {
    if (!cveImportJson.trim()) return;
    try {
      const meta = await backend.importCVEDataset(cveImportJson);
      setCveMeta(meta);
      setCveImportJson('');
      showToast(isEN ? 'CVE definitions imported.' : 'Definisi CVE diimpor.');
    } catch (err) {
      showToast(err.message || String(err));
    }
  };

  const filteredFindings = useMemo(() => {
    if (!activeResult || !Array.isArray(activeResult.findings)) return [];
    return activeResult.findings.filter((f) => {
      if (sevFilter !== 'ALL' && f.severity !== sevFilter) return false;
      if (modFilter !== 'ALL' && f.module !== modFilter) return false;
      if (diffFilter !== 'ALL' && f.diffStatus !== diffFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const title = (isEN && f.titleEn ? f.titleEn : f.title || '').toLowerCase();
        const desc = (isEN && f.descriptionEn ? f.descriptionEn : f.description || '').toLowerCase();
        const rule = (f.ruleId || '').toLowerCase();
        const cwe = (f.cwe || '').toLowerCase();
        if (!title.includes(q) && !desc.includes(q) && !rule.includes(q) && !cwe.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [activeResult, sevFilter, modFilter, diffFilter, searchQuery, isEN]);

  const copyEvidenceText = (finding) => {
    if (!finding?.evidence) return;
    navigator.clipboard.writeText(finding.evidence);
    setCopiedId(finding.id);
    setTimeout(() => setCopiedId(''), 2000);
  };

  const navItems = [
    { id: 'new', label: t.navNewScan, icon: Play },
    {
      id: 'progress',
      label: t.navProgress,
      icon: Activity,
      badge: isScanning ? `${progress?.progressPct || 0}%` : null,
    },
    {
      id: 'results',
      label: t.navResults,
      icon: FileText,
      count: activeResult?.summary?.total,
    },
    {
      id: 'history',
      label: t.navHistory,
      icon: History,
      count: historyList.length || null,
    },
    {
      id: 'audit',
      label: t.navAudit,
      icon: FileSpreadsheet,
      count: auditLogs.length || null,
    },
    { id: 'settings', label: t.navSettings, icon: Settings },
  ];

  return (
    <div className="h-screen w-screen overflow-hidden flex select-none">
      {/* Persistent Left Instrument Rail */}
      <aside className="w-56 shrink-0 h-full workbench-surface border-r flex flex-col justify-between">
        <div>
          {/* Application Identity */}
          <div className="px-4 py-4 border-b" style={{ borderColor: 'var(--border-hairline)' }}>
            <div className="flex items-center gap-2.5">
              <div
                className="w-1.5 h-5 rounded-sm"
                style={{ backgroundColor: 'var(--accent-primary)' }}
              />
              <span className="font-bold text-[15px] tracking-tight">JenderalScan</span>
              <span
                className="text-[11px] font-mono px-1.5 py-0.5 rounded"
                style={{
                  backgroundColor: 'var(--bg-raised)',
                  color: 'var(--text-secondary)',
                }}
              >
                1.0
              </span>
            </div>
            <p className="text-[11.5px] mt-1 leading-snug" style={{ color: 'var(--text-muted)' }}>
              {t.appSubtitle}
            </p>
          </div>

          {/* Primary Navigation */}
          <nav className="py-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className="w-full px-4 py-2.5 flex items-center justify-between text-left text-[13px] transition-colors relative"
                  style={{
                    backgroundColor: active ? 'var(--bg-raised)' : 'transparent',
                    color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                    fontWeight: active ? 600 : 500,
                  }}
                >
                  {active && (
                    <span
                      className="absolute left-0 top-0 bottom-0 w-[3px]"
                      style={{ backgroundColor: 'var(--accent-primary)' }}
                    />
                  )}
                  <span className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </span>
                  {item.badge ? (
                    <span
                      className="text-[11px] font-mono tabular-nums px-1.5 py-0.5 rounded"
                      style={{
                        backgroundColor: 'var(--accent-Tint)',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      {item.badge}
                    </span>
                  ) : item.count !== undefined && item.count !== null ? (
                    <span
                      className="text-[11.5px] font-mono tabular-nums"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      {item.count}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Guardrail Telemetry & Environment Controls */}
        <div
          className="p-3.5 border-t space-y-3 text-[12px]"
          style={{ borderColor: 'var(--border-hairline)' }}
        >
          <div className="space-y-1.5" style={{ color: 'var(--text-secondary)' }}>
            <div className="flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--sev-fixed)' }} />
              <span>{t.guardrailScopeLock}</span>
            </div>
            <div className="flex items-center justify-between tabular-nums">
              <span style={{ color: 'var(--text-muted)' }}>{t.guardrailRateLimit}</span>
              <span className="font-mono">{settings.rateLimitRps} req/s</span>
            </div>
          </div>

          {/* Segmented Language & Appearance Toggles */}
          <div className="grid grid-cols-2 gap-1.5 pt-1">
            <div
              className="grid grid-cols-2 p-0.5 rounded border"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                borderColor: 'var(--border-hairline)',
              }}
            >
              {['id', 'en'].map((code) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => handleSetLanguage(code)}
                  className="py-1 text-[11px] font-semibold rounded-sm transition-colors"
                  style={{
                    backgroundColor:
                      settings.language === code ? 'var(--bg-surface)' : 'transparent',
                    color:
                      settings.language === code ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  {code === 'id' ? 'ID' : 'EN'}
                </button>
              ))}
            </div>

            <div
              className="grid grid-cols-2 p-0.5 rounded border"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                borderColor: 'var(--border-hairline)',
              }}
            >
              {[
                { id: 'dark', label: isEN ? 'Dark' : 'Gelap' },
                { id: 'light', label: isEN ? 'Light' : 'Terang' },
              ].map((mode) => (
                <button
                  key={mode.id}
                  type="button"
                  onClick={() => handleSetTheme(mode.id)}
                  className="py-1 text-[11px] font-semibold rounded-sm transition-colors"
                  style={{
                    backgroundColor:
                      settings.theme === mode.id ? 'var(--bg-surface)' : 'transparent',
                    color:
                      settings.theme === mode.id ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  {mode.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </aside>

      {/* Main Inspection Workspace */}
      <div className="flex-1 h-full flex flex-col overflow-hidden">
        {/* Toast Status Bar */}
        {toast && (
          <div
            className="fixed bottom-4 right-5 z-50 px-4 py-2.5 rounded border shadow-md flex items-center gap-2.5 text-[12.5px]"
            style={{
              backgroundColor: 'var(--bg-surface)',
              borderColor: 'var(--border-strong)',
              color: 'var(--text-primary)',
            }}
          >
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: 'var(--sev-fixed)' }}
            />
            <span className="select-text">{toast}</span>
          </div>
        )}

        {/* VIEW 1: NEW SCAN WORKBENCH */}
        {activeTab === 'new' && (
          <div className="flex-1 overflow-y-auto p-6">
            <form onSubmit={handleStartScan} className="max-w-5xl mx-auto space-y-6">
              {/* Focal Centerpiece: Target Command Bar */}
              <section className="workbench-surface border rounded p-5 space-y-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div>
                    <h1 className="text-[17px] font-bold tracking-tight">{t.targetHeading}</h1>
                    <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                      {t.targetDesc}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleUseSandbox}
                    className="btn-secondary px-3 py-1.5 text-[12px]"
                  >
                    {t.useSandboxBtn}
                  </button>
                </div>

                <div className="flex gap-2.5">
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder={t.targetPlaceholder}
                    className="workbench-input flex-1 px-3.5 py-2.5 font-mono text-[13.5px]"
                    required
                  />
                  <button
                    type="submit"
                    disabled={
                      !authorizedConfirm ||
                      !targetUrl.trim() ||
                      selectedModules.length === 0 ||
                      isScanning
                    }
                    className="btn-primary px-5 py-2.5 text-[13px] shrink-0"
                  >
                    {isScanning ? t.startingScanBtn : t.startScanBtn}
                  </button>
                </div>
              </section>

              {/* Two-Column Inspection Configuration */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                {/* Left Column: Profile Selector & Legal Authorization */}
                <div className="lg:col-span-5 space-y-5">
                  <section className="workbench-surface border rounded p-5 space-y-3">
                    <h2 className="text-[14.5px] font-bold">{t.profileHeading}</h2>
                    <div className="space-y-2">
                      {[
                        {
                          id: 'Quick',
                          title: t.profileQuickTitle,
                          desc: t.profileQuickDesc,
                        },
                        {
                          id: 'Full',
                          title: t.profileFullTitle,
                          desc: t.profileFullDesc,
                        },
                        {
                          id: 'Custom',
                          title: t.profileCustomTitle,
                          desc: t.profileCustomDesc,
                        },
                      ].map((p) => {
                        const active = profile === p.id;
                        return (
                          <div
                            key={p.id}
                            onClick={() => handleProfileChange(p.id)}
                            className="cursor-pointer rounded border p-3 transition-colors"
                            style={{
                              backgroundColor: active ? 'var(--accent-Tint)' : 'var(--bg-canvas)',
                              borderColor: active
                                ? 'var(--accent-primary)'
                                : 'var(--border-hairline)',
                            }}
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-[13px]">{p.title}</span>
                              <input
                                type="radio"
                                checked={active}
                                onChange={() => {}}
                                className="accent-blue-600"
                              />
                            </div>
                            <p
                              className="text-[12px] mt-1 leading-relaxed"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {p.desc}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  </section>

                  {/* Mandatory Legal Authorization Box */}
                  <section className="workbench-surface border rounded p-5 space-y-3.5">
                    <h2 className="text-[14.5px] font-bold">{t.authHeading}</h2>

                    <div>
                      <label
                        className="block text-[12px] font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        {t.authNoteLabel}
                      </label>
                      <input
                        type="text"
                        value={authorizationNote}
                        onChange={(e) => setAuthorizationNote(e.target.value)}
                        placeholder={t.authNotePlaceholder}
                        className="workbench-input w-full px-3 py-2 text-[12.5px]"
                      />
                    </div>

                    <label
                      className="flex items-start gap-2.5 p-3 rounded border cursor-pointer"
                      style={{
                        backgroundColor: 'var(--bg-canvas)',
                        borderColor: authorizedConfirm
                          ? 'var(--accent-primary)'
                          : 'var(--border-hairline)',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={authorizedConfirm}
                        onChange={(e) => setAuthorizedConfirm(e.target.checked)}
                        className="mt-0.5 accent-blue-600"
                      />
                      <span className="text-[12.5px] leading-relaxed">{t.authCheckboxLabel}</span>
                    </label>

                    <div
                      className="pt-2 border-t text-[11.5px] leading-relaxed"
                      style={{
                        borderColor: 'var(--border-hairline)',
                        color: 'var(--text-muted)',
                      }}
                    >
                      <strong style={{ color: 'var(--text-secondary)' }}>
                        {t.legalNoticeTitle}:
                      </strong>{' '}
                      {t.legalNoticeText}
                    </div>
                  </section>
                </div>

                {/* Right Column: 10-Module Matrix Table */}
                <section className="lg:col-span-7 workbench-surface border rounded overflow-hidden">
                  <div
                    className="px-4 py-3 border-b flex items-center justify-between"
                    style={{ borderColor: 'var(--border-hairline)' }}
                  >
                    <h2 className="text-[14.5px] font-bold">
                      {isEN ? 'Inspection modules' : 'Daftar modul pemeriksaan'}
                    </h2>
                    <span
                      className="text-[12px] font-mono tabular-nums"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {selectedModules.length} / {modules.length}
                    </span>
                  </div>

                  <div
                    className="divide-y"
                    style={{ borderColor: 'var(--border-hairline)' }}
                  >
                    {modules.map((m) => {
                      const checked = selectedModules.includes(m.id);
                      return (
                        <div
                          key={m.id}
                          onClick={() => toggleModuleInCustom(m.id)}
                          className="px-4 py-2.5 flex items-start gap-3 cursor-pointer transition-colors"
                          style={{
                            backgroundColor: checked ? 'transparent' : 'var(--bg-subtle)',
                            opacity: checked ? 1 : 0.6,
                            borderColor: 'var(--border-hairline)',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => {}}
                            className="mt-1 accent-blue-600"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-semibold text-[13px]">
                                {isEN ? m.nameEn : m.name}
                              </span>
                              <div className="flex items-center gap-2 shrink-0 text-[11px] font-mono">
                                <span style={{ color: 'var(--text-muted)' }}>
                                  {m.typicalSeverity}
                                </span>
                                <span
                                  className="px-1.5 py-0.2 rounded"
                                  style={{
                                    backgroundColor: 'var(--bg-raised)',
                                    color: 'var(--text-secondary)',
                                  }}
                                >
                                  {m.phase}
                                </span>
                              </div>
                            </div>
                            <p
                              className="text-[12px] mt-0.5 leading-snug"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {isEN ? m.descriptionEn : m.description}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </section>
              </div>
            </form>
          </div>
        )}

        {/* VIEW 2: LIVE EXECUTION TELEMETRY */}
        {activeTab === 'progress' && (
          <div className="flex-1 overflow-y-auto p-6">
            <div className="max-w-4xl mx-auto space-y-5">
              {!progress ? (
                <div className="workbench-surface border rounded p-10 text-center space-y-3">
                  <p className="font-semibold text-[14px]">{t.noActiveResultTitle}</p>
                  <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                    {t.noActiveResultDesc}
                  </p>
                  <button
                    onClick={() => setActiveTab('new')}
                    className="btn-primary px-4 py-2 text-[12.5px]"
                  >
                    {t.navNewScan}
                  </button>
                </div>
              ) : (
                <>
                  <div className="workbench-surface border rounded p-5 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div>
                        <h1 className="text-[16px] font-bold">{t.progressTitle}</h1>
                        <p
                          className="font-mono text-[12.5px] mt-0.5"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {progress.targetUrl}
                        </p>
                      </div>

                      <div className="flex items-center gap-3">
                        <div
                          className="text-[12px] font-mono tabular-nums"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {((progress.elapsedMs || 0) / 1000).toFixed(1)}s |{' '}
                          {progress.requestsSent || 0} req
                        </div>
                        {isScanning ? (
                          <button
                            onClick={handleCancelScan}
                            className="btn-secondary px-3.5 py-1.5 text-[12px] flex items-center gap-1.5"
                            style={{ color: 'var(--sev-high)' }}
                          >
                            <Square className="w-3 h-3 fill-current" />
                            <span>{t.cancelScanBtn}</span>
                          </button>
                        ) : (
                          activeResult && (
                            <button
                              onClick={() => setActiveTab('results')}
                              className="btn-primary px-4 py-1.5 text-[12.5px]"
                            >
                              {t.openResultsBtn}
                            </button>
                          )
                        )}
                      </div>
                    </div>

                    {/* Linear Progress Meter */}
                    <div
                      className="w-full h-2 rounded-sm overflow-hidden"
                      style={{ backgroundColor: 'var(--bg-raised)' }}
                    >
                      <div
                        className="h-full transition-all duration-200"
                        style={{
                          width: `${progress.progressPct || 0}%`,
                          backgroundColor: 'var(--accent-primary)',
                        }}
                      />
                    </div>
                  </div>

                  {/* Tabular Module Status List */}
                  <div className="workbench-surface border rounded overflow-hidden">
                    <table className="w-full text-left border-collapse text-[13px]">
                      <thead>
                        <tr
                          className="border-b text-[12px]"
                          style={{
                            backgroundColor: 'var(--bg-subtle)',
                            borderColor: 'var(--border-hairline)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          <th className="py-2.5 px-4 font-semibold">Modul</th>
                          <th className="py-2.5 px-4 font-semibold">Status</th>
                          <th className="py-2.5 px-4 font-semibold text-right">Temuan</th>
                          <th className="py-2.5 px-4 font-semibold text-right">Durasi</th>
                        </tr>
                      </thead>
                      <tbody
                        className="divide-y tabular-nums"
                        style={{ borderColor: 'var(--border-hairline)' }}
                      >
                        {(progress.moduleStatuses || []).map((ms) => (
                          <tr
                            key={ms.module}
                            style={{ borderColor: 'var(--border-hairline)' }}
                          >
                            <td className="py-2.5 px-4 font-mono font-medium">{ms.module}</td>
                            <td className="py-2.5 px-4">
                              <span
                                className="inline-flex items-center gap-1.5 text-[12px] font-medium"
                                style={{
                                  color:
                                    ms.status === 'completed'
                                      ? 'var(--sev-fixed)'
                                      : ms.status === 'running'
                                      ? 'var(--accent-primary)'
                                      : ms.status === 'failed'
                                      ? 'var(--sev-high)'
                                      : 'var(--text-muted)',
                                }}
                              >
                                <span
                                  className="w-1.5 h-1.5 rounded-full"
                                  style={{
                                    backgroundColor:
                                      ms.status === 'completed'
                                        ? 'var(--sev-fixed)'
                                        : ms.status === 'running'
                                        ? 'var(--accent-primary)'
                                        : ms.status === 'failed'
                                        ? 'var(--sev-high)'
                                        : 'var(--text-muted)',
                                  }}
                                />
                                {ms.status}
                              </span>
                            </td>
                            <td className="py-2.5 px-4 text-right font-mono">
                              {ms.findings || 0}
                            </td>
                            <td
                              className="py-2.5 px-4 text-right font-mono"
                              style={{ color: 'var(--text-muted)' }}
                            >
                              {ms.durationMs ? `${ms.durationMs} ms` : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* VIEW 3: AUDIT REPORT & SPLIT INSPECTION DOSSIER */}
        {activeTab === 'results' && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {!activeResult ? (
              <div className="p-8">
                <div className="max-w-xl mx-auto workbench-surface border rounded p-10 text-center space-y-3">
                  <p className="font-semibold text-[14.5px]">{t.noActiveResultTitle}</p>
                  <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                    {t.noActiveResultDesc}
                  </p>
                  <button
                    onClick={() => setActiveTab('new')}
                    className="btn-primary px-4 py-2 text-[12.5px]"
                  >
                    {t.navNewScan}
                  </button>
                </div>
              </div>
            ) : (
              <>
                {/* Report Header & Export Bar */}
                <div
                  className="workbench-surface border-b px-6 py-3.5 flex flex-wrap items-center justify-between gap-4 shrink-0"
                  style={{ borderColor: 'var(--border-hairline)' }}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-3">
                      <h1 className="font-mono font-bold text-[15px] truncate select-text">
                        {activeResult.targetUrl}
                      </h1>
                      <span
                        className="text-[11.5px] px-2 py-0.5 rounded border font-medium"
                        style={{
                          backgroundColor: 'var(--bg-raised)',
                          borderColor: 'var(--border-hairline)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {activeResult.profile}
                      </span>
                    </div>
                    <div
                      className="text-[12px] mt-0.5 flex flex-wrap items-center gap-4 tabular-nums"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <span>Host: {activeResult.normalizedHost}</span>
                      <span>{new Date(activeResult.startedAt).toLocaleString()}</span>
                      <span>
                        {(activeResult.durationMs / 1000).toFixed(2)}s ({activeResult.requestsSent}{' '}
                        req)
                      </span>
                      {activeResult.diff && activeResult.diff.previousScanId && (
                        <span style={{ color: 'var(--text-secondary)' }}>
                          Diff: +{activeResult.diff.newCount} {t.diffNew}, -
                          {activeResult.diff.fixedCount} {t.diffFixed}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Grouped Export Toolbar: JSON | Markdown (.md) | HTML | PDF */}
                  <div className="flex items-center gap-1.5">
                    <span
                      className="text-[12px] mr-1.5"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      {isEN ? 'Export:' : 'Ekspor:'}
                    </span>
                    <button
                      onClick={() => handleExport('json')}
                      className="btn-secondary px-2.5 py-1.5 text-[12px] font-mono"
                    >
                      {t.exportJSON}
                    </button>
                    <button
                      onClick={() => handleExport('md')}
                      className="btn-secondary px-2.5 py-1.5 text-[12px] font-mono"
                    >
                      {t.exportMD}
                    </button>
                    <button
                      onClick={() => handleExport('html')}
                      className="btn-secondary px-2.5 py-1.5 text-[12px] font-mono"
                    >
                      {t.exportHTML}
                    </button>
                    <button
                      onClick={() => handleExport('pdf')}
                      className="btn-primary px-3 py-1.5 text-[12px]"
                    >
                      {t.exportPDF}
                    </button>
                  </div>
                </div>

                {/* Proportional Severity Strip & Sub-navigation */}
                <div
                  className="workbench-subtle border-b px-6 py-2.5 flex flex-wrap items-center justify-between gap-4 shrink-0"
                  style={{ borderColor: 'var(--border-hairline)' }}
                >
                  {/* Clickable Severity Filter Cells */}
                  <div className="flex items-center gap-2 tabular-nums">
                    <button
                      onClick={() => {
                        setResultsSubtab('findings');
                        setSevFilter('ALL');
                      }}
                      className="px-3 py-1 rounded border text-[12px] font-semibold transition-colors"
                      style={{
                        backgroundColor:
                          resultsSubtab === 'findings' && sevFilter === 'ALL'
                            ? 'var(--bg-surface)'
                            : 'transparent',
                        borderColor:
                          resultsSubtab === 'findings' && sevFilter === 'ALL'
                            ? 'var(--border-strong)'
                            : 'transparent',
                      }}
                    >
                      Total: {activeResult.summary?.total || 0}
                    </button>

                    {['High', 'Medium', 'Low', 'Info'].map((sev) => {
                      const count = activeResult.summary?.[sev.toLowerCase()] || 0;
                      const meta = SEVERITY_META[sev];
                      const active = resultsSubtab === 'findings' && sevFilter === sev;
                      return (
                        <button
                          key={sev}
                          onClick={() => {
                            setResultsSubtab('findings');
                            setSevFilter(active ? 'ALL' : sev);
                          }}
                          className="px-3 py-1 rounded border text-[12px] flex items-center gap-2 transition-colors"
                          style={{
                            backgroundColor: active ? 'var(--bg-surface)' : 'transparent',
                            borderColor: active ? meta.color : 'transparent',
                          }}
                        >
                          <span
                            className="w-2 h-2 rounded-sm"
                            style={{ backgroundColor: meta.color }}
                          />
                          <span style={{ color: 'var(--text-secondary)' }}>{sev}</span>
                          <strong className="font-mono">{count}</strong>
                        </button>
                      );
                    })}
                  </div>

                  {/* Secondary View Switch: Findings vs Tech Inventory vs Resolved */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setResultsSubtab('findings')}
                      className="px-2.5 py-1 rounded text-[12px] font-medium"
                      style={{
                        backgroundColor:
                          resultsSubtab === 'findings' ? 'var(--bg-raised)' : 'transparent',
                        color:
                          resultsSubtab === 'findings'
                            ? 'var(--text-primary)'
                            : 'var(--text-secondary)',
                      }}
                    >
                      {t.tabFindings} ({activeResult.findings?.length || 0})
                    </button>
                    <button
                      onClick={() => setResultsSubtab('tech')}
                      className="px-2.5 py-1 rounded text-[12px] font-medium"
                      style={{
                        backgroundColor:
                          resultsSubtab === 'tech' ? 'var(--bg-raised)' : 'transparent',
                        color:
                          resultsSubtab === 'tech'
                            ? 'var(--text-primary)'
                            : 'var(--text-secondary)',
                      }}
                    >
                      {t.tabTechStack} ({activeResult.technologies?.length || 0})
                    </button>
                    {activeResult.diff?.fixedFindings?.length > 0 && (
                      <button
                        onClick={() => setResultsSubtab('fixed')}
                        className="px-2.5 py-1 rounded text-[12px] font-medium"
                        style={{
                          backgroundColor:
                            resultsSubtab === 'fixed' ? 'var(--bg-raised)' : 'transparent',
                          color: 'var(--sev-fixed)',
                        }}
                      >
                        {t.tabFixedFindings} ({activeResult.diff.fixedFindings.length})
                      </button>
                    )}
                  </div>
                </div>

                {/* Split-Pane Body */}
                {resultsSubtab === 'findings' && (
                  <div className="flex-1 flex overflow-hidden">
                    {/* Left Master Table of Findings */}
                    <div
                      className="w-[410px] shrink-0 h-full border-r flex flex-col workbench-surface"
                      style={{ borderColor: 'var(--border-hairline)' }}
                    >
                      {/* Filter & Search Header */}
                      <div
                        className="p-3 border-b space-y-2"
                        style={{ borderColor: 'var(--border-hairline)' }}
                      >
                        <div className="relative">
                          <Search
                            className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2"
                            style={{ color: 'var(--text-muted)' }}
                          />
                          <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder={t.searchPlaceholder}
                            className="workbench-input w-full pl-8 pr-3 py-1.5 text-[12.5px]"
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <select
                            value={modFilter}
                            onChange={(e) => setModFilter(e.target.value)}
                            className="workbench-input px-2 py-1 text-[12px]"
                          >
                            <option value="ALL">{t.filterAllModules}</option>
                            {modules.map((m) => (
                              <option key={m.id} value={m.id}>
                                {m.id}
                              </option>
                            ))}
                          </select>
                          <select
                            value={diffFilter}
                            onChange={(e) => setDiffFilter(e.target.value)}
                            className="workbench-input px-2 py-1 text-[12px]"
                          >
                            <option value="ALL">{t.filterAllDiff}</option>
                            <option value="new">{t.diffNew}</option>
                            <option value="recurring">{t.diffRecurring}</option>
                          </select>
                        </div>
                      </div>

                      {/* Findings List */}
                      <div
                        className="flex-1 overflow-y-auto divide-y"
                        style={{ borderColor: 'var(--border-hairline)' }}
                      >
                        {filteredFindings.length === 0 ? (
                          <div
                            className="p-8 text-center text-[12.5px]"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {isEN
                              ? 'No findings match the current filter.'
                              : 'Tidak ada temuan yang sesuai dengan filter.'}
                          </div>
                        ) : (
                          filteredFindings.map((f) => {
                            const meta = SEVERITY_META[f.severity] || SEVERITY_META.Info;
                            const isSelected = selectedFinding && selectedFinding.id === f.id;
                            const displayTitle = isEN && f.titleEn ? f.titleEn : f.title;
                            return (
                              <button
                                key={f.id}
                                type="button"
                                onClick={() => setSelectedFinding(f)}
                                className="w-full text-left px-4 py-3 transition-colors relative block"
                                style={{
                                  backgroundColor: isSelected
                                    ? 'var(--bg-raised)'
                                    : 'transparent',
                                  borderColor: 'var(--border-hairline)',
                                }}
                              >
                                <span
                                  className="absolute left-0 top-0 bottom-0 w-[3px]"
                                  style={{ backgroundColor: meta.color }}
                                />
                                <div className="flex items-start justify-between gap-2">
                                  <span className="font-semibold text-[13px] leading-snug">
                                    {displayTitle}
                                  </span>
                                  <span
                                    className="shrink-0 text-[11px] font-mono px-1.5 py-0.2 rounded"
                                    style={{
                                      backgroundColor: meta.bg,
                                      color: meta.color,
                                      fontWeight: 600,
                                    }}
                                  >
                                    {f.severity}
                                  </span>
                                </div>
                                <div
                                  className="mt-1.5 flex items-center gap-2.5 text-[11.5px] font-mono"
                                  style={{ color: 'var(--text-muted)' }}
                                >
                                  <span>{f.module}</span>
                                  {f.cwe && <span>{f.cwe}</span>}
                                  {f.diffStatus === 'new' && (
                                    <span style={{ color: 'var(--accent-primary)' }}>
                                      {isEN ? 'New' : 'Baru'}
                                    </span>
                                  )}
                                </div>
                              </button>
                            );
                          })
                        )}
                      </div>
                    </div>

                    {/* Right Technical Dossier Pane */}
                    <div className="flex-1 h-full overflow-y-auto p-6 select-text">
                      {!selectedFinding ? (
                        <div
                          className="text-[13px]"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          {isEN
                            ? 'Select a finding from the list to inspect its technical details.'
                            : 'Pilih salah satu temuan di panel kiri untuk membaca lembar inspeksi.'}
                        </div>
                      ) : (
                        <article className="max-w-[68ch] space-y-6">
                          {/* Dossier Header */}
                          <header
                            className="pb-4 border-b space-y-2.5"
                            style={{ borderColor: 'var(--border-hairline)' }}
                          >
                            <div className="flex items-start justify-between gap-4">
                              <h2 className="text-[18px] font-bold leading-snug tracking-tight">
                                {isEN && selectedFinding.titleEn
                                  ? selectedFinding.titleEn
                                  : selectedFinding.title}
                              </h2>
                              <span
                                className="shrink-0 text-[12px] font-mono font-semibold px-2.5 py-0.5 rounded"
                                style={{
                                  backgroundColor: (
                                    SEVERITY_META[selectedFinding.severity] || SEVERITY_META.Info
                                  ).bg,
                                  color: (
                                    SEVERITY_META[selectedFinding.severity] || SEVERITY_META.Info
                                  ).color,
                                }}
                              >
                                {selectedFinding.severity}
                              </span>
                            </div>

                            <div
                              className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] font-mono"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              <span>Rule: {selectedFinding.ruleId}</span>
                              <span>
                                {t.confidenceLabel}: {selectedFinding.confidence}
                              </span>
                              {selectedFinding.cwe && <span>{selectedFinding.cwe}</span>}
                              {selectedFinding.owasp && <span>{selectedFinding.owasp}</span>}
                            </div>
                          </header>

                          {/* 1. Finding Description */}
                          <section className="space-y-1.5">
                            <h3
                              className="text-[13px] font-semibold"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {t.whatIsThis}
                            </h3>
                            <p className="text-[14px] leading-[1.65]">
                              {isEN && selectedFinding.descriptionEn
                                ? selectedFinding.descriptionEn
                                : selectedFinding.description}
                            </p>
                          </section>

                          {/* 2. Security Impact */}
                          <section className="space-y-1.5">
                            <h3
                              className="text-[13px] font-semibold"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {t.whyRisky}
                            </h3>
                            <p className="text-[14px] leading-[1.65]">
                              {isEN && selectedFinding.impactEn
                                ? selectedFinding.impactEn
                                : selectedFinding.impact}
                            </p>
                          </section>

                          {/* 3. Actionable Remediation */}
                          <section
                            className="pl-4 py-3 pr-4 rounded-r border-l-[3px] space-y-1"
                            style={{
                              backgroundColor: 'var(--bg-surface)',
                              borderLeftColor: 'var(--sev-fixed)',
                            }}
                          >
                            <h3
                              className="text-[13px] font-semibold"
                              style={{ color: 'var(--sev-fixed)' }}
                            >
                              {t.howToFix}
                            </h3>
                            <p className="text-[14px] leading-[1.65]">
                              {isEN && selectedFinding.recommendationEn
                                ? selectedFinding.recommendationEn
                                : selectedFinding.recommendation}
                            </p>
                          </section>

                          {/* 4. Technical Evidence */}
                          {selectedFinding.evidence && (
                            <section className="space-y-2">
                              <div className="flex items-center justify-between">
                                <h3
                                  className="text-[13px] font-semibold"
                                  style={{ color: 'var(--text-secondary)' }}
                                >
                                  {t.technicalEvidence}
                                </h3>
                                <button
                                  type="button"
                                  onClick={() => copyEvidenceText(selectedFinding)}
                                  className="inline-flex items-center gap-1.5 text-[12px] font-medium"
                                  style={{ color: 'var(--accent-primary)' }}
                                >
                                  {copiedId === selectedFinding.id ? (
                                    <>
                                      <Check className="w-3.5 h-3.5" />
                                      <span>{t.copied}</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3.5 h-3.5" />
                                      <span>{t.copyEvidence}</span>
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre
                                className="p-3.5 rounded border font-mono text-[12px] leading-relaxed overflow-x-auto whitespace-pre-wrap"
                                style={{
                                  backgroundColor: 'var(--bg-surface)',
                                  borderColor: 'var(--border-hairline)',
                                }}
                              >
                                {selectedFinding.evidence}
                              </pre>
                            </section>
                          )}

                          {/* 5. References */}
                          {selectedFinding.references &&
                            selectedFinding.references.length > 0 && (
                              <section className="space-y-1.5">
                                <h3
                                  className="text-[13px] font-semibold"
                                  style={{ color: 'var(--text-secondary)' }}
                                >
                                  {t.referencesTitle}
                                </h3>
                                <ul className="space-y-1 text-[12.5px] font-mono">
                                  {selectedFinding.references.map((ref, idx) => (
                                    <li key={idx}>
                                      <a
                                        href={ref}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="inline-flex items-center gap-1.5 hover:underline break-all"
                                        style={{ color: 'var(--accent-primary)' }}
                                      >
                                        <ExternalLink className="w-3 h-3 shrink-0" />
                                        <span>{ref}</span>
                                      </a>
                                    </li>
                                  ))}
                                </ul>
                              </section>
                            )}
                        </article>
                      )}
                    </div>
                  </div>
                )}

                {/* Subview: Technology Inventory Table */}
                {resultsSubtab === 'tech' && (
                  <div className="flex-1 overflow-y-auto p-6">
                    <div className="max-w-6xl workbench-surface border rounded overflow-hidden">
                      <table className="w-full text-left border-collapse text-[13px]">
                        <thead>
                          <tr
                            className="border-b text-[12px]"
                            style={{
                              backgroundColor: 'var(--bg-subtle)',
                              borderColor: 'var(--border-hairline)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Component' : 'Komponen'}
                            </th>
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Language / Ecosystem' : 'Bahasa / Ekosistem'}
                            </th>
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Category' : 'Kategori'}
                            </th>
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Version' : 'Versi'}
                            </th>
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Associated / Estimated CVEs' : 'Kaitan / Estimasi CVE'}
                            </th>
                            <th className="py-2.5 px-4 font-semibold">
                              {isEN ? 'Detection source' : 'Sumber deteksi'}
                            </th>
                          </tr>
                        </thead>
                        <tbody
                          className="divide-y"
                          style={{ borderColor: 'var(--border-hairline)' }}
                        >
                          {(activeResult.technologies || []).map((tech, idx) => (
                            <tr
                              key={idx}
                              style={{ borderColor: 'var(--border-hairline)' }}
                            >
                              <td className="py-2.5 px-4 font-semibold">{tech.name}</td>
                              <td className="py-2.5 px-4">
                                {tech.language ? (
                                  <span
                                    className="text-[11.5px] font-mono px-2 py-0.5 rounded"
                                    style={{
                                      backgroundColor: 'var(--bg-raised)',
                                      color: 'var(--text-primary)',
                                    }}
                                  >
                                    {tech.language}
                                  </span>
                                ) : (
                                  <span style={{ color: 'var(--text-muted)' }}>-</span>
                                )}
                              </td>
                              <td
                                className="py-2.5 px-4"
                                style={{ color: 'var(--text-secondary)' }}
                              >
                                {tech.category}
                              </td>
                              <td className="py-2.5 px-4 font-mono">
                                {tech.version || (
                                  <span
                                    className="text-[11.5px]"
                                    style={{ color: 'var(--text-muted)' }}
                                  >
                                    {isEN ? 'Hidden' : 'Disembunyikan'}
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 px-4">
                                {tech.potentialCves && tech.potentialCves.length > 0 ? (
                                  <div className="flex flex-wrap gap-1.5">
                                    {tech.potentialCves.map((cveStr, cIdx) => {
                                      const isEstimate = cveStr.startsWith('?');
                                      return (
                                        <button
                                          key={cIdx}
                                          type="button"
                                          onClick={() => {
                                            setModFilter('cve');
                                            setSevFilter('ALL');
                                            setResultsSubtab('findings');
                                          }}
                                          className="text-[11px] font-mono px-2 py-0.5 rounded text-left transition-opacity hover:opacity-80"
                                          style={{
                                            backgroundColor: isEstimate
                                              ? 'var(--sev-low-bg)'
                                              : 'var(--sev-high-bg)',
                                            color: isEstimate
                                              ? 'var(--sev-low)'
                                              : 'var(--sev-high)',
                                            fontWeight: 600,
                                          }}
                                        >
                                          {cveStr}
                                        </button>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <span
                                    className="text-[11.5px]"
                                    style={{ color: 'var(--text-muted)' }}
                                  >
                                    {isEN ? 'None mapped' : 'Tidak ada'}
                                  </span>
                                )}
                              </td>
                              <td
                                className="py-2.5 px-4 font-mono text-[12px]"
                                style={{ color: 'var(--text-muted)' }}
                              >
                                {tech.source}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Subview: Resolved Findings */}
                {resultsSubtab === 'fixed' && (
                  <div className="flex-1 overflow-y-auto p-6">
                    <div className="max-w-3xl space-y-2.5">
                      {(activeResult.diff?.fixedFindings || []).map((ff) => (
                        <div
                          key={ff.id}
                          className="workbench-surface border rounded px-4 py-3 flex items-center justify-between"
                        >
                          <div>
                            <div className="font-semibold text-[13.5px]">
                              {isEN && ff.titleEn ? ff.titleEn : ff.title}
                            </div>
                            <div
                              className="text-[12px] font-mono mt-0.5"
                              style={{ color: 'var(--text-muted)' }}
                            >
                              {ff.module} | {ff.ruleId}
                            </div>
                          </div>
                          <span
                            className="text-[11.5px] font-mono font-semibold px-2 py-0.5 rounded"
                            style={{
                              backgroundColor: 'var(--sev-fixed-bg)',
                              color: 'var(--sev-fixed)',
                            }}
                          >
                            {isEN ? 'Resolved' : 'Teratasi'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* VIEW 4: SAVED SCAN HISTORY */}
        {activeTab === 'history' && (
          <div className="flex-1 overflow-y-auto p-6">
            <div className="max-w-5xl mx-auto space-y-4">
              <div className="flex items-center justify-between">
                <h1 className="text-[17px] font-bold">{t.historyTitle}</h1>
                {historyList.length > 0 && (
                  <button
                    onClick={handleClearHistory}
                    className="btn-secondary px-3 py-1.5 text-[12px] flex items-center gap-1.5"
                    style={{ color: 'var(--sev-high)' }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>{t.clearHistoryBtn}</span>
                  </button>
                )}
              </div>

              {historyList.length === 0 ? (
                <div
                  className="workbench-surface border rounded p-10 text-center text-[13px]"
                  style={{ color: 'var(--text-muted)' }}
                >
                  {t.emptyHistory}
                </div>
              ) : (
                <div className="workbench-surface border rounded overflow-hidden">
                  <table className="w-full text-left border-collapse text-[13px] tabular-nums">
                    <thead>
                      <tr
                        className="border-b text-[12px]"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          borderColor: 'var(--border-hairline)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        <th className="py-2.5 px-4 font-semibold">Target</th>
                        <th className="py-2.5 px-4 font-semibold">Profil</th>
                        <th className="py-2.5 px-4 font-semibold">Waktu</th>
                        <th className="py-2.5 px-4 font-semibold">Ringkasan temuan</th>
                        <th className="py-2.5 px-4 font-semibold text-right">Tindakan</th>
                      </tr>
                    </thead>
                    <tbody
                      className="divide-y"
                      style={{ borderColor: 'var(--border-hairline)' }}
                    >
                      {historyList.map((scan) => (
                        <tr
                          key={scan.id}
                          style={{ borderColor: 'var(--border-hairline)' }}
                        >
                          <td className="py-3 px-4 font-mono font-medium">
                            {scan.targetUrl}
                          </td>
                          <td className="py-3 px-4">{scan.profile}</td>
                          <td
                            className="py-3 px-4 text-[12px]"
                            style={{ color: 'var(--text-secondary)' }}
                          >
                            {new Date(scan.startedAt).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-mono text-[12px]">
                            <span style={{ color: 'var(--sev-high)' }}>
                              H:{scan.summary?.high || 0}
                            </span>{' '}
                            <span style={{ color: 'var(--sev-medium)' }}>
                              M:{scan.summary?.medium || 0}
                            </span>{' '}
                            <span style={{ color: 'var(--sev-low)' }}>
                              L:{scan.summary?.low || 0}
                            </span>{' '}
                            <span style={{ color: 'var(--text-muted)' }}>
                              I:{scan.summary?.info || 0}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right space-x-2">
                            <button
                              onClick={() => handleOpenHistoryScan(scan.id)}
                              className="btn-primary px-3 py-1 text-[12px]"
                            >
                              {t.openResultBtn}
                            </button>
                            <button
                              onClick={() => handleDeleteScan(scan.id)}
                              className="btn-secondary px-2.5 py-1 text-[12px]"
                            >
                              {t.deleteBtn}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 5: ACCOUNTABILITY AUDIT LOG */}
        {activeTab === 'audit' && (
          <div className="flex-1 overflow-y-auto p-6">
            <div className="max-w-5xl mx-auto space-y-4">
              <h1 className="text-[17px] font-bold">{t.auditTitle}</h1>
              <div className="workbench-surface border rounded overflow-hidden">
                <table className="w-full text-left border-collapse text-[12.5px] tabular-nums">
                  <thead>
                    <tr
                      className="border-b text-[12px]"
                      style={{
                        backgroundColor: 'var(--bg-subtle)',
                        borderColor: 'var(--border-hairline)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      <th className="py-2.5 px-4 font-semibold">{t.auditTableTime}</th>
                      <th className="py-2.5 px-4 font-semibold">{t.auditTableTarget}</th>
                      <th className="py-2.5 px-4 font-semibold">{t.auditTableProfile}</th>
                      <th className="py-2.5 px-4 font-semibold">{t.auditTableAuth}</th>
                      <th className="py-2.5 px-4 font-semibold">{t.auditTableMetrics}</th>
                    </tr>
                  </thead>
                  <tbody
                    className="divide-y"
                    style={{ borderColor: 'var(--border-hairline)' }}
                  >
                    {auditLogs.map((log) => (
                      <tr
                        key={log.id}
                        style={{ borderColor: 'var(--border-hairline)' }}
                      >
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-4 font-mono">
                          <div>{log.targetUrl}</div>
                          <div
                            className="text-[11.5px]"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {log.normalizedHost}
                          </div>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="font-medium">{log.profile}</div>
                          <div
                            className="text-[11.5px] font-mono truncate max-w-xs"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {log.modulesExecuted}
                          </div>
                        </td>
                        <td className="py-2.5 px-4">
                          <div style={{ color: 'var(--sev-fixed)' }}>
                            {isEN ? 'Confirmed' : 'Dikonfirmasi'}
                          </div>
                          {log.authorizationNote && (
                            <div
                              className="text-[11.5px]"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {log.authorizationNote}
                            </div>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-mono">
                          <div>{log.status}</div>
                          <div
                            className="text-[11.5px]"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {log.totalFindings} findings | {log.rateLimitRps} req/s
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 6: ENGINE SETTINGS & LOCAL CVE DATABASE */}
        {activeTab === 'settings' && (
          <div className="flex-1 overflow-y-auto p-6">
            <div className="max-w-5xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <form
                onSubmit={handleSaveSettings}
                className="lg:col-span-7 workbench-surface border rounded p-5 space-y-4"
              >
                <h2
                  className="text-[15px] font-bold pb-3 border-b"
                  style={{ borderColor: 'var(--border-hairline)' }}
                >
                  {t.engineConfigTitle}
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {t.workersLabel}
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="25"
                      value={settings.maxWorkers}
                      onChange={(e) =>
                        setSettings({ ...settings, maxWorkers: Number(e.target.value) })
                      }
                      className="workbench-input w-full px-3 py-1.5 font-mono text-[13px]"
                    />
                  </div>

                  <div>
                    <label
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {t.rateLimitLabel}
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="100"
                      value={settings.rateLimitRps}
                      onChange={(e) =>
                        setSettings({ ...settings, rateLimitRps: Number(e.target.value) })
                      }
                      className="workbench-input w-full px-3 py-1.5 font-mono text-[13px]"
                    />
                  </div>

                  <div>
                    <label
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {t.timeoutLabel}
                    </label>
                    <input
                      type="number"
                      min="2"
                      max="60"
                      value={settings.timeoutSeconds}
                      onChange={(e) =>
                        setSettings({ ...settings, timeoutSeconds: Number(e.target.value) })
                      }
                      className="workbench-input w-full px-3 py-1.5 font-mono text-[13px]"
                    />
                  </div>

                  <div>
                    <label
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {t.retriesLabel}
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="5"
                      value={settings.maxRetries}
                      onChange={(e) =>
                        setSettings({ ...settings, maxRetries: Number(e.target.value) })
                      }
                      className="workbench-input w-full px-3 py-1.5 font-mono text-[13px]"
                    />
                  </div>
                </div>

                <div>
                  <label
                    className="block text-[12px] font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {t.userAgentLabel}
                  </label>
                  <input
                    type="text"
                    value={settings.userAgent}
                    onChange={(e) => setSettings({ ...settings, userAgent: e.target.value })}
                    className="workbench-input w-full px-3 py-1.5 font-mono text-[12.5px]"
                  />
                </div>

                <div>
                  <label
                    className="block text-[12px] font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {t.proxyLabel}
                  </label>
                  <input
                    type="text"
                    value={settings.proxyUrl}
                    onChange={(e) => setSettings({ ...settings, proxyUrl: e.target.value })}
                    placeholder="http://127.0.0.1:8080"
                    className="workbench-input w-full px-3 py-1.5 font-mono text-[12.5px]"
                  />
                </div>

                <div>
                  <label
                    className="block text-[12px] font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {t.customHeadersLabel}
                  </label>
                  <textarea
                    rows={3}
                    value={customHeadersText}
                    onChange={(e) => setCustomHeadersText(e.target.value)}
                    className="workbench-input w-full px-3 py-1.5 font-mono text-[12px]"
                  />
                </div>

                <button type="submit" className="btn-primary px-4 py-2 text-[12.5px]">
                  {t.saveSettingsBtn}
                </button>
              </form>

              {/* Right Column: Offline CVE Database */}
              <div className="lg:col-span-5 workbench-surface border rounded p-5 space-y-4">
                <h2
                  className="text-[15px] font-bold pb-3 border-b"
                  style={{ borderColor: 'var(--border-hairline)' }}
                >
                  {t.cveSectionTitle}
                </h2>

                {cveMeta && (
                  <div
                    className="p-3.5 rounded border space-y-1.5 text-[12.5px] tabular-nums"
                    style={{
                      backgroundColor: 'var(--bg-canvas)',
                      borderColor: 'var(--border-hairline)',
                    }}
                  >
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {t.cveVersionLabel}
                      </span>
                      <span className="font-mono font-medium">{cveMeta.version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {t.cveUpdatedLabel}
                      </span>
                      <span>{new Date(cveMeta.lastUpdated).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {t.cveTotalLabel}
                      </span>
                      <span className="font-mono font-semibold">{cveMeta.totalEntries}</span>
                    </div>
                  </div>
                )}

                <button
                  type="button"
                  onClick={handleRefreshCVE}
                  className="btn-secondary w-full py-2 text-[12.5px] flex items-center justify-center gap-2"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>{t.refreshCVEBtn}</span>
                </button>

                <div className="space-y-2 pt-2">
                  <label
                    className="block text-[12px] font-medium"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {t.importCVELabel}
                  </label>
                  <textarea
                    rows={4}
                    value={cveImportJson}
                    onChange={(e) => setCveImportJson(e.target.value)}
                    placeholder='[{"cveId":"CVE-2026-0001","product":"nginx","versionStart":"1.20.0","versionEnd":"1.27.0","severity":"High","cvss":7.8,"cwe":"CWE-20","summaryId":"Ringkasan","summaryEn":"Summary","remediationId":"Perbarui","remediationEn":"Update"}]'
                    className="workbench-input w-full px-3 py-2 font-mono text-[11.5px]"
                  />
                  <button
                    type="button"
                    onClick={handleImportCVE}
                    className="btn-secondary w-full py-2 text-[12.5px]"
                  >
                    {t.importCVEBtn}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
