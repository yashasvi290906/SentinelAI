'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { Command } from 'cmdk';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Shield,
  Wifi,
  WifiOff,
  Clock,
  LayoutDashboard,
  Brain,
  GitCompareArrows,
  Activity,
  BarChart3,
  FlaskConical,
  Target,
  FileText,
  Settings,
  HeartPulse,
  MessageCircle,
  ScanSearch,
  Network,
  Crosshair,
  TrendingUp,
} from 'lucide-react';
import { useGlobalStore } from '@/stores/globalStore';
import { useSystemStore } from '@/stores/systemStore';
import { useAnalyticsStore } from '@/stores/analyticsStore';
import NotificationCenter from '@/components/layout/NotificationCenter';

const moduleMap: Record<string, { label: string; description: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }> }> = {
  dashboard: { label: 'Dashboard', description: 'Security overview and metrics', icon: LayoutDashboard },
  predictions: { label: 'Predictions', description: 'ML threat predictions', icon: Brain },
  compare: { label: 'Compare', description: 'Model comparison analysis', icon: GitCompareArrows },
  'live-feed': { label: 'Live Feed', description: 'Real-time event stream', icon: Activity },
  timeline: { label: 'Timeline', description: 'Attack timeline view', icon: Clock },
  analytics: { label: 'Analytics', description: 'Traffic analytics and charts', icon: BarChart3 },
  copilot: { label: 'AI Copilot', description: 'AI-powered assistant', icon: MessageCircle },
  explainability: { label: 'Explainability', description: 'Model decision explanations', icon: ScanSearch },
  'network-graph': { label: 'Network Graph', description: 'Network topology visualization', icon: Network },
  killchain: { label: 'Kill Chain', description: 'Attack lifecycle mapping', icon: Crosshair },
  'drift-analytics': { label: 'Drift Analytics', description: 'Data drift detection', icon: TrendingUp },
  simulation: { label: 'Simulation Lab', description: 'Attack simulation environment', icon: FlaskConical },
  'threat-intel': { label: 'Threat Intel', description: 'Threat intelligence feeds', icon: Target },
  reports: { label: 'Reports', description: 'Security report generation', icon: FileText },
  'system-health': { label: 'System Health', description: 'System performance metrics', icon: HeartPulse },
  settings: { label: 'Settings', description: 'Application configuration', icon: Settings },
};

interface SearchResult {
  id: string;
  label: string;
  description: string;
  category: 'module' | 'setting' | 'action';
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  shortcut?: string;
}

const settingsList: SearchResult[] = [
  { id: 'settings-theme', label: 'Theme Settings', description: 'Customize UI theme', category: 'setting', icon: Settings },
  { id: 'settings-notifications', label: 'Notification Preferences', description: 'Alert configuration', category: 'setting', icon: Settings },
];

const actionsList: SearchResult[] = [
  { id: 'action-refresh', label: 'Refresh Dashboard', description: 'Reload all data', category: 'action', icon: Activity, shortcut: '⌘R' },
  { id: 'action-export', label: 'Export Report', description: 'Download security report', category: 'action', icon: FileText, shortcut: '⌘E' },
  { id: 'action-alert', label: 'Create Alert Rule', description: 'Set up new alert', category: 'action', icon: Target },
];

const allModules = Object.entries(moduleMap).map(([id, mod]) => ({
  id,
  ...mod,
}));

function getThreatLabel(score: number): string {
  if (score > 70) return 'HIGH';
  if (score > 40) return 'MEDIUM';
  return 'LOW';
}

function getThreatColor(score: number): string {
  if (score > 70) return 'var(--accent-red)';
  if (score > 40) return 'var(--accent-amber)';
  return 'var(--accent-green)';
}

const allSearchResults: SearchResult[] = [
  ...allModules.map(mod => ({
    ...mod,
    description: mod.description || '',
    category: 'module' as const,
  })),
  ...settingsList,
  ...actionsList,
];

function searchResults(query: string): SearchResult[] {
  if (!query.trim()) return allSearchResults;
  const q = query.toLowerCase();
  return allSearchResults.filter(r =>
    r.label.toLowerCase().includes(q) ||
    r.description.toLowerCase().includes(q) ||
    r.category.toLowerCase().includes(q)
  );
}

export default function CommandBar() {
  const [open, setOpen] = useState(false);
  const [currentTime, setCurrentTime] = useState('');
  const [query, setQuery] = useState('');

  const activeModule = useGlobalStore((s) => s.activeModule);
  const setActiveModule = useGlobalStore((s) => s.setActiveModule);
  const backendStatus = useSystemStore((s) => s.backendStatus);
  const getDashboardMetrics = useAnalyticsStore((s) => s.getDashboardMetrics);

  const threatScore = useMemo(() => getDashboardMetrics().threatScore, [getDashboardMetrics]);

  const isOnline = backendStatus === 'online';

  const activeLabel = moduleMap[activeModule]?.label ?? 'Dashboard';

  const results = useMemo(() => searchResults(query), [query]);
  const grouped = useMemo(() => ({
    modules: results.filter(r => r.category === 'module'),
    settings: results.filter(r => r.category === 'setting'),
    actions: results.filter(r => r.category === 'action'),
  }), [results]);

  useEffect(() => {
    const tick = () =>
      setCurrentTime(
        new Date().toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
      );
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
      if (e.key === 'Escape') setOpen(false);
    },
    [],
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  const selectModule = (id: string) => {
    setActiveModule(id);
    setOpen(false);
  };

  return (
    <>
      {/* Top Bar */}
      <div
        className="h-14 flex items-center justify-between px-5 relative z-10 shrink-0"
        style={{
          background: 'rgba(8, 20, 32, 0.7)',
          backdropFilter: 'blur(24px)',
          borderBottom: '1px solid rgba(0, 229, 255, 0.08)',
        }}
      >
        {/* Left: Breadcrumb */}
        <div className="flex items-center gap-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          <Shield className="w-3.5 h-3.5" style={{ color: 'var(--accent-cyan)' }} />
          <span className="tracking-wider uppercase">{activeLabel}</span>
        </div>

        {/* Center: Threat Level Pill */}
        <div className="hidden md:flex items-center gap-3">
          <div
            className="flex items-center gap-2.5 px-4 py-1.5 rounded-full"
            style={{
              background:
                threatScore > 70
                  ? 'rgba(255, 77, 109, 0.08)'
                  : threatScore > 40
                    ? 'rgba(255, 176, 32, 0.08)'
                    : 'rgba(0, 255, 136, 0.08)',
              border: `1px solid ${
                threatScore > 70
                  ? 'rgba(255, 77, 109, 0.2)'
                  : threatScore > 40
                    ? 'rgba(255, 176, 32, 0.2)'
                    : 'rgba(0, 255, 136, 0.2)'
              }`,
            }}
          >
            <motion.div
              className="w-2 h-2 rounded-full"
              style={{ background: getThreatColor(threatScore) }}
              animate={{ scale: [1, 1.3, 1] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
            />
            <span
              className="text-[10px] font-bold tracking-widest uppercase"
              style={{ color: getThreatColor(threatScore) }}
            >
              Threat: {getThreatLabel(threatScore)}
            </span>
            <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
              {threatScore}/100
            </span>
          </div>
        </div>

        {/* Right: Controls */}
        <div className="flex items-center gap-2">
          {/* Search Trigger */}
          <button
            onClick={() => setOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all duration-300 hover:shadow-[0_0_12px_rgba(0,229,255,0.08)]"
            style={{
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(0,229,255,0.08)',
            }}
          >
            <Search className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-[11px] hidden sm:inline" style={{ color: 'var(--text-muted)' }}>
              Search
            </span>
            <kbd
              className="px-1.5 py-0.5 text-[9px] rounded hidden sm:inline"
              style={{
                color: 'var(--text-muted)',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(0,229,255,0.06)',
              }}
            >
              ⌘K
            </kbd>
          </button>

          {/* Notification Center */}
          <NotificationCenter />

          {/* Backend Status */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg"
            style={{
              background: isOnline ? 'rgba(0, 255, 136, 0.06)' : 'rgba(255, 77, 109, 0.06)',
              border: `1px solid ${isOnline ? 'rgba(0, 255, 136, 0.15)' : 'rgba(255, 77, 109, 0.15)'}`,
            }}
          >
            {isOnline ? (
              <Wifi className="w-3.5 h-3.5" style={{ color: 'var(--accent-green)' }} />
            ) : (
              <WifiOff className="w-3.5 h-3.5" style={{ color: 'var(--accent-red)' }} />
            )}
            <span
              className="text-[10px] font-mono font-semibold"
              style={{ color: isOnline ? 'var(--accent-green)' : 'var(--accent-red)' }}
            >
              {isOnline ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>

          {/* Clock */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(0,229,255,0.06)' }}
          >
            <Clock className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-[11px] font-mono tabular-nums" style={{ color: 'var(--text-secondary)' }}>
              {currentTime}
            </span>
          </div>
        </div>
      </div>

      {/* Command Palette */}
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50"
              style={{ background: 'rgba(8, 20, 32, 0.7)', backdropFilter: 'blur(4px)' }}
              onClick={() => setOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -10, scale: 0.98 }}
              transition={{ duration: 0.2 }}
              className="fixed top-20 left-1/2 -translate-x-1/2 w-full max-w-lg z-50"
            >
              <Command
                className="overflow-hidden"
                style={{
                  background: 'rgba(8, 20, 32, 0.95)',
                  backdropFilter: 'blur(24px)',
                  border: '1px solid rgba(0, 229, 255, 0.15)',
                  borderRadius: '16px',
                  boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 229, 255, 0.05)',
                }}
              >
                <div className="p-4 border-b" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
                  <Command.Input
                    placeholder="Search pages, commands..."
                    className="w-full bg-transparent outline-none text-sm font-mono"
                    style={{ color: 'var(--text-primary)' }}
                    onValueChange={setQuery}
                  />
                </div>
                <Command.List className="max-h-80 overflow-y-auto p-2">
                  <Command.Empty className="py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                    No results found.
                  </Command.Empty>
                  {grouped.modules.length > 0 && (
                    <>
                      <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center gap-2" style={{ color: 'var(--accent-cyan)' }}>
                        <span className="px-1.5 py-0.5 rounded text-[9px]" style={{ background: 'rgba(0,229,255,0.15)' }}>M</span>
                        Modules
                      </div>
                      <Command.Group>
                        {grouped.modules.map((result) => {
                          const Icon = result.icon;
                          return (
                            <Command.Item
                              key={result.id}
                              onSelect={() => selectModule(result.id)}
                              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm cursor-pointer"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              <Icon className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="truncate">{result.label}</span>
                                  {activeModule === result.id && (
                                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded shrink-0" style={{ background: 'rgba(0,229,255,0.1)', color: 'var(--accent-cyan)' }}>
                                      ACTIVE
                                    </span>
                                  )}
                                </div>
                                <p className="text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{result.description}</p>
                              </div>
                              <span className="ml-auto text-xs font-mono shrink-0" style={{ color: 'rgba(255,255,255,0.2)' }}>
                                {result.shortcut || '↵'}
                              </span>
                            </Command.Item>
                          );
                        })}
                      </Command.Group>
                    </>
                  )}
                  {grouped.settings.length > 0 && (
                    <>
                      <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center gap-2" style={{ color: 'var(--accent-purple)' }}>
                        <span className="px-1.5 py-0.5 rounded text-[9px]" style={{ background: 'rgba(124,77,255,0.15)' }}>S</span>
                        Settings
                      </div>
                      <Command.Group>
                        {grouped.settings.map((result) => {
                          const Icon = result.icon;
                          return (
                            <Command.Item
                              key={result.id}
                              onSelect={() => { selectModule('settings'); }}
                              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm cursor-pointer"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              <Icon className="w-4 h-4" style={{ color: 'var(--accent-purple)' }} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="truncate">{result.label}</span>
                                </div>
                                <p className="text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{result.description}</p>
                              </div>
                              <span className="ml-auto text-xs font-mono shrink-0" style={{ color: 'rgba(255,255,255,0.2)' }}>
                                {result.shortcut || '↵'}
                              </span>
                            </Command.Item>
                          );
                        })}
                      </Command.Group>
                    </>
                  )}
                  {grouped.actions.length > 0 && (
                    <>
                      <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center gap-2" style={{ color: 'var(--accent-amber)' }}>
                        <span className="px-1.5 py-0.5 rounded text-[9px]" style={{ background: 'rgba(255,176,32,0.15)' }}>A</span>
                        Actions
                      </div>
                      <Command.Group>
                        {grouped.actions.map((result) => {
                          const Icon = result.icon;
                          return (
                            <Command.Item
                              key={result.id}
                              onSelect={() => {}}
                              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm cursor-pointer"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              <Icon className="w-4 h-4" style={{ color: 'var(--accent-amber)' }} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="truncate">{result.label}</span>
                                </div>
                                <p className="text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{result.description}</p>
                              </div>
                              <span className="ml-auto text-xs font-mono shrink-0" style={{ color: 'rgba(255,255,255,0.2)' }}>
                                {result.shortcut || '↵'}
                              </span>
                            </Command.Item>
                          );
                        })}
                      </Command.Group>
                    </>
                  )}
                </Command.List>
              </Command>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
