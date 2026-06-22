'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Brain,
  GitCompareArrows,
  Activity,
  Clock,
  BarChart3,
  FlaskConical,
  Target,
  FileText,
  Settings,
  ChevronLeft,
  Shield,
  ShieldAlert,
  HeartPulse,
  MessageCircle,
  ScanSearch,
  Network,
  Crosshair,
  TrendingUp,
  Route,
  Cpu,
  LogOut,
  Upload,
  Search,
  Server,
} from 'lucide-react';
import { useGlobalStore } from '@/stores/globalStore';
import { useSystemStore } from '@/stores/systemStore';

const primaryNav = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'predictions', label: 'Predictions', icon: Brain },
  { id: 'compare', label: 'Compare', icon: GitCompareArrows },
  { id: 'live-feed', label: 'Live Feed', icon: Activity },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
];

const secondaryNav = [
  { id: 'copilot', label: 'AI Copilot', icon: MessageCircle },
  { id: 'threat-hunt', label: 'Threat Hunt', icon: Search },
  { id: 'security-metrics', label: 'Security Metrics', icon: BarChart3 },
  { id: 'pipeline-visualizer', label: 'Pipeline', icon: Activity },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { id: 'agent-health', label: 'Agent Health', icon: Server },
  { id: 'explainability', label: 'Explainability', icon: ScanSearch },
  { id: 'network-graph', label: 'Network Graph', icon: Network },
  { id: 'attack-journey', label: 'Attack Journey', icon: Route },
  { id: 'killchain', label: 'Kill Chain', icon: Crosshair },
  { id: 'drift-analytics', label: 'Drift Analytics', icon: TrendingUp },
  { id: 'simulation', label: 'Simulation Lab', icon: FlaskConical },
  { id: 'threat-intel', label: 'Threat Intel', icon: Target },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'system-health', label: 'System Health', icon: HeartPulse },
  { id: 'system-architecture', label: 'Architecture', icon: Cpu },
  { id: 'log-upload', label: 'Log Upload', icon: Upload },
  { id: 'threat-detection', label: 'Threats', icon: ShieldAlert },
  { id: 'mitre-matrix', label: 'MITRE', icon: Target },
  { id: 'investigation', label: 'Investigate', icon: Search },
  { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
  { id: 'devices', label: 'Devices', icon: Server },
  { id: 'settings', label: 'Settings', icon: Settings },
];

function NavItem({
  item,
  isActive,
  expanded,
  onClick,
}: {
  item: { id: string; label: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }> };
  isActive: boolean;
  expanded: boolean;
  onClick: () => void;
}) {
  const Icon = item.icon;

  return (
      <button
      onClick={onClick}
      className="relative w-full flex items-center gap-3 p-2.5 rounded-xl transition-all duration-300 hover:translate-y-[-1px] hover:scale-[1.01] focus:outline-none focus:ring-2 focus:ring-cyan-400/50 focus:ring-offset-2 focus:ring-offset-transparent"
      style={{ transition: "transform 0.2s ease, box-shadow 0.2s ease" }}
      onMouseEnter={(e) => { e.currentTarget.style.boxShadow = "0 0 12px rgba(0,229,255,0.1)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.boxShadow = "none"; }}
      aria-current={isActive ? 'page' : undefined}
    >
      {isActive && (
        <motion.div
          layoutId="sidebar-active"
          className="absolute inset-0 rounded-xl"
          style={{ background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.15)' }}
          transition={{ type: "spring", stiffness: 350, damping: 30 }}
        />
      )}

      <div
        className="relative z-10 w-8 h-8 rounded-lg flex items-center justify-center transition-all duration-300 shrink-0"
        style={{
          background: isActive ? 'rgba(0, 229, 255, 0.15)' : 'rgba(255,255,255,0.03)',
          color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
          boxShadow: isActive ? '0 0 12px rgba(0,229,255,0.2)' : 'none',
        }}
      >
        <Icon className="w-4 h-4" />
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.span
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -6 }}
            transition={{ duration: 0.15 }}
            className="text-[13px] font-semibold relative z-10 whitespace-nowrap"
            style={{ color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}
          >
            {item.label}
          </motion.span>
        )}
      </AnimatePresence>
    </button>
  );
}

export default function CollapsibleSidebar() {
  const [expanded, setExpanded] = useState(true);
  const activeModule = useGlobalStore((s) => s.activeModule);
  const setActiveModule = useGlobalStore((s) => s.setActiveModule);
  const backendStatus = useSystemStore((s) => s.backendStatus);

  const isOnline = backendStatus === 'online';
  const isOffline = backendStatus === 'offline';

  return (
    <motion.div
      animate={{ width: expanded ? 260 : 72 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col h-full overflow-hidden shrink-0"
      role="navigation"
      aria-label="Main navigation"
      style={{
        background: 'rgba(8, 20, 32, 0.7)',
        backdropFilter: 'blur(24px)',
        borderRight: '1px solid rgba(0, 229, 255, 0.08)',
      }}
    >
      {/* Logo */}
      <div className="p-4 border-b border-white/[0.06]">
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
            style={{
              background: 'linear-gradient(135deg, rgba(0,229,255,0.2), rgba(0,255,136,0.1))',
              border: '1px solid rgba(0,229,255,0.25)',
              boxShadow: '0 0 20px rgba(0,229,255,0.15)',
            }}
          >
            <Shield className="w-5 h-5" style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                className="min-w-0"
              >
                <p className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-primary)' }}>
                  SENTINEL<span style={{ color: 'var(--accent-cyan)' }}>AI</span>
                </p>
                <p className="text-[9px] font-mono tracking-widest" style={{ color: 'var(--text-muted)' }}>
                  CYBER COMMAND
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Toggle */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="p-3 mx-2 mt-2 rounded-lg transition-colors hover:bg-white/[0.04]"
      >
        <motion.div animate={{ rotate: expanded ? 180 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronLeft className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        </motion.div>
      </button>

      {/* Nav */}
      <div className="flex-1 overflow-y-auto px-2.5 py-2 space-y-1">
        {/* Command Center Header */}
        <AnimatePresence>
          {expanded && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-[9px] font-mono tracking-widest px-3 py-2 uppercase"
              style={{ color: 'var(--text-muted)' }}
            >
              Command Center
            </motion.p>
          )}
        </AnimatePresence>

        {primaryNav.map((item) => (
          <NavItem
            key={item.id}
            item={item}
            isActive={activeModule === item.id}
            expanded={expanded}
            onClick={() => setActiveModule(item.id)}
          />
        ))}

        {/* Divider */}
        <div
          className="h-px my-3 mx-2"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(0,229,255,0.08), transparent)' }}
        />

        {/* Tools Header */}
        <AnimatePresence>
          {expanded && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-[9px] font-mono tracking-widest px-3 py-2 uppercase"
              style={{ color: 'var(--text-muted)' }}
            >
              Tools
            </motion.p>
          )}
        </AnimatePresence>

        {secondaryNav.map((item) => (
          <NavItem
            key={item.id}
            item={item}
            isActive={activeModule === item.id}
            expanded={expanded}
            onClick={() => setActiveModule(item.id)}
          />
        ))}
      </div>

      {/* Backend Status */}
      <div className="p-3 border-t" style={{ borderColor: 'rgba(0,229,255,0.06)' }}>
        <div className="flex items-center gap-3">
          <div className="relative shrink-0">
            <div
              className="w-3 h-3 rounded-full"
              style={{
                background: isOnline
                  ? 'var(--accent-green)'
                  : isOffline
                    ? 'var(--accent-red)'
                    : 'var(--accent-amber)',
                boxShadow: isOnline
                  ? '0 0 8px rgba(0,255,136,0.5)'
                  : isOffline
                    ? '0 0 8px rgba(255,77,109,0.5)'
                    : '0 0 8px rgba(255,176,32,0.5)',
              }}
            />
            {isOnline && (
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{ background: 'var(--accent-green)' }}
                animate={{ scale: [1, 2], opacity: [0.5, 0] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: 'easeOut' }}
              />
            )}
          </div>

          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="min-w-0"
              >
                <p className="text-[9px] font-mono tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>
                  Backend
                </p>
                <p
                  className="text-[11px] font-mono font-bold"
                  style={{
                    color: isOnline
                      ? 'var(--accent-green)'
                      : isOffline
                        ? 'var(--accent-red)'
                        : 'var(--accent-amber)',
                  }}
                >
                  {isOnline ? 'ONLINE' : isOffline ? 'OFFLINE' : 'CONNECTING'}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <button
          onClick={() => {
            localStorage.removeItem('sentinelai_access_token');
            localStorage.removeItem('sentinelai_refresh_token');
            localStorage.removeItem('sentinelai_user');
            window.location.href = '/login';
          }}
          className="mt-2 flex items-center gap-2 w-full px-2 py-1.5 rounded-lg text-[10px] font-mono transition-all cursor-pointer"
          style={{ color: 'var(--text-muted)' }}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--accent-red)'; e.currentTarget.style.background = 'rgba(255,77,109,0.06)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent'; }}
        >
          <LogOut className="w-3 h-3 shrink-0" />
          {expanded && <span>Sign Out</span>}
        </button>
      </div>
    </motion.div>
  );
}
