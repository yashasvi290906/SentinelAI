"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassPanel from "@/components/ui/GlassPanel";
import { useSystemStore } from "@/stores/systemStore";
import { usePredictionStore } from "@/stores/predictionStore";
import { useEventStore } from "@/stores/eventStore";
import { healthCheck } from "@/lib/api";
import { API_BASE_URL } from "@/lib/config";
import {
  Settings as SettingsIcon, Server, Brain, Bell, Plug,
  CheckCircle2, XCircle, Loader2, Save, RotateCcw,
  Monitor, Shield, Globe,
  Eye, Activity, Download, FileText,
  Palette, Zap, Database,
} from "lucide-react";

type TabId = "general" | "backend" | "models" | "notifications" | "export" | "about";

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
}

const TABS: Tab[] = [
  { id: "general", label: "General", icon: <SettingsIcon className="w-4 h-4" /> },
  { id: "backend", label: "Backend", icon: <Server className="w-4 h-4" /> },
  { id: "models", label: "Models", icon: <Brain className="w-4 h-4" /> },
  { id: "notifications", label: "Notifications", icon: <Bell className="w-4 h-4" /> },
  { id: "export", label: "Export", icon: <Download className="w-4 h-4" /> },
  { id: "about", label: "About", icon: <Monitor className="w-4 h-4" /> },
];

const THEMES = [
  { id: "cyber-blue", name: "Cyber Blue", accent: "var(--accent-cyan)" },
  { id: "emerald-matrix", name: "Emerald Matrix", accent: "var(--accent-green)" },
  { id: "purple-pulse", name: "Purple Pulse", accent: "var(--accent-purple)" },
  { id: "red-alert", name: "Red Alert", accent: "var(--accent-red)" },
] as const;

const MODELS = [
  { id: "ensemble", label: "Ensemble (ML + Markov)" },
  { id: "xgboost", label: "XGBoost" },
  { id: "random_forest", label: "Random Forest" },
  { id: "markov", label: "Markov Chain" },
];

const container = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const item = {
  hidden: { opacity: 0, y: 10 },
  show: { opacity: 1, y: 0 },
};

interface SettingsState {
  theme: string;
  accentColor: string;
  animationSpeed: number;
  compactMode: boolean;
  uiAnimations: boolean;
  apiUrl: string;
  healthPollingInterval: number;
  apiTimeout: number;
  retryAttempts: number;
  defaultModel: string;
  predictionHistorySize: number;
  confidenceThreshold: number;
  browserAlerts: boolean;
  soundAlerts: boolean;
  emailAlerts: boolean;
}

const DEFAULT_SETTINGS: SettingsState = {
  theme: "cyber-blue",
  accentColor: "var(--accent-cyan)",
  animationSpeed: 100,
  compactMode: false,
  uiAnimations: true,
  apiUrl: API_BASE_URL,
  healthPollingInterval: 10,
  apiTimeout: 10000,
  retryAttempts: 3,
  defaultModel: "ensemble",
  predictionHistorySize: 100,
  confidenceThreshold: 70,
  browserAlerts: true,
  soundAlerts: false,
  emailAlerts: false,
};

function Toggle({
  enabled,
  onToggle,
  label,
  description,
}: {
  enabled: boolean;
  onToggle: () => void;
  label: string;
  description: string;
}) {
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] hover:border-[var(--accent-cyan)]/20 transition-all duration-300">
      <div className="flex items-center gap-3">
        <div>
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{label}</p>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>{description}</p>
        </div>
      </div>
      <button
        onClick={onToggle}
        className={`relative w-12 h-6 rounded-full transition-all duration-300 ${
          enabled ? "bg-[var(--accent-cyan)]/30 shadow-[0_0_12px_rgba(0,229,255,0.3)]" : "bg-white/10"
        }`}
      >
        <motion.div
          className={`absolute top-0.5 w-5 h-5 rounded-full transition-colors ${
            enabled ? "bg-[var(--accent-cyan)]" : "bg-gray-400"
          }`}
          animate={{ x: enabled ? 24 : 0 }}
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
        />
      </button>
    </div>
  );
}

function Slider({
  value,
  onChange,
  min,
  max,
  step = 1,
  label,
  description,
  unit = "",
  minLabel,
  maxLabel,
}: {
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
  label: string;
  description: string;
  unit?: string;
  minLabel?: string;
  maxLabel?: string;
}) {
  return (
    <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] hover:border-[var(--accent-cyan)]/20 transition-all duration-300">
      <div className="flex items-center justify-between mb-3">
        <div>
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{label}</p>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>{description}</p>
        </div>
        <span className="text-lg font-bold font-mono tabular-nums" style={{ color: "var(--accent-cyan)" }}>
          {value}{unit}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full h-1.5 bg-white/10 rounded-full appearance-none cursor-pointer
                   [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4
                   [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[var(--accent-cyan)]
                   [&::-webkit-slider-thumb]:shadow-[0_0_10px_rgba(0,229,255,0.5)]
                   [&::-webkit-slider-thumb]:cursor-pointer"
      />
      <div className="flex justify-between mt-1.5">
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{minLabel ?? min}</span>
        <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{maxLabel ?? max}</span>
      </div>
    </div>
  );
}

function ExportButton({
  label,
  icon,
  onClick,
  variant = "default",
}: {
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
  variant?: "default" | "danger";
}) {
  const colors = variant === "danger"
    ? { border: "var(--accent-red)", bg: "var(--accent-red)" }
    : { border: "var(--accent-cyan)", bg: "var(--accent-cyan)" };
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-mono font-bold transition-all duration-300 hover:scale-[1.02]"
      style={{
        color: colors.bg,
        border: `1px solid ${colors.border}30`,
        background: `${colors.bg}10`,
      }}
    >
      {icon}
      {label}
    </button>
  );
}

export default function Settings() {
  const [activeTab, setActiveTab] = useState<TabId>("general");
  const [settings, setSettings] = useState<SettingsState>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("sentinelai-settings");
      if (saved) {
        try {
          return { ...DEFAULT_SETTINGS, ...JSON.parse(saved) };
        } catch {
          // ignore malformed settings
        }
      }
    }
    return DEFAULT_SETTINGS;
  });
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectionResult, setConnectionResult] = useState<"success" | "error" | null>(null);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");

  const backendStatus = useSystemStore((s) => s.backendStatus);
  const apiLatency = useSystemStore((s) => s.apiLatency);

  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const compareHistory = usePredictionStore((s) => s.compareHistory);
  const events = useEventStore((s) => s.events);

  const update = useCallback(<K extends keyof SettingsState>(key: K, value: SettingsState[K]) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }, []);

  const handleSave = useCallback(() => {
    setSaveStatus("saving");
    localStorage.setItem("sentinelai-settings", JSON.stringify(settings));
    setTimeout(() => {
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus("idle"), 2000);
    }, 300);
  }, [settings]);

  const handleReset = useCallback(() => {
    setSettings(DEFAULT_SETTINGS);
    localStorage.removeItem("sentinelai-settings");
  }, []);

  const handleTestConnection = useCallback(async () => {
    setIsConnecting(true);
    setConnectionResult(null);
    try {
      const ok = await healthCheck();
      setConnectionResult(ok ? "success" : "error");
    } catch {
      setConnectionResult("error");
    } finally {
      setIsConnecting(false);
    }
  }, []);

  const handleExportLogs = useCallback(() => {
    const data = events.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      type: e.type,
      message: e.message,
      details: e.details,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-logs-${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [events]);

  const handleExportPredictions = useCallback(() => {
    const data = predictionHistory.map((p) => ({
      id: p.id,
      timestamp: p.timestamp,
      predictedAttack: p.predictedAttack,
      confidence: p.confidence,
      riskLevel: p.riskLevel,
      model: p.model,
      sequence: p.sequence,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-predictions-${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [predictionHistory]);

  const handleExportSettings = useCallback(() => {
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-settings-${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [settings]);

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="px-6 pt-6 pb-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-xs font-mono tracking-[0.2em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
            System Configuration
          </p>
          <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>Settings</h1>
          <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
            Configure your SentinelAI security operations center
          </p>
        </motion.div>
      </div>

      <div className="px-6 pb-4">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="flex gap-1 p-1 bg-white/[0.03] border border-white/[0.06] rounded-xl overflow-x-auto"
        >
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all duration-300 ${
                activeTab === tab.id
                  ? "bg-[var(--accent-cyan)]/10"
                  : "hover:bg-white/[0.04]"
              }`}
              style={{ color: activeTab === tab.id ? "var(--accent-cyan)" : "var(--text-muted)" }}
            >
              {activeTab === tab.id && (
                <motion.div
                  layoutId="settingsActiveTab"
                  className="absolute inset-0 rounded-lg bg-[var(--accent-cyan)]/10 border border-[var(--accent-cyan)]/20"
                  style={{ boxShadow: "0 0 15px rgba(0,229,255,0.1)" }}
                  transition={{ type: "spring", stiffness: 380, damping: 30 }}
                />
              )}
              <span className="relative z-10 flex items-center gap-2">
                {tab.icon}
                {tab.label}
              </span>
            </button>
          ))}
        </motion.div>
      </div>

      <div className="flex-1 overflow-y-auto px-6 pb-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            transition={{ duration: 0.3 }}
          >
            {/* ═══ GENERAL ═══ */}
            {activeTab === "general" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="Theme" icon={<Palette className="w-4 h-4" />}>
                    <div className="space-y-4">
                      <div>
                        <p className="text-sm font-medium mb-3" style={{ color: "var(--text-primary)" }}>Theme Preset</p>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                          {THEMES.map((t) => (
                            <button
                              key={t.id}
                              onClick={() => update("theme", t.id)}
                              className={`p-4 rounded-xl border text-left transition-all duration-300 ${
                                settings.theme === t.id
                                  ? "border-[var(--accent-cyan)]/30"
                                  : "border-white/[0.06] hover:border-white/20"
                              }`}
                              style={{
                                background: settings.theme === t.id ? `${t.accent}10` : "rgba(255,255,255,0.03)",
                              }}
                            >
                              <div className="w-full h-3 rounded-full mb-3" style={{ background: t.accent, opacity: 0.6 }} />
                              <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{t.name}</p>
                              <p className="text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
                                {settings.theme === t.id ? "Active" : "Click to apply"}
                              </p>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium mb-3" style={{ color: "var(--text-primary)" }}>Accent Color</p>
                        <div className="flex gap-3">
                          {[
                            { var: "var(--accent-cyan)", label: "Cyan" },
                            { var: "var(--accent-green)", label: "Green" },
                            { var: "var(--accent-purple)", label: "Purple" },
                            { var: "var(--accent-red)", label: "Red" },
                            { var: "var(--accent-amber)", label: "Amber" },
                          ].map((c) => (
                            <button
                              key={c.var}
                              onClick={() => update("accentColor", c.var)}
                              className="flex flex-col items-center gap-2 p-3 rounded-xl border transition-all duration-300"
                              style={{
                                borderColor: settings.accentColor === c.var ? "var(--accent-cyan)" : "rgba(255,255,255,0.06)",
                                background: settings.accentColor === c.var ? "rgba(0,229,255,0.1)" : "rgba(255,255,255,0.03)",
                              }}
                            >
                              <div className="w-8 h-8 rounded-full" style={{ background: c.var }} />
                              <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{c.label}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Appearance" icon={<Eye className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <Slider
                        value={settings.animationSpeed}
                        onChange={(v) => update("animationSpeed", v)}
                        min={50}
                        max={200}
                        label="Animation Speed"
                        description="Control the speed of UI animations"
                        unit="%"
                        minLabel="Slow"
                        maxLabel="Fast"
                      />
                      <Toggle
                        enabled={settings.compactMode}
                        onToggle={() => update("compactMode", !settings.compactMode)}
                        label="Compact Mode"
                        description="Reduce padding and spacing throughout the UI"
                      />
                      <Toggle
                        enabled={settings.uiAnimations}
                        onToggle={() => update("uiAnimations", !settings.uiAnimations)}
                        label="UI Animations"
                        description="Enable motion effects and transitions"
                      />
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Data Summary" icon={<Database className="w-4 h-4" />}>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {[
                        { label: "Predictions", value: predictionHistory.length, color: "var(--accent-cyan)" },
                        { label: "Comparisons", value: compareHistory.length, color: "var(--accent-green)" },
                        { label: "Events", value: events.length, color: "var(--accent-amber)" },
                        { label: "Status", value: backendStatus.toUpperCase(), color: backendStatus === "online" ? "var(--accent-green)" : "var(--accent-red)" },
                      ].map((stat) => (
                        <div key={stat.label} className="text-center p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                          <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>{stat.label}</p>
                          <p className="text-sm font-bold font-mono" style={{ color: stat.color }}>{stat.value}</p>
                        </div>
                      ))}
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}

            {/* ═══ BACKEND ═══ */}
            {activeTab === "backend" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="API Connection" icon={<Server className="w-4 h-4" />}>
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] uppercase tracking-widest block mb-2" style={{ color: "var(--text-muted)" }}>
                          API Base URL
                        </label>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            value={settings.apiUrl}
                            onChange={(e) => update("apiUrl", e.target.value)}
                            className="flex-1 bg-white/[0.05] border border-white/[0.1] rounded-xl px-4 py-2.5 text-sm font-mono focus:border-[var(--accent-cyan)]/50 outline-none transition-all"
                            style={{ color: "var(--accent-cyan)" }}
                          />
                          <button
                            onClick={handleTestConnection}
                            disabled={isConnecting}
                            className="px-5 py-2.5 rounded-xl text-xs font-bold transition-all disabled:opacity-50 flex items-center gap-2"
                            style={{
                              background: "rgba(0,229,255,0.2)",
                              border: "1px solid rgba(0,229,255,0.3)",
                              color: "var(--accent-cyan)",
                            }}
                          >
                            {isConnecting ? (
                              <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                              <Globe className="w-4 h-4" />
                            )}
                            {isConnecting ? "Testing..." : "Test Connection"}
                          </button>
                        </div>
                      </div>

                      {connectionResult && (
                        <motion.div
                          initial={{ opacity: 0, y: -10 }}
                          animate={{ opacity: 1, y: 0 }}
                          className={`flex items-center gap-3 p-4 rounded-xl border ${
                            connectionResult === "success"
                              ? "border-[var(--accent-green)]/30 bg-[var(--accent-green)]/10"
                              : "border-[var(--accent-red)]/30 bg-[var(--accent-red)]/10"
                          }`}
                        >
                          {connectionResult === "success" ? (
                            <CheckCircle2 className="w-5 h-5" style={{ color: "var(--accent-green)" }} />
                          ) : (
                            <XCircle className="w-5 h-5" style={{ color: "var(--accent-red)" }} />
                          )}
                          <div>
                            <p className="text-sm font-bold" style={{ color: connectionResult === "success" ? "var(--accent-green)" : "var(--accent-red)" }}>
                              {connectionResult === "success" ? "Connection Successful" : "Connection Failed"}
                            </p>
                            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                              {connectionResult === "success"
                                ? `Backend is online. Latency: ${apiLatency}ms`
                                : "Unable to reach the backend. Check the URL and try again."}
                            </p>
                          </div>
                        </motion.div>
                      )}

                      <div className="flex items-center justify-between p-4 rounded-xl border"
                        style={{
                          borderColor: backendStatus === "online" ? "rgba(0,229,255,0.15)" : "rgba(255,59,59,0.15)",
                          background: backendStatus === "online" ? "rgba(0,229,255,0.05)" : "rgba(255,59,59,0.05)",
                        }}
                      >
                        <div className="flex items-center gap-3">
                          {backendStatus === "online" ? (
                            <CheckCircle2 className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
                          ) : backendStatus === "offline" ? (
                            <XCircle className="w-4 h-4" style={{ color: "var(--accent-red)" }} />
                          ) : (
                            <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--accent-amber)" }} />
                          )}
                          <div>
                            <p className="text-xs" style={{ color: "var(--text-muted)" }}>Connection Status</p>
                            <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                              {backendStatus === "online" ? "CONNECTED" : backendStatus === "offline" ? "DISCONNECTED" : "CHECKING..."}
                            </p>
                          </div>
                        </div>
                        <div className="w-2.5 h-2.5 rounded-full" style={{
                          background: backendStatus === "online" ? "var(--accent-green)" : backendStatus === "offline" ? "var(--accent-red)" : "var(--accent-amber)",
                          boxShadow: backendStatus === "online" ? "0 0 8px var(--accent-green)" : "none",
                        }} />
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Connection Settings" icon={<Plug className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <Slider
                        value={settings.healthPollingInterval}
                        onChange={(v) => update("healthPollingInterval", v)}
                        min={5}
                        max={60}
                        label="Health Polling Interval"
                        description="How often to check backend health"
                        unit="s"
                        minLabel="5s"
                        maxLabel="60s"
                      />
                      <Slider
                        value={settings.apiTimeout}
                        onChange={(v) => update("apiTimeout", v)}
                        min={3000}
                        max={30000}
                        step={1000}
                        label="Request Timeout"
                        description="Maximum time to wait for API responses"
                        unit="ms"
                        minLabel="3s"
                        maxLabel="30s"
                      />
                      <Slider
                        value={settings.retryAttempts}
                        onChange={(v) => update("retryAttempts", v)}
                        min={0}
                        max={10}
                        label="Retry Attempts"
                        description="Number of retry attempts for failed API calls"
                        unit="x"
                        minLabel="0"
                        maxLabel="10"
                      />
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="API Endpoints" icon={<Globe className="w-4 h-4" />}>
                    <div className="space-y-2">
                      {[
                        { method: "GET", path: "/", desc: "Health Check" },
                        { method: "POST", path: "/predict", desc: "ML Prediction" },
                        { method: "POST", path: "/compare", desc: "Model Comparison" },
                        { method: "POST", path: "/drift", desc: "Drift Detection" },
                      ].map((endpoint) => (
                        <div
                          key={endpoint.path}
                          className="flex items-center gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/[0.06] hover:border-[var(--accent-cyan)]/20 transition-all duration-300"
                        >
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            endpoint.method === "GET"
                              ? "bg-[var(--accent-green)]/10"
                              : "bg-[var(--accent-cyan)]/10"
                          }`}
                          style={{ color: endpoint.method === "GET" ? "var(--accent-green)" : "var(--accent-cyan)" }}
                          >
                            {endpoint.method}
                          </span>
                          <span className="text-sm font-mono flex-1" style={{ color: "var(--text-primary)" }}>{endpoint.path}</span>
                          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{endpoint.desc}</span>
                        </div>
                      ))}
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}

            {/* ═══ MODELS ═══ */}
            {activeTab === "models" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="Model Configuration" icon={<Brain className="w-4 h-4" />}>
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] uppercase tracking-widest block mb-2" style={{ color: "var(--text-muted)" }}>
                          Default Model
                        </label>
                        <div className="grid grid-cols-2 gap-3">
                          {MODELS.map((model) => (
                            <button
                              key={model.id}
                              onClick={() => update("defaultModel", model.id)}
                              className="p-3 rounded-xl border text-left transition-all duration-300"
                              style={{
                                borderColor: settings.defaultModel === model.id ? "rgba(0,229,255,0.3)" : "rgba(255,255,255,0.06)",
                                background: settings.defaultModel === model.id ? "rgba(0,229,255,0.1)" : "rgba(255,255,255,0.03)",
                              }}
                            >
                              <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{model.label}</p>
                              {settings.defaultModel === model.id && (
                                <p className="text-[10px] mt-1" style={{ color: "var(--accent-cyan)" }}>Selected</p>
                              )}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Prediction Parameters" icon={<Zap className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <Slider
                        value={settings.predictionHistorySize}
                        onChange={(v) => update("predictionHistorySize", v)}
                        min={10}
                        max={500}
                        step={10}
                        label="Prediction History Size"
                        description="Maximum number of predictions to retain in history"
                        unit=""
                        minLabel="10"
                        maxLabel="500"
                      />
                      <Slider
                        value={settings.confidenceThreshold}
                        onChange={(v) => update("confidenceThreshold", v)}
                        min={0}
                        max={100}
                        step={5}
                        label="Confidence Threshold"
                        description="Minimum confidence to display predictions"
                        unit="%"
                        minLabel="0%"
                        maxLabel="100%"
                      />
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Model Performance" icon={<Activity className="w-4 h-4" />}>
                    <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle2 className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
                        <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Real-Time Metrics</p>
                      </div>
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                        Model performance metrics are calculated from actual prediction and comparison data stored in the application state.
                      </p>
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}

            {/* ═══ NOTIFICATIONS ═══ */}
            {activeTab === "notifications" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="Alert Preferences" icon={<Bell className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <Toggle
                        enabled={settings.browserAlerts}
                        onToggle={() => update("browserAlerts", !settings.browserAlerts)}
                        label="Browser Alerts"
                        description="Show browser notifications for critical events"
                      />
                      <Toggle
                        enabled={settings.soundAlerts}
                        onToggle={() => update("soundAlerts", !settings.soundAlerts)}
                        label="Sound Alerts"
                        description="Play sound on critical alerts"
                      />
                      <Toggle
                        enabled={settings.emailAlerts}
                        onToggle={() => update("emailAlerts", !settings.emailAlerts)}
                        label="Email Alerts"
                        description="Send email notifications for critical security events"
                      />
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="Notification Levels" icon={<Shield className="w-4 h-4" />}>
                    <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                        Notification preferences are saved locally. Email and sound integrations require backend configuration.
                      </p>
                      <div className="space-y-2">
                        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => (
                          <div key={level} className="flex items-center justify-between p-2 rounded-lg bg-white/[0.02]">
                            <span className="text-xs font-mono font-bold" style={{
                              color: level === "CRITICAL" ? "var(--accent-red)"
                                : level === "HIGH" ? "var(--accent-amber)"
                                : level === "MEDIUM" ? "var(--accent-cyan)"
                                : "var(--accent-green)"
                            }}>
                              {level}
                            </span>
                            <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                              {level === "CRITICAL" || level === "HIGH" ? "Enabled" : "Disabled"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}

            {/* ═══ EXPORT ═══ */}
            {activeTab === "export" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="Export Data" icon={<Download className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Export Event Logs</p>
                            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                              {events.length} events recorded this session
                            </p>
                          </div>
                          <ExportButton
                            label="Export Logs"
                            icon={<FileText className="w-3.5 h-3.5" />}
                            onClick={handleExportLogs}
                          />
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Export Predictions</p>
                            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                              {predictionHistory.length} predictions in history
                            </p>
                          </div>
                          <ExportButton
                            label="Export Predictions"
                            icon={<Zap className="w-3.5 h-3.5" />}
                            onClick={handleExportPredictions}
                          />
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Export Settings</p>
                            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                              Download current configuration as JSON
                            </p>
                          </div>
                          <ExportButton
                            label="Export Settings"
                            icon={<SettingsIcon className="w-3.5 h-3.5" />}
                            onClick={handleExportSettings}
                          />
                        </div>
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}

            {/* ═══ ABOUT ═══ */}
            {activeTab === "about" && (
              <motion.div variants={container} initial="hidden" animate="show" className="space-y-4">
                <motion.div variants={item}>
                  <GlassPanel title="Version Information" icon={<Monitor className="w-4 h-4" />}>
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] text-center">
                          <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>Version</p>
                          <p className="text-lg font-bold font-mono" style={{ color: "var(--accent-cyan)" }}>1.0.0</p>
                        </div>
                        <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] text-center">
                          <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>Build Date</p>
                          <p className="text-sm font-mono" style={{ color: "var(--text-primary)" }}>
                            2026-06-20
                          </p>
                        </div>
                        <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] text-center">
                          <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>Platform</p>
                          <p className="text-sm font-mono" style={{ color: "var(--text-primary)" }}>SentinelAI</p>
                        </div>
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>

                <motion.div variants={item}>
                  <GlassPanel title="About SentinelAI" icon={<Shield className="w-4 h-4" />}>
                    <div className="space-y-4">
                      <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                        SentinelAI is an AI-powered cybersecurity prediction platform that uses machine learning
                        and statistical models to detect, classify, and forecast network attack patterns in real-time.
                      </p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                          <h4 className="text-xs font-bold uppercase tracking-widest mb-2" style={{ color: "var(--accent-cyan)" }}>Frontend</h4>
                          <ul className="space-y-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                            <li>Next.js + React</li>
                            <li>TypeScript</li>
                            <li>Zustand State Management</li>
                            <li>Recharts Visualization</li>
                            <li>Framer Motion Animations</li>
                            <li>Tailwind CSS</li>
                          </ul>
                        </div>
                        <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                          <h4 className="text-xs font-bold uppercase tracking-widest mb-2" style={{ color: "var(--accent-green)" }}>Backend</h4>
                          <ul className="space-y-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                            <li>FastAPI (Python)</li>
                            <li>Scikit-learn ML Models</li>
                            <li>Pandas Data Processing</li>
                            <li>NumPy Computing</li>
                            <li>Uvicorn ASGI Server</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </GlassPanel>
                </motion.div>
              </motion.div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="px-6 py-4 border-t" style={{ borderColor: "rgba(0,229,255,0.06)", background: "rgba(8,20,32,0.8)", backdropFilter: "blur(24px)" }}>
        <div className="flex items-center justify-between">
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-mono border border-white/[0.1] hover:border-white/20 transition-all"
            style={{ color: "var(--text-muted)" }}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset to Defaults
          </button>
          <div className="flex items-center gap-3">
            <AnimatePresence>
              {saveStatus === "saved" && (
                <motion.span
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="text-xs font-mono"
                  style={{ color: "var(--accent-green)" }}
                >
                  Saved successfully
                </motion.span>
              )}
            </AnimatePresence>
            <button
              onClick={handleSave}
              disabled={saveStatus === "saving"}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl text-xs font-bold transition-all duration-300 disabled:opacity-50"
              style={{
                background: "var(--accent-cyan)",
                color: "var(--bg-deep)",
                boxShadow: "0 0 20px rgba(0,229,255,0.3)",
              }}
            >
              {saveStatus === "saving" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Save className="w-3.5 h-3.5" />
              )}
              {saveStatus === "saving" ? "Saving..." : "Save Changes"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
