"use client";

import { useState, useCallback, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Server,
  Activity,
  Clock,
  Cpu,
  HardDrive,
  Zap,
  BarChart3,
} from "lucide-react";
import { useSystemStore } from "@/stores/systemStore";
import { runIntegrityChecks, getOverallHealth, type IntegrityCheck } from "@/services/dataIntegrity.service";
import { systemMonitor, type SystemMetrics } from "@/services/systemMonitor";
import Explanation from "@/components/ui/Explanation";

export default function SystemHealth() {
  const [checks, setChecks] = useState<IntegrityCheck[]>(() => runIntegrityChecks());
  const [lastRun, setLastRun] = useState<Date>(() => new Date());
  const [running, setRunning] = useState(false);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);

  const backendStatus = useSystemStore((s) => s.backendStatus);
  const apiLatency = useSystemStore((s) => s.apiLatency);
  const lastHealthCheck = useSystemStore((s) => s.lastHealthCheck);
  const connectionErrors = useSystemStore((s) => s.connectionErrors);

  useEffect(() => {
    const unsub = systemMonitor.onMetricsUpdate(setMetrics);
    return unsub;
  }, []);

  const runChecks = useCallback(() => {
    setRunning(true);
    const results = runIntegrityChecks();
    setChecks(results);
    setLastRun(new Date());
    setTimeout(() => setRunning(false), 500);
  }, []);

  const overallHealth = getOverallHealth(checks);

  const statusColor = overallHealth === "healthy" ? "var(--accent-green)"
    : overallHealth === "degraded" ? "var(--accent-amber)"
    : "var(--accent-red)";

  const formatTime = (d: Date) => d.toLocaleTimeString("en-US", { hour12: false });

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          System Diagnostics
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          System Health
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Verify all system components are operational and data is trustworthy.
        </p>
      </motion.div>

      <Explanation text="This page verifies that all backend services are reachable, stores are synchronized, and data integrity checks pass. Use this as a debugging tool when something appears wrong." />

      {/* Overall Status */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="rounded-2xl p-6"
        style={{
          background: "rgba(8,20,32,0.7)",
          backdropFilter: "blur(24px)",
          border: `1px solid ${statusColor}30`,
          boxShadow: `0 0 30px ${statusColor}10`,
        }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center"
              style={{
                background: `${statusColor}15`,
                border: `1px solid ${statusColor}30`,
              }}
            >
              <Shield className="w-6 h-6" style={{ color: statusColor }} />
            </div>
            <div>
              <p className="text-sm font-bold" style={{ color: statusColor }}>
                System {overallHealth === "healthy" ? "Operational" : overallHealth === "degraded" ? "Degraded" : "Critical"}
              </p>
              <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                {checks.filter((c) => c.status === "healthy").length}/{checks.length} checks passing
                <span suppressHydrationWarning> — Last run: {formatTime(lastRun)}</span>
              </p>
            </div>
          </div>
          <button
            onClick={runChecks}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 text-xs font-mono font-bold rounded-xl transition-all duration-300 disabled:opacity-50"
            style={{
              background: "rgba(0,229,255,0.1)",
              border: "1px solid rgba(0,229,255,0.2)",
              color: "var(--accent-cyan)",
            }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${running ? "animate-spin" : ""}`} />
            Re-check
          </button>
        </div>
      </motion.div>

      {/* Real-Time System Metrics */}
      {metrics && (
        <div className="rounded-2xl p-5" style={{ background: "rgba(8,20,32,0.7)", backdropFilter: "blur(24px)", border: "1px solid rgba(0,229,255,0.08)" }}>
          <p className="text-[10px] font-mono tracking-[0.2em] uppercase mb-4" style={{ color: "var(--accent-cyan)" }}>
            Real-Time Metrics (2s refresh)
          </p>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { label: "Throughput", value: `${metrics.predictionThroughput}/min`, icon: Zap, color: "var(--accent-cyan)" },
              { label: "Avg Response", value: `${metrics.avgResponseTime.toFixed(1)}ms`, icon: Clock, color: metrics.avgResponseTime < 100 ? "var(--accent-green)" : "var(--accent-amber)" },
              { label: "Memory", value: metrics.memoryUsage ? `${metrics.memoryUsage.toFixed(0)}MB` : "N/A", icon: HardDrive, color: "var(--accent-green)" },
              { label: "Uptime", value: `${Math.floor(metrics.systemUptime / 60)}m`, icon: Activity, color: "var(--accent-green)" },
              { label: "Queue Size", value: String(metrics.predictionQueueSize), icon: BarChart3, color: "var(--accent-purple)" },
              { label: "API Latency", value: `${metrics.apiLatency}ms`, icon: Cpu, color: metrics.apiLatency < 100 ? "var(--accent-green)" : "var(--accent-amber)" },
              { label: "Last API Call", value: metrics.lastApiCall ? new Date(metrics.lastApiCall).toLocaleTimeString("en-US", { hour12: false }) : "Never", icon: Server, color: "var(--accent-cyan)" },
              { label: "Backend", value: metrics.backendHealth.toUpperCase(), icon: Shield, color: metrics.backendHealth === "online" ? "var(--accent-green)" : "var(--accent-red)" },
            ].map((item) => (
              <div key={item.label} className="rounded-xl p-3" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)" }}>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <item.icon className="w-3 h-3" style={{ color: item.color }} />
                  <span className="text-[9px] font-mono tracking-wider uppercase" style={{ color: "var(--text-muted)" }}>{item.label}</span>
                </div>
                <p className="text-sm font-display font-bold" style={{ color: item.color }}>{item.value}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Backend Info */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Backend Status", value: backendStatus.toUpperCase(), icon: Server, color: backendStatus === "online" ? "var(--accent-green)" : "var(--accent-red)" },
          { label: "API Latency", value: `${apiLatency}ms`, icon: Clock, color: apiLatency < 100 ? "var(--accent-green)" : apiLatency < 500 ? "var(--accent-amber)" : "var(--accent-red)" },
          { label: "Connection Errors", value: String(connectionErrors), icon: AlertTriangle, color: connectionErrors === 0 ? "var(--accent-green)" : "var(--accent-red)" },
          { label: "Last Health Check", value: lastHealthCheck ? formatTime(new Date(lastHealthCheck)) : "Never", icon: Activity, color: "var(--accent-cyan)" },
        ].map((item) => (
          <div key={item.label} className="rounded-xl p-4" style={{ background: "rgba(8,20,32,0.7)", border: "1px solid rgba(0,229,255,0.08)" }}>
            <div className="flex items-center gap-2 mb-2">
              <item.icon className="w-3.5 h-3.5" style={{ color: item.color }} />
              <span className="text-[10px] font-mono tracking-wider uppercase" style={{ color: "var(--text-muted)" }}>{item.label}</span>
            </div>
            <p className="text-lg font-display font-bold" style={{ color: item.color }}>{item.value}</p>
          </div>
        ))}
      </div>

      {/* Integrity Checks */}
      <div className="rounded-2xl overflow-hidden" style={{ background: "rgba(8,20,32,0.7)", backdropFilter: "blur(24px)", border: "1px solid rgba(0,229,255,0.08)" }}>
        <div className="flex items-center gap-2.5 px-5 py-3.5 border-b" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
          <Shield className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
            Data Integrity Checks
          </h3>
        </div>
        <div className="divide-y" style={{ borderColor: "rgba(0,229,255,0.04)" }}>
          {checks.map((check) => (
            <div key={check.name} className="flex items-center gap-4 px-5 py-4">
              <div className="shrink-0">
                {check.status === "healthy" ? (
                  <CheckCircle2 className="w-5 h-5" style={{ color: "var(--accent-green)" }} />
                ) : check.status === "warning" ? (
                  <AlertTriangle className="w-5 h-5" style={{ color: "var(--accent-amber)" }} />
                ) : (
                  <XCircle className="w-5 h-5" style={{ color: "var(--accent-red)" }} />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{check.name}</p>
                <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>{check.message}</p>
              </div>
              <span
                className="text-[10px] font-mono font-bold px-2 py-0.5 rounded shrink-0 uppercase"
                style={{
                  background: check.status === "healthy" ? "rgba(0,255,136,0.1)" : check.status === "warning" ? "rgba(255,176,32,0.1)" : "rgba(255,77,109,0.1)",
                  color: check.status === "healthy" ? "var(--accent-green)" : check.status === "warning" ? "var(--accent-amber)" : "var(--accent-red)",
                }}
              >
                {check.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
