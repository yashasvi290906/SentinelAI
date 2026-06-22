"use client";
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { getSecurityMetricsAPI, getAttackHeatmapAPI } from "@/lib/api";
import GlassCard from "@/components/ui/GlassCard";
import {
  Activity, Shield, AlertTriangle, Clock, Server, TrendingUp,
  TrendingDown, Zap, Target, Users, BarChart3
} from "lucide-react";

interface SecurityMetrics {
  aps: number;
  eps: number;
  trend_percent: number;
  total_detections: number;
  total_alerts: number;
  total_incidents: number;
  open_alerts: number;
  closed_alerts: number;
  open_incidents: number;
  closed_incidents: number;
  mttd_minutes: number;
  mttr_minutes: number;
  severity_breakdown: Record<string, number>;
  attack_distribution: Record<string, number>;
  connected_agents: number;
  total_agents: number;
  threat_score: { score: number };
}

interface HeatmapData {
  hourly: number[];
  daily: number[];
  grid: number[][];
  day_labels: string[];
  hour_labels: string[];
  total: number;
}

export default function SecurityMetrics() {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [m, h] = await Promise.all([getSecurityMetricsAPI(), getAttackHeatmapAPI()]);
      setMetrics(m);
      setHeatmap(h);
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading || !metrics) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">Security Metrics</h1>
        <div className="grid grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => (
            <GlassCard key={i} className="p-4 animate-pulse">
              <div className="h-4 bg-[var(--accent-cyan)]/10 rounded w-20 mb-2" />
              <div className="h-8 bg-[var(--accent-cyan)]/5 rounded w-16" />
            </GlassCard>
          ))}
        </div>
      </div>
    );
  }

  const maxHeatmapVal = Math.max(...(heatmap?.hourly || [1]), 1);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-[var(--accent-cyan)]" />
            Security Metrics
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Real-time security posture and operational metrics
          </p>
        </div>
        <div className="text-xs text-[var(--text-muted)]">
          Auto-refresh: 10s
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Attacks/sec", value: metrics.aps, icon: Zap, color: "cyan", trend: metrics.trend_percent },
          { label: "Open Alerts", value: metrics.open_alerts, icon: AlertTriangle, color: "amber" },
          { label: "Open Incidents", value: metrics.open_incidents, icon: Target, color: "red" },
          { label: "Threat Score", value: `${metrics.threat_score.score}`, icon: Shield, color: "purple" },
        ].map((kpi) => (
          <motion.div key={kpi.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
            <GlassCard className="p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-[var(--text-muted)]">{kpi.label}</p>
                <kpi.icon className={`w-4 h-4 text-[var(--accent-${kpi.color})]/50`} />
              </div>
              <div className="flex items-end gap-2">
                <p className="text-3xl font-bold text-[var(--text-primary)]">{kpi.value}</p>
                {kpi.trend !== undefined && (
                  <span className={`text-xs mb-1 flex items-center gap-0.5 ${
                    kpi.trend >= 0 ? "text-red-400" : "text-green-400"
                  }`}>
                    {kpi.trend >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                    {Math.abs(kpi.trend)}%
                  </span>
                )}
              </div>
            </GlassCard>
          </motion.div>
        ))}
      </div>

      {/* Second Row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "MTTD", value: `${metrics.mttd_minutes}m`, sub: "Mean Time to Detect", icon: Clock },
          { label: "MTTR", value: `${metrics.mttr_minutes}m`, sub: "Mean Time to Respond", icon: Clock },
          { label: "Connected Agents", value: `${metrics.connected_agents}/${metrics.total_agents}`, sub: "Online/Total", icon: Server },
          { label: "Total Detections", value: metrics.total_detections, sub: "All time", icon: Shield },
        ].map((kpi) => (
          <GlassCard key={kpi.label} className="p-4">
            <div className="flex items-center gap-2 mb-1">
              <kpi.icon className="w-4 h-4 text-[var(--accent-cyan)]/50" />
              <p className="text-xs text-[var(--text-muted)]">{kpi.label}</p>
            </div>
            <p className="text-2xl font-bold text-[var(--text-primary)]">{kpi.value}</p>
            <p className="text-xs text-[var(--text-muted)]">{kpi.sub}</p>
          </GlassCard>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <GlassCard className="p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">Severity Breakdown</h3>
          <div className="space-y-3">
            {Object.entries(metrics.severity_breakdown).map(([sev, count]) => {
              const max = Math.max(...Object.values(metrics.severity_breakdown), 1);
              const pct = (count / max) * 100;
              const colors: Record<string, string> = {
                CRITICAL: "bg-red-500", HIGH: "bg-orange-500", MEDIUM: "bg-amber-500", LOW: "bg-cyan-500"
              };
              return (
                <div key={sev}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-[var(--text-muted)]">{sev}</span>
                    <span className="text-[var(--text-primary)] font-medium">{count}</span>
                  </div>
                  <div className="h-2 bg-[var(--bg-deep)]/50 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      className={`h-full ${colors[sev] || "bg-slate-500"} rounded-full`}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </GlassCard>

        {/* Attack Distribution */}
        <GlassCard className="p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">Attack Distribution</h3>
          <div className="space-y-3">
            {Object.entries(metrics.attack_distribution).slice(0, 6).map(([type, count]) => {
              const max = Math.max(...Object.values(metrics.attack_distribution), 1);
              const pct = (count / max) * 100;
              return (
                <div key={type}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-[var(--text-muted)]">{type}</span>
                    <span className="text-[var(--text-primary)] font-medium">{count}</span>
                  </div>
                  <div className="h-2 bg-[var(--bg-deep)]/50 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      className="h-full bg-[var(--accent-cyan)] rounded-full"
                      transition={{ duration: 0.8, ease: "easeOut" }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </GlassCard>
      </div>

      {/* Attack Heatmap */}
      {heatmap && (
        <GlassCard className="p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">
            Attack Heatmap <span className="text-[var(--text-muted)] font-normal">(hourly distribution)</span>
          </h3>
          <div className="overflow-x-auto">
            <div className="inline-flex flex-col gap-1">
              {heatmap.grid.map((row, dayIdx) => (
                <div key={dayIdx} className="flex items-center gap-1">
                  <span className="w-8 text-xs text-[var(--text-muted)]">{heatmap.day_labels[dayIdx]}</span>
                  {row.map((val, hourIdx) => {
                    const intensity = val / maxHeatmapVal;
                    const bg = val === 0
                      ? "bg-[var(--bg-deep)]/30"
                      : intensity < 0.25
                        ? "bg-cyan-900/40"
                        : intensity < 0.5
                          ? "bg-cyan-700/50"
                          : intensity < 0.75
                            ? "bg-cyan-500/60"
                            : "bg-cyan-400/80";
                    return (
                      <div
                        key={hourIdx}
                        className={`w-5 h-5 rounded-sm ${bg} transition-colors`}
                        title={`${heatmap.day_labels[dayIdx]} ${heatmap.hour_labels[hourIdx]}:00 — ${val} attacks`}
                      />
                    );
                  })}
                </div>
              ))}
              <div className="flex items-center gap-1 ml-9">
                {heatmap.hour_labels.filter((_, i) => i % 4 === 0).map((h) => (
                  <span key={h} className="text-[10px] text-[var(--text-muted)]" style={{ width: `${4 * 22}px` }}>
                    {h}:00
                  </span>
                ))}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3 text-xs text-[var(--text-muted)]">
            <span>Less</span>
            <div className="flex gap-0.5">
              {["bg-[var(--bg-deep)]/30", "bg-cyan-900/40", "bg-cyan-700/50", "bg-cyan-500/60", "bg-cyan-400/80"].map((c, i) => (
                <div key={i} className={`w-3 h-3 rounded-sm ${c}`} />
              ))}
            </div>
            <span>More</span>
            <span className="ml-2">({heatmap.total} total events)</span>
          </div>
        </GlassCard>
      )}
    </div>
  );
}
