"use client";
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";
import {
  Database, Filter, Shield, Brain, Link, Bell, AlertTriangle,
  FileText, ArrowRight, Activity, Layers, Clock, Search,
  GitBranch, Zap, Eye, XCircle, CheckCircle
} from "lucide-react";

const PIPELINE_STAGES = [
  { key: "ingested", label: "Ingested", icon: Database, color: "cyan" },
  { key: "parsed", label: "Parsed", icon: Filter, color: "blue" },
  { key: "normalized", label: "Normalized", icon: GitBranch, color: "indigo" },
  { key: "ml_detected", label: "ML Detection", icon: Brain, color: "purple" },
  { key: "rule_matched", label: "Rule Match", icon: Shield, color: "amber" },
  { key: "sigma_matched", label: "Sigma Match", icon: Shield, color: "orange" },
  { key: "ioc_matched", label: "IOC Match", icon: AlertTriangle, color: "red" },
  { key: "alert_created", label: "Alert", icon: Bell, color: "pink" },
  { key: "correlated", label: "Correlated", icon: Link, color: "emerald" },
  { key: "incident_created", label: "Incident", icon: FileText, color: "red" },
  { key: "notified", label: "Notified", icon: Zap, color: "yellow" },
];

interface StageMetric {
  stage: string;
  total: number;
  succeeded: number;
  failed: number;
  avg_latency: number;
  max_latency: number;
}

interface PipelineSummary {
  [key: string]: { count: number; avg_latency_ms: number };
}

interface EventTrace {
  event_id: string;
  stage_count: number;
  stages: {
    id: string;
    stage: string;
    status: string;
    entered_at: string;
    completed_at: string;
    latency_ms: number;
    details: string;
  }[];
}

export default function PipelineVisualizer() {
  const [summary, setSummary] = useState<PipelineSummary | null>(null);
  const [metrics, setMetrics] = useState<StageMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [traceId, setTraceId] = useState("");
  const [eventTrace, setEventTrace] = useState<EventTrace | null>(null);
  const [tracing, setTracing] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [sumRes, metRes] = await Promise.all([
        fetch("/api/pipeline/summary"),
        fetch("/api/pipeline/metrics"),
      ]);
      const sumData = await sumRes.json();
      const metData = await metRes.json();
      setSummary(sumData);
      setMetrics(metData.metrics || []);
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const traceEvent = async () => {
    if (!traceId.trim()) return;
    setTracing(true);
    try {
      const res = await fetch(`/api/pipeline/event/${traceId}`);
      if (res.ok) {
        const data = await res.json();
        setEventTrace(data);
      } else {
        setEventTrace(null);
      }
    } catch {
      setEventTrace(null);
    }
    setTracing(false);
  };

  const maxCount = Math.max(...PIPELINE_STAGES.map(s => (summary as any)?.[s.key]?.count || 0), 1);

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">Detection Pipeline</h1>
        <GlassCard className="p-12 animate-pulse">
          <div className="flex items-center justify-center gap-4">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="flex items-center gap-4">
                <div className="w-20 h-20 bg-[var(--accent-cyan)]/5 rounded-xl" />
                {i < 7 && <ArrowRight className="w-5 h-5 text-[var(--accent-cyan)]/10" />}
              </div>
            ))}
          </div>
        </GlassCard>
      </div>
    );
  }

  const totalEvents = PIPELINE_STAGES.reduce((sum, s) => sum + ((summary as any)?.[s.key]?.count || 0), 0);
  const totalFailed = metrics.reduce((sum, m) => sum + (m.failed || 0), 0);
  const avgLatency = metrics.length > 0 ? metrics.reduce((sum, m) => sum + (m.avg_latency || 0), 0) / metrics.length : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Layers className="w-6 h-6 text-[var(--accent-cyan)]" />
            Detection Pipeline
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Per-event tracking from ingestion through notification
          </p>
        </div>
        <div className="text-xs text-[var(--text-muted)] flex items-center gap-2">
          <Activity className="w-3 h-3 text-green-400" />
          Live — refreshing every 5s
        </div>
      </div>

      {/* Pipeline Flow */}
      <GlassCard className="p-6 overflow-x-auto">
        <div className="flex items-center gap-1 min-w-max py-2">
          {PIPELINE_STAGES.map((stage, idx) => {
            const count = (summary as any)?.[stage.key]?.count || 0;
            const latency = (summary as any)?.[stage.key]?.avg_latency_ms || 0;
            const intensity = count / maxCount;
            const isActive = count > 0;
            const Icon = stage.icon;

            return (
              <div key={stage.key} className="flex items-center gap-1">
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: idx * 0.05 }}
                  className={`relative flex flex-col items-center gap-1.5 p-3 rounded-xl border transition-all ${
                    isActive
                      ? `bg-[var(--accent-${stage.color})]/5 border-[var(--accent-${stage.color})]/20`
                      : "bg-[var(--bg-deep)]/20 border-[var(--accent-cyan)]/5"
                  }`}
                  style={{ minWidth: "100px" }}
                >
                  {isActive && (
                    <motion.div
                      className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-green-400 rounded-full"
                      animate={{ scale: [1, 1.3, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  )}

                  <div className={`p-1.5 rounded-lg ${
                    isActive ? `bg-[var(--accent-${stage.color})]/10` : "bg-[var(--bg-deep)]/30"
                  }`}>
                    <Icon className={`w-4 h-4 ${
                      isActive ? `text-[var(--accent-${stage.color})]` : "text-[var(--text-muted)]"
                    }`} />
                  </div>

                  <div className="text-center">
                    <p className="text-[10px] font-medium text-[var(--text-primary)]">{stage.label}</p>
                    <motion.p
                      className={`text-lg font-bold ${isActive ? `text-[var(--accent-${stage.color})]` : "text-[var(--text-muted)]"}`}
                      key={count}
                      initial={{ scale: 1.2 }}
                      animate={{ scale: 1 }}
                    >
                      {count.toLocaleString()}
                    </motion.p>
                    {latency > 0 && (
                      <p className="text-[9px] text-[var(--text-muted)] font-mono">{latency.toFixed(1)}ms</p>
                    )}
                  </div>

                  <div className="w-full h-0.5 bg-[var(--bg-deep)]/50 rounded-full overflow-hidden">
                    <motion.div
                      className={`h-full rounded-full bg-[var(--accent-${stage.color})]`}
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.max(intensity * 100, isActive ? 15 : 0)}%` }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </motion.div>

                {idx < PIPELINE_STAGES.length - 1 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: idx * 0.05 + 0.03 }}
                  >
                    <ArrowRight className={`w-4 h-4 ${
                      isActive ? "text-[var(--accent-cyan)]/40" : "text-[var(--text-muted)]/15"
                    }`} />
                  </motion.div>
                )}
              </div>
            );
          })}
        </div>
      </GlassCard>

      {/* Summary Cards */}
      <div className="grid grid-cols-5 gap-4">
        <GlassCard className="p-4">
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs text-[var(--text-muted)]">Total Events</p>
            <Database className="w-4 h-4 text-cyan-400/50" />
          </div>
          <p className="text-2xl font-bold text-[var(--text-primary)]">{totalEvents.toLocaleString()}</p>
        </GlassCard>
        <GlassCard className="p-4">
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs text-[var(--text-muted)]">Failed</p>
            <XCircle className="w-4 h-4 text-red-400/50" />
          </div>
          <p className="text-2xl font-bold text-red-400">{totalFailed}</p>
        </GlassCard>
        <GlassCard className="p-4">
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs text-[var(--text-muted)]">Avg Latency</p>
            <Clock className="w-4 h-4 text-emerald-400/50" />
          </div>
          <p className="text-2xl font-bold text-emerald-400">{avgLatency.toFixed(1)}<span className="text-sm text-[var(--text-muted)]">ms</span></p>
        </GlassCard>
        <GlassCard className="p-4">
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs text-[var(--text-muted)]">Alerts</p>
            <Bell className="w-4 h-4 text-pink-400/50" />
          </div>
          <p className="text-2xl font-bold text-pink-400">{(summary as any)?.alert_created?.count || 0}</p>
        </GlassCard>
        <GlassCard className="p-4">
          <div className="flex items-center justify-between mb-1">
            <p className="text-xs text-[var(--text-muted)]">Incidents</p>
            <FileText className="w-4 h-4 text-red-400/50" />
          </div>
          <p className="text-2xl font-bold text-red-400">{(summary as any)?.incident_created?.count || 0}</p>
        </GlassCard>
      </div>

      {/* Event Trace */}
      <GlassCard className="p-5">
        <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3 flex items-center gap-2">
          <Search className="w-4 h-4 text-cyan-400" />
          Event Lineage Trace
        </h3>
        <div className="flex gap-2 mb-4">
          <input type="text" value={traceId} onChange={e => setTraceId(e.target.value)}
            placeholder="Enter event ID to trace through pipeline..."
            className="flex-1 bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white/70 outline-none focus:border-cyan-400/50 font-mono"
            onKeyDown={e => e.key === 'Enter' && traceEvent()} />
          <button onClick={traceEvent} disabled={tracing || !traceId.trim()}
            className="px-4 py-2 bg-cyan-500/20 border border-cyan-400/30 rounded text-cyan-400 text-sm hover:bg-cyan-500/30 disabled:opacity-50">
            {tracing ? 'Tracing...' : 'Trace'}
          </button>
        </div>
        {eventTrace && (
          <div className="space-y-2">
            <p className="text-xs text-[var(--text-muted)] mb-2">
              Event <span className="font-mono text-cyan-400">{eventTrace.event_id}</span> — {eventTrace.stage_count} stages
            </p>
            <div className="flex items-center gap-1 flex-wrap">
              {eventTrace.stages.map((stage, idx) => {
                const stageConfig = PIPELINE_STAGES.find(s => s.key === stage.stage);
                const isCompleted = stage.status === 'completed';
                return (
                  <div key={stage.id} className="flex items-center gap-1">
                    <div className={`px-2 py-1 rounded text-[10px] border ${
                      isCompleted
                        ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                        : 'bg-red-500/10 border-red-500/20 text-red-400'
                    }`}>
                      <span className="font-medium">{stageConfig?.label || stage.stage}</span>
                      {stage.latency_ms > 0 && (
                        <span className="ml-1 text-white/30">{stage.latency_ms.toFixed(1)}ms</span>
                      )}
                    </div>
                    {idx < eventTrace.stages.length - 1 && (
                      <ArrowRight className="w-3 h-3 text-white/20" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {!eventTrace && !tracing && (
          <p className="text-xs text-white/30">Enter an event ID to trace its journey through the detection pipeline</p>
        )}
      </GlassCard>

      {/* Stage Detail Table */}
      {metrics.length > 0 && (
        <GlassCard className="p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">Stage Performance</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[var(--text-muted)] border-b border-white/5">
                  <th className="text-left py-2 px-3">Stage</th>
                  <th className="text-right py-2 px-3">Total</th>
                  <th className="text-right py-2 px-3">Succeeded</th>
                  <th className="text-right py-2 px-3">Failed</th>
                  <th className="text-right py-2 px-3">Avg Latency</th>
                  <th className="text-right py-2 px-3">Max Latency</th>
                  <th className="text-right py-2 px-3">Success %</th>
                </tr>
              </thead>
              <tbody>
                {metrics.map(m => {
                  const stageConfig = PIPELINE_STAGES.find(s => s.key === m.stage);
                  const successRate = m.total > 0 ? ((m.succeeded / m.total) * 100) : 0;
                  return (
                    <tr key={m.stage} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                      <td className="py-2 px-3 font-medium text-[var(--text-primary)]">
                        {stageConfig?.label || m.stage}
                      </td>
                      <td className="py-2 px-3 text-right font-mono">{m.total}</td>
                      <td className="py-2 px-3 text-right font-mono text-emerald-400">{m.succeeded}</td>
                      <td className="py-2 px-3 text-right font-mono text-red-400">{m.failed}</td>
                      <td className="py-2 px-3 text-right font-mono">{(m.avg_latency || 0).toFixed(1)}ms</td>
                      <td className="py-2 px-3 text-right font-mono">{(m.max_latency || 0).toFixed(1)}ms</td>
                      <td className="py-2 px-3 text-right">
                        <span className={`font-mono ${successRate >= 95 ? 'text-emerald-400' : successRate >= 80 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {successRate.toFixed(1)}%
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </GlassCard>
      )}

      {/* Flow Description */}
      <GlassCard className="p-5">
        <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">How the Pipeline Works</h3>
        <div className="grid grid-cols-4 gap-4 text-xs text-[var(--text-muted)]">
          {[
            { stage: "1. Ingest", desc: "Logs received via file upload or streaming API from Windows, Linux, Suricata, and Zeek agents" },
            { stage: "2. Parse & Normalize", desc: "Multi-format parser extracts events, normalizer converts to canonical schema with 40+ event types" },
            { stage: "3. Detect", desc: "ML threat detection, YAML rules, Sigma rules, and IOC matching run in parallel to identify threats" },
            { stage: "4. Correlate & Respond", desc: "Alerts correlated into incidents, SOC analysts notified via WebSocket, evidence collected" },
          ].map((step) => (
            <div key={step.stage} className="p-3 rounded-lg bg-[var(--bg-deep)]/30">
              <p className="font-medium text-[var(--text-primary)] mb-1">{step.stage}</p>
              <p>{step.desc}</p>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
