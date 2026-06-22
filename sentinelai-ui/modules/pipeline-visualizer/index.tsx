"use client";
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { getPipelineMetricsAPI } from "@/lib/api";
import GlassCard from "@/components/ui/GlassCard";
import {
  Database, Filter, Shield, Brain, Link, Bell, AlertTriangle,
  FileText, ArrowRight, Activity, Layers
} from "lucide-react";

const STAGE_ICONS: Record<string, any> = {
  database: Database,
  filter: Filter,
  shield: Shield,
  brain: Brain,
  link: Link,
  bell: Bell,
  "alert-triangle": AlertTriangle,
  "file-text": FileText,
};

interface PipelineStage {
  name: string;
  count: number;
  status: "active" | "idle";
  icon: string;
  detail?: string;
}

interface PipelineData {
  stages: PipelineStage[];
  total_logs: number;
  total_events: number;
  total_detections: number;
  total_alerts: number;
  total_incidents: number;
  total_reports: number;
  active_rules: number;
}

export default function PipelineVisualizer() {
  const [pipeline, setPipeline] = useState<PipelineData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const data = await getPipelineMetricsAPI();
      setPipeline(data);
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

  if (loading || !pipeline) {
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

  const maxCount = Math.max(...pipeline.stages.map(s => s.count), 1);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Layers className="w-6 h-6 text-[var(--accent-cyan)]" />
            Detection Pipeline
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Real-time view of the detection and response pipeline
          </p>
        </div>
        <div className="text-xs text-[var(--text-muted)] flex items-center gap-2">
          <Activity className="w-3 h-3 text-green-400" />
          Live — refreshing every 5s
        </div>
      </div>

      {/* Pipeline Flow */}
      <GlassCard className="p-6 overflow-x-auto">
        <div className="flex items-center gap-2 min-w-max py-2">
          {pipeline.stages.map((stage, idx) => {
            const Icon = STAGE_ICONS[stage.icon] || Shield;
            const intensity = stage.count / maxCount;
            const isActive = stage.status === "active";

            return (
              <div key={stage.name} className="flex items-center gap-2">
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: idx * 0.1 }}
                  className={`relative flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
                    isActive
                      ? "bg-[var(--accent-cyan)]/5 border-[var(--accent-cyan)]/20"
                      : "bg-[var(--bg-deep)]/20 border-[var(--accent-cyan)]/5"
                  }`}
                  style={{ minWidth: "120px" }}
                >
                  {/* Pulse for active */}
                  {isActive && (
                    <motion.div
                      className="absolute -top-1 -right-1 w-3 h-3 bg-green-400 rounded-full"
                      animate={{ scale: [1, 1.3, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  )}

                  <div className={`p-2 rounded-lg ${
                    isActive ? "bg-[var(--accent-cyan)]/10" : "bg-[var(--bg-deep)]/30"
                  }`}>
                    <Icon className={`w-5 h-5 ${
                      isActive ? "text-[var(--accent-cyan)]" : "text-[var(--text-muted)]"
                    }`} />
                  </div>

                  <div className="text-center">
                    <p className="text-xs font-medium text-[var(--text-primary)]">{stage.name}</p>
                    <motion.p
                      className="text-xl font-bold text-[var(--accent-cyan)]"
                      key={stage.count}
                      initial={{ scale: 1.2 }}
                      animate={{ scale: 1 }}
                    >
                      {stage.count.toLocaleString()}
                    </motion.p>
                    {stage.detail && (
                      <p className="text-[10px] text-[var(--text-muted)]">{stage.detail}</p>
                    )}
                  </div>

                  {/* Activity bar */}
                  <div className="w-full h-1 bg-[var(--bg-deep)]/50 rounded-full overflow-hidden">
                    <motion.div
                      className={`h-full rounded-full ${
                        isActive ? "bg-[var(--accent-cyan)]" : "bg-[var(--text-muted)]/20"
                      }`}
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.max(intensity * 100, isActive ? 20 : 0)}%` }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </motion.div>

                {idx < pipeline.stages.length - 1 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: idx * 0.1 + 0.05 }}
                  >
                    <ArrowRight className={`w-5 h-5 ${
                      isActive ? "text-[var(--accent-cyan)]/50" : "text-[var(--text-muted)]/20"
                    }`} />
                  </motion.div>
                )}
              </div>
            );
          })}
        </div>
      </GlassCard>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Logs", value: pipeline.total_logs, icon: Database, color: "cyan" },
          { label: "Total Events", value: pipeline.total_events, icon: Activity, color: "green" },
          { label: "Active Rules", value: pipeline.active_rules, icon: Shield, color: "amber" },
          { label: "Reports Generated", value: pipeline.total_reports, icon: FileText, color: "purple" },
        ].map((stat) => (
          <GlassCard key={stat.label} className="p-4">
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs text-[var(--text-muted)]">{stat.label}</p>
              <stat.icon className={`w-4 h-4 text-[var(--accent-${stat.color})]/50`} />
            </div>
            <p className="text-2xl font-bold text-[var(--text-primary)]">{stat.value.toLocaleString()}</p>
          </GlassCard>
        ))}
      </div>

      {/* Flow Description */}
      <GlassCard className="p-5">
        <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">How the Pipeline Works</h3>
        <div className="grid grid-cols-4 gap-4 text-xs text-[var(--text-muted)]">
          {[
            { stage: "1. Collection", desc: "Sentinel Agents collect logs from Windows, Linux, and network devices via streaming API" },
            { stage: "2. Normalization", desc: "Events are normalized into a canonical schema (NormalizedEvent) with 40+ event types" },
            { stage: "3. Detection", desc: "YAML rules engine + ML prediction + anomaly detection identify threats in real-time" },
            { stage: "4. Response", desc: "Alerts are created, incidents correlated, and SOC analysts notified via WebSocket" },
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
