"use client";

import { useMemo, useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useAnalyticsStore, type DashboardMetrics } from "@/stores/analyticsStore";
import { useSystemStore } from "@/stores/systemStore";
import { usePredictionStore } from "@/stores/predictionStore";
import { useEventStore } from "@/stores/eventStore";
import { statsAPI, type SystemStats } from "@/lib/api";
import {
  Shield,
  HeartPulse,
  Brain,
  GitCompareArrows,
  BarChart3,
  Activity,
  Clock,
  AlertTriangle,
  Flame,
  TrendingUp,
  TrendingDown,
  Minus,
  type LucideIcon,
  Zap,
  Globe,
  Radar,
  Maximize2,
  Minimize2,
} from "lucide-react";
import Provenance from "@/components/ui/Provenance";
import Explanation from "@/components/ui/Explanation";
import GlassCard from "@/components/ui/GlassCard";
import { geoMercator } from "d3-geo";

/* ─── animation variants ────────────────────────────────────── */
const stagger = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.07 } },
};

/* ─── empty state ───────────────────────────────────────────── */
function EmptyState({ message = "No data available" }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full min-h-[80px] gap-2">
      <Minus className="w-5 h-5" style={{ color: "var(--text-muted)" }} />
      <p className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
        {message}
      </p>
    </div>
  );
}

/* ─── card label ────────────────────────────────────────────── */
function CardLabel({ icon: Icon, children }: { icon: LucideIcon; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2.5 mb-4">
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{
          background: "rgba(0,229,255,0.08)",
          border: "1px solid rgba(0,229,255,0.15)",
        }}
      >
        <Icon className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
      </div>
      <p
        className="text-[10px] font-mono tracking-[0.2em] uppercase"
        style={{ color: "var(--text-muted)" }}
      >
        {children}
      </p>
    </div>
  );
}

/* ─── metric row ────────────────────────────────────────────── */
function MetricRow({
  label,
  value,
  color = "var(--text-primary)",
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
        {label}
      </span>
      <span className="text-sm font-mono font-semibold" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 1 — Threat Score                                        */
/* ═══════════════════════════════════════════════════════════════ */
function ThreatScoreCard({ metrics }: { metrics: DashboardMetrics }) {
  const score = metrics.threatScore;
  const breakdown = metrics.threatBreakdown;
  const hasData = score > 0;
  const color =
    score > 70 ? "var(--accent-red)" : score > 40 ? "var(--accent-amber)" : "var(--accent-green)";
  const label = score > 70 ? "HIGH RISK" : score > 40 ? "ELEVATED" : "SECURE";

  return (
    <GlassCard>
      <CardLabel icon={Shield}>Threat Score</CardLabel>
      {!hasData ? (
        <EmptyState message="No data" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-4">
            <div className="relative w-20 h-20">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(0,229,255,0.06)" strokeWidth="6" />
                <circle
                  cx="60" cy="60" r="52" fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
                  strokeDasharray={`${(score / 100) * 327} 327`}
                  style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: "stroke-dasharray 0.8s ease" }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-display font-bold" style={{ color }}>{score}</span>
                <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>/100</span>
              </div>
            </div>
            <div className="flex-1">
              <span className="text-[10px] font-mono font-bold tracking-widest" style={{ color }}>{label}</span>
              <div className="mt-2 space-y-1">
                <MetricRow label="Confidence" value={`+${breakdown.confidence_contribution}`} color="var(--accent-cyan)" />
                <MetricRow label="Critical Alerts" value={`+${breakdown.critical_alerts}`} color="var(--accent-red)" />
                <MetricRow label="Model Conflict" value={`+${breakdown.model_conflict}`} color="var(--accent-amber)" />
                <MetricRow label="Drift" value={`+${breakdown.drift_impact}`} color="var(--accent-purple)" />
              </div>
            </div>
          </div>
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 2 — Backend Health                                      */
/* ═══════════════════════════════════════════════════════════════ */
function BackendHealthCard() {
  const status = useSystemStore((s) => s.backendStatus);
  const lastCheck = useSystemStore((s) => s.lastHealthCheck);
  const latency = useSystemStore((s) => s.apiLatency);

  const isOnline = status === "online";
  const dotColor = isOnline ? "var(--accent-green)" : status === "connecting" ? "var(--accent-amber)" : "var(--accent-red)";
  const statusText = isOnline ? "ONLINE" : status === "connecting" ? "CONNECTING" : "OFFLINE";

  return (
    <GlassCard>
      <CardLabel icon={HeartPulse}>Backend Health</CardLabel>
      <div className="flex items-center gap-3 mb-4">
        <span className="relative flex h-3 w-3 shrink-0">
          {isOnline && (
            <span
              className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"
              style={{ background: dotColor }}
            />
          )}
          <span className="relative inline-flex h-3 w-3 rounded-full" style={{ background: dotColor }} />
        </span>
        <span className="text-sm font-mono font-bold" style={{ color: dotColor }}>
          {statusText}
        </span>
      </div>
      <div className="space-y-2">
        <MetricRow
          label="Last Check"
          value={lastCheck ? new Date(lastCheck).toLocaleTimeString("en-US", { hour12: false }) : "—"}
        />
        <MetricRow
          label="API Latency"
          value={latency > 0 ? `${latency}ms` : "—"}
          color={latency > 500 ? "var(--accent-red)" : latency > 200 ? "var(--accent-amber)" : "var(--accent-green)"}
        />
      </div>
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 3 — Latest Prediction                                  */
/* ═══════════════════════════════════════════════════════════════ */
function LatestPredictionCard({ metrics }: { metrics: DashboardMetrics }) {
  const hasData = metrics.latestPrediction !== "None";
  const riskColors: Record<string, string> = {
    CRITICAL: "var(--accent-red)",
    HIGH: "var(--accent-amber)",
    MEDIUM: "var(--accent-cyan)",
    LOW: "var(--accent-green)",
  };

  return (
    <GlassCard>
      <CardLabel icon={Brain}>Latest Prediction</CardLabel>
      {!hasData ? (
        <EmptyState message="No predictions yet" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
              style={{
                background: "rgba(128,0,255,0.1)",
                border: "1px solid rgba(128,0,255,0.2)",
              }}
            >
              <Brain className="w-5 h-5" style={{ color: "var(--accent-purple)" }} />
            </div>
            <div>
              <p className="text-sm font-mono font-bold" style={{ color: "var(--text-primary)" }}>
                {metrics.latestPrediction}
              </p>
              <div className="flex items-center gap-3">
                <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                  {(metrics.latestConfidence * 100).toFixed(1)}%
                </p>
                {metrics.latestSeverityScore > 0 && (
                  <p className="text-[10px] font-mono" style={{ color: metrics.latestSeverityScore >= 75 ? "var(--accent-red)" : metrics.latestSeverityScore >= 55 ? "var(--accent-amber)" : "var(--accent-cyan)" }}>
                    SEV: {metrics.latestSeverityScore}
                  </p>
                )}
                {metrics.latestLatency > 0 && (
                  <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                    {metrics.latestLatency}ms
                  </p>
                )}
              </div>
            </div>
          </div>
          {/* Confidence bar */}
          <div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
              <motion.div
                className="h-full rounded-full"
                style={{ background: "var(--accent-cyan)" }}
                initial={{ width: 0 }}
                animate={{ width: `${metrics.latestConfidence * 100}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
          </div>
          {/* Risk badge */}
          {metrics.recentPredictions[0] && (
            <span
              className="inline-block px-2.5 py-1 rounded-full text-[10px] font-mono font-bold tracking-wider"
              style={{
                background: `${riskColors[metrics.recentPredictions[0].riskLevel] || "var(--text-muted)"}15`,
                color: riskColors[metrics.recentPredictions[0].riskLevel] || "var(--text-muted)",
                border: `1px solid ${riskColors[metrics.recentPredictions[0].riskLevel] || "var(--text-muted)"}30`,
              }}
            >
              {metrics.recentPredictions[0].riskLevel}
            </span>
          )}
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 4 — Model Agreement                                     */
/* ═══════════════════════════════════════════════════════════════ */
function ModelAgreementCard({ metrics }: { metrics: DashboardMetrics }) {
  const compareHistory = usePredictionStore((s) => s.compareHistory);
  const totalCompares = compareHistory.length;
  const hasData = totalCompares > 0;
  const lastCompare = compareHistory[0];
  const agreementColor =
    metrics.modelAgreement >= 80 ? "var(--accent-green)" : metrics.modelAgreement >= 50 ? "var(--accent-amber)" : "var(--accent-red)";

  return (
    <GlassCard>
      <CardLabel icon={GitCompareArrows}>Model Agreement</CardLabel>
      {!hasData ? (
        <EmptyState message="No comparisons yet" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-end gap-2">
            <span className="text-3xl font-display font-bold" style={{ color: agreementColor }}>
              {metrics.modelAgreement}%
            </span>
            <span className="text-[10px] font-mono mb-1" style={{ color: "var(--text-muted)" }}>
              agreement
            </span>
          </div>
          <div className="space-y-2">
            <MetricRow label="Comparisons" value={totalCompares} />
            <MetricRow
              label="Last Result"
              value={lastCompare ? (lastCompare.modelsAgree ? "AGREE" : "CONFLICT") : "—"}
              color={lastCompare ? (lastCompare.modelsAgree ? "var(--accent-green)" : "var(--accent-red)") : "var(--text-muted)"}
            />
          </div>
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 5 — Prediction Volume                                   */
/* ═══════════════════════════════════════════════════════════════ */
function PredictionVolumeCard({ metrics }: { metrics: DashboardMetrics }) {
  const total = metrics.predictionVolume;
  const hasData = total > 0;
  const confidenceTrend = metrics.confidenceTrend;

  let trendDirection: "up" | "down" | "flat" = "flat";
  if (confidenceTrend.length >= 2) {
    const recent = confidenceTrend.slice(-5);
    const firstHalf = recent.slice(0, Math.floor(recent.length / 2));
    const secondHalf = recent.slice(Math.floor(recent.length / 2));
    const avgFirst = firstHalf.reduce((s, e) => s + e.confidence, 0) / (firstHalf.length || 1);
    const avgSecond = secondHalf.reduce((s, e) => s + e.confidence, 0) / (secondHalf.length || 1);
    if (avgSecond > avgFirst + 2) trendDirection = "up";
    else if (avgSecond < avgFirst - 2) trendDirection = "down";
  }

  const TrendIcon = trendDirection === "up" ? TrendingUp : trendDirection === "down" ? TrendingDown : Minus;
  const trendColor =
    trendDirection === "up" ? "var(--accent-green)" : trendDirection === "down" ? "var(--accent-red)" : "var(--text-muted)";

  return (
    <GlassCard>
      <CardLabel icon={BarChart3}>Prediction Volume</CardLabel>
      {!hasData ? (
        <EmptyState message="No predictions yet" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
              {total}
            </span>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full" style={{ background: `${trendColor}12` }}>
              <TrendIcon className="w-3 h-3" style={{ color: trendColor }} />
              <span className="text-[10px] font-mono font-bold" style={{ color: trendColor }}>
                {trendDirection === "up" ? "Rising" : trendDirection === "down" ? "Falling" : "Stable"}
              </span>
            </div>
          </div>
          <MetricRow label="Total Events" value={metrics.totalEvents} />
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 6 — Drift Status                                        */
/* ═══════════════════════════════════════════════════════════════ */
function DriftStatusCard({ metrics }: { metrics: DashboardMetrics }) {
  const driftHistory = usePredictionStore((s) => s.driftHistory);
  const hasData = driftHistory.length > 0;
  const latestDrift = driftHistory[0];
  const driftScore = latestDrift ? Math.round(latestDrift.score * 100) : 0;
  const status = latestDrift?.status || metrics.driftStatus;

  const statusConfig: Record<string, { color: string; label: string; bg: string }> = {
    stable: { color: "var(--accent-green)", label: "STABLE", bg: "rgba(0,255,136,0.08)" },
    warning: { color: "var(--accent-amber)", label: "WARNING", bg: "rgba(255,176,32,0.08)" },
    critical: { color: "var(--accent-red)", label: "CRITICAL", bg: "rgba(255,77,109,0.08)" },
  };
  const cfg = statusConfig[status] || statusConfig.stable;

  return (
    <GlassCard>
      <CardLabel icon={Activity}>Drift Status</CardLabel>
      {!hasData ? (
        <EmptyState message="No drift data" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-2xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
              {driftScore}%
            </span>
            <span
              className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold tracking-wider"
              style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}30` }}
            >
              {cfg.label}
            </span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
            <motion.div
              className="h-full rounded-full"
              style={{ background: cfg.color }}
              initial={{ width: 0 }}
              animate={{ width: `${driftScore}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          </div>
          <MetricRow
            label="Status"
            value={cfg.label}
            color={cfg.color}
          />
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 7 — API Latency                                         */
/* ═══════════════════════════════════════════════════════════════ */
function ApiLatencyCard() {
  const latency = useSystemStore((s) => s.apiLatency);
  const hasData = latency > 0;

  const indicatorColor =
    latency > 500 ? "var(--accent-red)" : latency > 200 ? "var(--accent-amber)" : "var(--accent-green)";
  const indicatorLabel =
    latency > 500 ? "Slow" : latency > 200 ? "Moderate" : "Fast";

  return (
    <GlassCard>
      <CardLabel icon={Clock}>API Latency</CardLabel>
      {!hasData ? (
        <EmptyState message="No latency data" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-end gap-2">
            <span className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
              {latency}
            </span>
            <span className="text-sm font-mono mb-1" style={{ color: "var(--text-muted)" }}>
              ms
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="relative flex h-2 w-2 shrink-0"
            >
              <span
                className="absolute inline-flex h-full w-full rounded-full opacity-40"
                style={{ background: indicatorColor }}
              />
              <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: indicatorColor }} />
            </span>
            <span className="text-[10px] font-mono font-bold tracking-wider" style={{ color: indicatorColor }}>
              {indicatorLabel}
            </span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
            <motion.div
              className="h-full rounded-full"
              style={{ background: indicatorColor }}
              initial={{ width: 0 }}
              animate={{ width: `${Math.min((latency / 1000) * 100, 100)}%` }}
              transition={{ duration: 0.6, ease: "easeOut" }}
            />
          </div>
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 8 — Critical Alerts                                     */
/* ═══════════════════════════════════════════════════════════════ */
function CriticalAlertsCard({ metrics }: { metrics: DashboardMetrics }) {
  const total = metrics.criticalAlerts + metrics.highAlerts;
  const hasData = total > 0;

  return (
    <GlassCard>
      <CardLabel icon={AlertTriangle}>Critical Alerts</CardLabel>
      {!hasData ? (
        <EmptyState message="No alerts" />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <p className="text-[10px] font-mono tracking-wider uppercase mb-1" style={{ color: "var(--text-muted)" }}>
                Critical
              </p>
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4" style={{ color: "var(--accent-red)" }} />
                <span className="text-2xl font-display font-bold" style={{ color: "var(--accent-red)" }}>
                  {metrics.criticalAlerts}
                </span>
              </div>
            </div>
            <div className="w-px h-12" style={{ background: "rgba(0,229,255,0.08)" }} />
            <div className="flex-1">
              <p className="text-[10px] font-mono tracking-wider uppercase mb-1" style={{ color: "var(--text-muted)" }}>
                High
              </p>
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" style={{ color: "var(--accent-amber)" }} />
                <span className="text-2xl font-display font-bold" style={{ color: "var(--accent-amber)" }}>
                  {metrics.highAlerts}
                </span>
              </div>
            </div>
          </div>
          <MetricRow label="Total Alerts" value={total} color="var(--accent-red)" />
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 9 — Attack Distribution                                 */
/* ═══════════════════════════════════════════════════════════════ */
function AttackDistributionCard({ metrics }: { metrics: DashboardMetrics }) {
  const entries = Object.entries(metrics.attackDistribution).sort(([, a], [, b]) => b - a);
  const hasData = entries.length > 0;
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  const max = entries[0]?.[1] || 1;

  const colors: Record<string, string> = {
    DDoS: "var(--accent-red)",
    DoS: "var(--accent-amber)",
    PortScan: "var(--accent-cyan)",
    Bot: "var(--accent-purple)",
    WebAttack: "var(--accent-purple)",
    BruteForce: "var(--accent-amber)",
    Infiltration: "var(--accent-red)",
    BENIGN: "var(--accent-green)",
  };

  return (
    <GlassCard>
      <CardLabel icon={BarChart3}>Attack Distribution</CardLabel>
      {!hasData ? (
        <EmptyState message="No attack data yet" />
      ) : (
        <div className="space-y-3">
          {entries.slice(0, 7).map(([attack, count]) => {
            const color = colors[attack] || "var(--accent-cyan)";
            const pct = total > 0 ? (count / total) * 100 : 0;
            return (
              <div key={attack}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-mono" style={{ color: "var(--text-secondary)" }}>
                    {attack}
                  </span>
                  <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                    {count} ({pct.toFixed(0)}%)
                  </span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: color }}
                    initial={{ width: 0 }}
                    animate={{ width: `${(count / max) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 10 — Recent Predictions                                 */
/* ═══════════════════════════════════════════════════════════════ */
function RecentPredictionsCard({ metrics }: { metrics: DashboardMetrics }) {
  const predictions = metrics.recentPredictions;
  const hasData = predictions.length > 0;

  const riskColors: Record<string, string> = {
    CRITICAL: "var(--accent-red)",
    HIGH: "var(--accent-amber)",
    MEDIUM: "var(--accent-cyan)",
    LOW: "var(--accent-green)",
  };

  return (
    <GlassCard>
      <CardLabel icon={Flame}>Recent Predictions</CardLabel>
      {!hasData ? (
        <EmptyState message="Awaiting predictions..." />
      ) : (
        <div className="space-y-2 overflow-y-auto max-h-[340px] pr-1">
          {predictions.slice(0, 5).map((pred, idx) => {
            const color = riskColors[pred.riskLevel] || "var(--text-muted)";
            const time = new Date(pred.timestamp).toLocaleTimeString("en-US", {
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            });
            return (
              <motion.div
                key={pred.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
                className="rounded-xl p-3 transition-all duration-200 hover:bg-white/[0.02]"
                style={{ border: "1px solid rgba(0,229,255,0.06)" }}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className="relative flex h-2 w-2 shrink-0"
                    >
                      <span
                        className="absolute inline-flex h-full w-full rounded-full opacity-40"
                        style={{ background: color }}
                      />
                      <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: color }} />
                    </span>
                    <span
                      className="text-[11px] font-mono font-semibold"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {pred.predictedAttack}
                    </span>
                    <span
                      className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold tracking-wider"
                      style={{
                        background: `${color}12`,
                        color,
                        border: `1px solid ${color}25`,
                      }}
                    >
                      {pred.riskLevel}
                    </span>
                  </div>
                  <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                    {time}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: color }}
                      initial={{ width: 0 }}
                      animate={{ width: `${pred.confidence * 100}%` }}
                      transition={{ duration: 0.6, ease: "easeOut" }}
                    />
                  </div>
                  <span className="text-[9px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                    {(pred.confidence * 100).toFixed(1)}%
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  WORLD ATTACK MAP                                               */
/* ═══════════════════════════════════════════════════════════════ */
const MAP_COUNTRIES: Record<string, { lat: number; lng: number; name: string }> = {
  RU: { lat: 61.52, lng: 105.32, name: "Russia" },
  CN: { lat: 35.86, lng: 104.20, name: "China" },
  KP: { lat: 40.34, lng: 127.51, name: "North Korea" },
  IR: { lat: 32.43, lng: 53.69, name: "Iran" },
  US: { lat: 37.09, lng: -95.71, name: "United States" },
  BR: { lat: -14.24, lng: -51.93, name: "Brazil" },
  VN: { lat: 14.06, lng: 108.28, name: "Vietnam" },
  IN: { lat: 20.59, lng: 78.96, name: "India" },
  DE: { lat: 51.17, lng: 10.45, name: "Germany" },
  GB: { lat: 55.38, lng: -3.44, name: "United Kingdom" },
  JP: { lat: 36.20, lng: 138.25, name: "Japan" },
  KR: { lat: 35.91, lng: 127.77, name: "South Korea" },
  AU: { lat: -25.27, lng: 133.78, name: "Australia" },
  FR: { lat: 46.23, lng: 2.21, name: "France" },
  NL: { lat: 52.13, lng: 5.29, name: "Netherlands" },
};

const SEV_STROKE: Record<string, string> = {
  CRITICAL: "#ff4d6d", HIGH: "#ff9500", MEDIUM: "#00e5ff", LOW: "#00ff88",
};

interface AttackArc {
  id: string;
  srcLng: number; srcLat: number; dstLng: number; dstLat: number;
  srcCountry: string; dstCountry: string;
  srcName: string; dstName: string;
  attack: string; severity: string;
  score: number; time: string;
}

function buildArcs(events: ReturnType<typeof useEventStore.getState>["events"]): AttackArc[] {
  const arcs: AttackArc[] = [];
  events
    .filter((e) => {
      if (!e.details || typeof e.details !== "object") return false;
      const d = e.details as Record<string, unknown>;
      return ("geo" in d) || ("country" in d && "lat" in d);
    })
    .slice(0, 50)
    .forEach((evt) => {
      const d = evt.details as Record<string, unknown>;
      const geo = d.geo as Record<string, unknown> | undefined;
      const destGeo = d.dest_geo as Record<string, unknown> | undefined;

      let srcCountry = "", srcLat = 0, srcLng = 0;
      if (geo) {
        srcCountry = (geo.src_country as string) || "";
        srcLat = geo.src_lat as number;
        srcLng = geo.src_lng as number;
      } else {
        srcCountry = (d.country as string) || "";
        srcLat = d.lat as number;
        srcLng = d.lng as number;
      }

      let dstCountry = "", dstLat = 0, dstLng = 0;
      if (destGeo) {
        dstCountry = (destGeo.dest_country as string) || "";
        dstLat = destGeo.dest_lat as number;
        dstLng = destGeo.dest_lng as number;
      } else {
        dstCountry = "US";
        const dg = MAP_COUNTRIES[dstCountry];
        dstLat = dg.lat; dstLng = dg.lng;
      }

      if (!srcCountry || !srcLat || !srcLng) return;

      const srcInfo = MAP_COUNTRIES[srcCountry];
      if (srcInfo) { srcLat = srcInfo.lat; srcLng = srcInfo.lng; }
      const dstInfo = MAP_COUNTRIES[dstCountry];
      if (dstInfo) { dstLat = dstInfo.lat; dstLng = dstInfo.lng; }

      if (!dstLat || !dstLng) return;

      arcs.push({
        id: evt.id,
        srcLng, srcLat, dstLng, dstLat,
        srcCountry, dstCountry,
        srcName: srcInfo?.name || srcCountry,
        dstName: dstInfo?.name || dstCountry,
        attack: (d.attack_type as string) || "Unknown",
        severity: (d.severity as string) || "MEDIUM",
        score: (d.severity_score as number) || 50,
        time: new Date(evt.timestamp).toLocaleTimeString("en-US", { hour12: false }),
      });
    });
  return arcs;
}

function MapSVG({
  arcs, W, H, projection, expanded,
}: {
  arcs: AttackArc[];
  W: number; H: number;
  projection: ReturnType<typeof geoMercator>;
  expanded: boolean;
}) {
  const [hoveredArc, setHoveredArc] = useState<string | null>(null);

  const gridDots = useMemo(() => {
    const dots: Array<{ x: number; y: number }> = [];
    for (let lat = -70; lat <= 75; lat += expanded ? 6 : 8) {
      for (let lng = -170; lng <= 180; lng += expanded ? 8 : 10) {
        const p = projection([lng, lat]);
        if (p) dots.push({ x: p[0], y: p[1] });
      }
    }
    return dots;
  }, [projection, expanded]);

  const countryDots = useMemo(() => {
    const dots: Array<{ x: number; y: number; code: string; name: string }> = [];
    Object.entries(MAP_COUNTRIES).forEach(([code, c]) => {
      const p = projection([c.lng, c.lat]);
      if (p) dots.push({ x: p[0], y: p[1], code, name: c.name });
    });
    return dots;
  }, [projection]);

  const activeCountries = useMemo(() => {
    const s = new Set<string>();
    arcs.forEach((a) => { s.add(a.srcCountry); s.add(a.dstCountry); });
    return s;
  }, [arcs]);

  const arcPath = useCallback((x1: number, y1: number, x2: number, y2: number) => {
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist === 0) return `M ${x1} ${y1} L ${x2} ${y2}`;
    const bulge = Math.min(dist * 0.2, 70);
    const nx = -dy / dist;
    const ny = dx / dist;
    const cx = mx + nx * bulge;
    const cy = my + ny * bulge;
    return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
  }, []);

  const sevColor = (s: string) => SEV_STROKE[s] || SEV_STROKE.MEDIUM;
  const r = expanded ? 3 : 1;
  const countryR = expanded ? 6 : 4;
  const lineW = expanded ? 2 : 1.5;
  const lineHoverW = expanded ? 3.5 : 2.5;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full">
      <defs>
        <radialGradient id={`mapBg${expanded ? "X" : ""}`} cx="50%" cy="50%" r="60%">
          <stop offset="0%" stopColor="rgba(0,229,255,0.04)" />
          <stop offset="100%" stopColor="rgba(0,0,0,0)" />
        </radialGradient>
        <filter id={`arcGlow${expanded ? "X" : ""}`}>
          <feGaussianBlur stdDeviation={expanded ? 4 : 3} result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id={`dotGlow${expanded ? "X" : ""}`}>
          <feGaussianBlur stdDeviation={expanded ? 3 : 2} result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id={`endGlow${expanded ? "X" : ""}`}>
          <feGaussianBlur stdDeviation={expanded ? 5 : 3} result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <rect width={W} height={H} fill={`url(#mapBg${expanded ? "X" : ""})`} />

      {gridDots.map((d, i) => (
        <circle key={i} cx={d.x} cy={d.y} r={r} fill="rgba(0,229,255,0.07)" />
      ))}

      {countryDots.map((c) => {
        const isActive = activeCountries.has(c.code);
        return (
          <g key={c.code}>
            <circle
              cx={c.x} cy={c.y} r={isActive ? countryR : countryR - 1}
              fill={isActive ? "rgba(0,229,255,0.9)" : "rgba(0,229,255,0.25)"}
              filter={isActive ? `url(#dotGlow${expanded ? "X" : ""})` : undefined}
            />
            {isActive && (
              <circle cx={c.x} cy={c.y} r={countryR} fill="none" stroke="rgba(0,229,255,0.15)" strokeWidth={1}>
                <animate attributeName="r" from={`${countryR}`} to={`${countryR + 8}`} dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.4" to="0" dur="2s" repeatCount="indefinite" />
              </circle>
            )}
            <text
              x={c.x} y={c.y - countryR - 3}
              textAnchor="middle"
              fill={isActive ? "rgba(0,229,255,0.85)" : "rgba(0,229,255,0.2)"}
              fontSize={expanded ? 9 : 7}
              fontFamily="monospace"
              fontWeight={isActive ? 700 : 400}
            >
              {c.name || c.code}
            </text>
          </g>
        );
      })}

      {arcs.map((arc, i) => {
        const sp = projection([arc.srcLng, arc.srcLat]);
        const dp = projection([arc.dstLng, arc.dstLat]);
        if (!sp || !dp) return null;
        const color = sevColor(arc.severity);
        const isHovered = hoveredArc === arc.id;
        const path = arcPath(sp[0], sp[1], dp[0], dp[1]);
        const endR = expanded ? 5 : 3.5;

        return (
          <g
            key={arc.id}
            onMouseEnter={() => setHoveredArc(arc.id)}
            onMouseLeave={() => setHoveredArc(null)}
            style={{ cursor: "pointer" }}
          >
            {/* Ghost trail behind the particle */}
            <path
              d={path}
              fill="none"
              stroke={color}
              strokeWidth={lineW}
              strokeOpacity={0.15}
              strokeDasharray="4 6"
            />
            {/* Main arc line */}
            <path
              d={path}
              fill="none"
              stroke={color}
              strokeWidth={isHovered ? lineHoverW : lineW}
              strokeOpacity={isHovered ? 1 : 0.65}
              filter={`url(#arcGlow${expanded ? "X" : ""})`}
            />
            {/* Source endpoint */}
            <circle
              cx={sp[0]} cy={sp[1]} r={endR}
              fill={color}
              filter={`url(#endGlow${expanded ? "X" : ""})`}
              stroke="rgba(0,0,0,0.4)"
              strokeWidth={1}
            />
            {/* Destination endpoint */}
            <circle
              cx={dp[0]} cy={dp[1]} r={endR}
              fill={color}
              fillOpacity={0.5}
              filter={`url(#endGlow${expanded ? "X" : ""})`}
              stroke={color}
              strokeWidth={1}
              strokeOpacity={0.6}
            />
            {/* Traveling particle */}
            <circle r={expanded ? 4 : 2.5} fill={color} filter={`url(#dotGlow${expanded ? "X" : ""})`}>
              <animateMotion
                dur={`${1.8 + (i % 3) * 0.4}s`}
                repeatCount="indefinite"
                path={path}
              />
            </circle>
            {isHovered && (
              <g>
                <rect
                  x={(sp[0] + dp[0]) / 2 - 90}
                  y={Math.min(sp[1], dp[1]) - 42}
                  width={180}
                  height={36}
                  rx={6}
                  fill="rgba(0,8,20,0.94)"
                  stroke={color}
                  strokeWidth={1}
                  strokeOpacity={0.5}
                />
                <text
                  x={(sp[0] + dp[0]) / 2}
                  y={Math.min(sp[1], dp[1]) - 28}
                  textAnchor="middle"
                  fill={color}
                  fontSize={expanded ? 11 : 9}
                  fontFamily="monospace"
                  fontWeight={700}
                >
                  {arc.srcName} → {arc.dstName} · {arc.attack}
                </text>
                <text
                  x={(sp[0] + dp[0]) / 2}
                  y={Math.min(sp[1], dp[1]) - 14}
                  textAnchor="middle"
                  fill="rgba(255,255,255,0.5)"
                  fontSize={expanded ? 9 : 8}
                  fontFamily="monospace"
                >
                  SEV {arc.score.toFixed(0)} · {arc.severity} · {arc.time}
                </text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function WorldAttackMap() {
  const events = useEventStore((s) => s.events);
  const [maximized, setMaximized] = useState(false);
  const [now, setNow] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setNow((p) => p + 1), 3000);
    return () => clearInterval(id);
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const arcs = useMemo(() => buildArcs(events), [events, now]);

  const W = maximized ? 1200 : 800;
  const H = maximized ? 500 : 260;
  const projection = useMemo(() =>
    geoMercator().translate([W / 2, H / 2 + 10]).scale(W / (maximized ? 1.6 : 2)),
    [W, H, maximized]
  );

  useEffect(() => {
    if (maximized) {
      document.body.style.overflow = "hidden";
      return () => { document.body.style.overflow = ""; };
    }
  }, [maximized]);

  const mapInner = (
    <MapSVG arcs={arcs} W={W} H={H} projection={projection} expanded={maximized} />
  );

  if (maximized) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center"
        style={{ background: "rgba(5,10,20,0.95)", backdropFilter: "blur(12px)" }}
      >
        <div className="w-full h-full max-w-[96vw] max-h-[92vh] p-4 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.15)" }}>
                <Globe className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
              </div>
              <p className="text-[10px] font-mono tracking-[0.2em] uppercase" style={{ color: "var(--text-muted)" }}>
                Global Attack Map — Expanded View
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3">
                {Object.entries(SEV_STROKE).map(([sev, color]) => (
                  <div key={sev} className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                    <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>{sev}</span>
                  </div>
                ))}
              </div>
              <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                {arcs.length} routes · {activeCount(arcs)} countries
              </span>
              <button
                onClick={() => setMaximized(false)}
                className="w-8 h-8 rounded-lg flex items-center justify-center transition-colors hover:bg-white/[0.06]"
                style={{ border: "1px solid rgba(0,229,255,0.15)" }}
              >
                <Minimize2 className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
              </button>
            </div>
          </div>
          <div className="flex-1 rounded-2xl overflow-hidden"
            style={{ background: "rgba(0,8,20,0.4)", border: "1px solid rgba(0,229,255,0.08)" }}>
            {mapInner}
          </div>
        </div>
      </div>
    );
  }

  return (
    <GlassCard hoverGlow={false} className="overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{
              background: "rgba(0,229,255,0.08)",
              border: "1px solid rgba(0,229,255,0.15)",
            }}
          >
            <Globe className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          </div>
          <p
            className="text-[10px] font-mono tracking-[0.2em] uppercase"
            style={{ color: "var(--text-muted)" }}
          >
            Global Attack Map
          </p>
        </div>
        <button
          onClick={() => setMaximized(true)}
          className="w-7 h-7 rounded-lg flex items-center justify-center transition-colors hover:bg-white/[0.06]"
          style={{ border: "1px solid rgba(0,229,255,0.15)" }}
          title="Expand map"
        >
          <Maximize2 className="w-3.5 h-3.5" style={{ color: "var(--accent-cyan)" }} />
        </button>
      </div>
      {arcs.length === 0 ? (
        <EmptyState message="Awaiting live attack data..." />
      ) : (
        <div className="relative" style={{ height: 260, borderRadius: 12, overflow: "hidden" }}>
          {mapInner}
          <div className="absolute bottom-3 left-3 flex items-center gap-3">
            {Object.entries(SEV_STROKE).map(([sev, color]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>{sev}</span>
              </div>
            ))}
          </div>
          <div className="absolute bottom-3 right-3 text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>
            {arcs.length} attack routes · {activeCount(arcs)} active countries
          </div>
        </div>
      )}
    </GlassCard>
  );
}

function activeCount(arcs: AttackArc[]): number {
  const s = new Set<string>();
  arcs.forEach((a) => { s.add(a.srcCountry); s.add(a.dstCountry); });
  return s.size;
}

/* ═══════════════════════════════════════════════════════════════ */
/*  THREAT RADAR                                                  */
/* ═══════════════════════════════════════════════════════════════ */
const ATTACK_SECTORS: Record<string, number> = {
  DDoS: 0, DoS: 1, PortScan: 2, Bot: 3, WebAttack: 4, BruteForce: 5, Infiltration: 6,
};
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ff4d6d", HIGH: "#ff9500", MEDIUM: "#00e5ff", LOW: "#00ff88",
};

function ThreatRadar() {
  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const events = useEventStore((s) => s.events);
  const [sweep, setSweep] = useState(0);
  const [tip, setTip] = useState<{
    x: number; y: number; attack: string; severity: string;
    score: number; time: string; confidence: number;
  } | null>(null);

  useEffect(() => {
    let raf: number;
    let last = performance.now();
    const go = (now: number) => {
      setSweep((p) => (p + (now - last) * 0.04) % 360);
      last = now;
      raf = requestAnimationFrame(go);
    };
    raf = requestAnimationFrame(go);
    return () => cancelAnimationFrame(raf);
  }, []);

  const dots = useMemo(() => {
    const out: Array<{
      id: string; angle: number; dist: number; color: string;
      attack: string; severity: string; score: number;
      time: string; confidence: number; size: number;
    }> = [];
    const n = 7;
    const sa = 360 / n;

    predictionHistory.slice(0, 40).forEach((p) => {
      const si = ATTACK_SECTORS[p.predictedAttack] ?? 0;
      const base = si * sa + sa / 2;
      const j = ((p.id.charCodeAt(p.id.length - 1) % 7) - 3) * 3;
      const angle = base + j;
      const sToD: Record<string, number> = { CRITICAL: 15, HIGH: 35, MEDIUM: 55, LOW: 72 };
      const dist = (sToD[p.riskLevel] || 60) + (p.severityScore % 20);
      out.push({
        id: p.id, angle, dist,
        color: SEV_COLORS[p.riskLevel] || SEV_COLORS.MEDIUM,
        attack: p.predictedAttack, severity: p.riskLevel, score: p.severityScore,
        time: new Date(p.timestamp).toLocaleTimeString("en-US", { hour12: false }),
        confidence: p.confidence,
        size: p.riskLevel === "CRITICAL" ? 5 : p.riskLevel === "HIGH" ? 4 : 3,
      });
    });

    events.filter((e) => e.type === "prediction" || e.type === "error").slice(0, 15).forEach((e) => {
      const d = e.details as Record<string, unknown> | undefined;
      const atk = (d?.attack_type as string) || "";
      const sev = (d?.severity as string) || "MEDIUM";
      const sc = (d?.severity_score as number) || 50;
      const si = ATTACK_SECTORS[atk];
      if (si === undefined) return;
      const base = si * sa + sa / 2;
      const j = ((e.id.charCodeAt(e.id.length - 1) % 5) - 2) * 4;
      const sToD: Record<string, number> = { CRITICAL: 12, HIGH: 32, MEDIUM: 52, LOW: 70 };
      const dist = (sToD[sev] || 55) + (sc % 18);
      out.push({
        id: e.id, angle: base + j, dist,
        color: SEV_COLORS[sev] || SEV_COLORS.MEDIUM,
        attack: atk, severity: sev, score: sc,
        time: new Date(e.timestamp).toLocaleTimeString("en-US", { hour12: false }),
        confidence: 0,
        size: sev === "CRITICAL" ? 6 : sev === "HIGH" ? 5 : 3,
      });
    });
    return out;
  }, [predictionHistory, events]);

  const S = 260;
  const cx = S / 2, cy = S / 2, R = S / 2 - 12;
  const rings = [0.25, 0.5, 0.75, 1.0];
  const sc = 7;
  const sAngle = 360 / sc;
  const recent = useMemo(() => {
    const s = new Set<string>();
    predictionHistory.slice(0, 5).forEach((p) => s.add(p.id));
    events.slice(0, 5).forEach((e) => s.add(e.id));
    return s;
  }, [predictionHistory, events]);

  if (dots.length === 0) {
    return (
      <GlassCard hoverGlow={false}>
        <CardLabel icon={Radar}>Global Threat Radar</CardLabel>
        <EmptyState message="Run predictions to populate radar" />
      </GlassCard>
    );
  }

  const saRad = (sweep * Math.PI) / 180;
  const cone = 45 * (Math.PI / 180);

  return (
    <GlassCard hoverGlow={false}>
      <CardLabel icon={Radar}>Global Threat Radar</CardLabel>
      <div className="flex gap-4 items-start">
        <div className="relative shrink-0">
          <svg width={S} height={S} viewBox={`0 0 ${S} ${S}`} className="block">
            <circle cx={cx} cy={cy} r={R} fill="rgba(0,20,40,0.5)" />
            {rings.map((r, i) => (
              <circle key={i} cx={cx} cy={cy} r={R * r} fill="none" stroke="rgba(0,229,255,0.08)" strokeWidth={0.75} />
            ))}
            {Array.from({ length: sc }).map((_, i) => {
              const a = (i * sAngle * Math.PI) / 180;
              return <line key={i} x1={cx} y1={cy} x2={cx + R * Math.cos(a)} y2={cy + R * Math.sin(a)} stroke="rgba(0,229,255,0.06)" strokeWidth={0.75} />;
            })}
            {Object.entries(ATTACK_SECTORS).map(([name, idx]) => {
              const a = ((idx * sAngle + sAngle / 2) * Math.PI) / 180;
              return (
                <text key={name} x={cx + (R + 2) * Math.cos(a)} y={cy + (R + 2) * Math.sin(a)}
                  textAnchor="middle" dominantBaseline="middle" fill="rgba(0,229,255,0.35)" fontSize={7} fontFamily="monospace">
                  {name}
                </text>
              );
            })}
            <defs>
              <radialGradient id="sweepCone">
                <stop offset="0%" stopColor="rgba(0,229,255,0)" />
                <stop offset="100%" stopColor="rgba(0,229,255,0.12)" />
              </radialGradient>
            </defs>
            {(() => {
              const x1 = cx + R * Math.cos(saRad - cone);
              const y1 = cy + R * Math.sin(saRad - cone);
              const x2 = cx + R * Math.cos(saRad + cone);
              const y2 = cy + R * Math.sin(saRad + cone);
              return (
                <path d={`M${cx},${cy} L${x1},${y1} A${R},${R} 0 0,1 ${x2},${y2} Z`} fill="rgba(0,229,255,0.08)" />
              );
            })()}
            <line x1={cx} y1={cy} x2={cx + R * Math.cos(saRad)} y2={cy + R * Math.sin(saRad)}
              stroke="rgba(0,229,255,0.5)" strokeWidth={1.2} />
            <circle cx={cx} cy={cy} r={3} fill="var(--accent-cyan)" opacity={0.8} />
            <circle cx={cx} cy={cy} r={5} fill="none" stroke="var(--accent-cyan)" strokeWidth={0.5} opacity={0.4} />
            {dots.map((dot) => {
              const a = (dot.angle * Math.PI) / 180;
              const r = (dot.dist / 100) * R;
              const dx = cx + r * Math.cos(a);
              const dy = cy + r * Math.sin(a);
              const isNew = recent.has(dot.id);
              return (
                <g key={dot.id}>
                  {isNew && (
                    <circle cx={dx} cy={dy} r={dot.size + 4} fill="none" stroke={dot.color} strokeWidth={0.8} opacity={0.35}>
                      <animate attributeName="r" from={`${dot.size + 1}`} to={`${dot.size + 8}`} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" from="0.4" to="0" dur="2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle cx={dx} cy={dy} r={dot.size} fill={dot.color} opacity={0.85}
                    className="cursor-pointer" style={{ filter: `drop-shadow(0 0 4px ${dot.color})` }}
                    onMouseEnter={() => setTip({ x: dx, y: dy, attack: dot.attack, severity: dot.severity, score: dot.score, time: dot.time, confidence: dot.confidence })}
                    onMouseLeave={() => setTip(null)} />
                </g>
              );
            })}
          </svg>
          {tip && (
            <div className="absolute z-20 pointer-events-none rounded-xl px-3 py-2.5 min-w-[160px]"
              style={{
                left: tip.x + 14, top: tip.y - 12,
                background: "rgba(8,20,32,0.95)",
                border: `1px solid ${SEV_COLORS[tip.severity] || "var(--accent-cyan)"}40`,
                boxShadow: `0 8px 24px rgba(0,0,0,0.5), 0 0 12px ${SEV_COLORS[tip.severity]}15`,
              }}>
              <p className="text-[10px] font-mono font-bold" style={{ color: SEV_COLORS[tip.severity] }}>{tip.attack}</p>
              <p className="text-[9px] font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                Severity: <span style={{ color: SEV_COLORS[tip.severity] }}>{tip.severity}</span> ({tip.score})
              </p>
              {tip.confidence > 0 && (
                <p className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                  Confidence: {(tip.confidence * 100).toFixed(1)}%
                </p>
              )}
              <p className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>{tip.time}</p>
            </div>
          )}
        </div>
        <div className="flex-1 min-w-0 space-y-2.5">
          <p className="text-[10px] font-mono tracking-widest uppercase" style={{ color: "var(--text-muted)" }}>Threat Distribution</p>
          {Object.entries(ATTACK_SECTORS).map(([name]) => {
            const count = dots.filter((d) => d.attack === name).length;
            const pct = dots.length > 0 ? (count / dots.length) * 100 : 0;
            const topSev = dots.filter((d) => d.attack === name).sort((a, b) => b.score - a.score)[0]?.severity;
            const color = SEV_COLORS[topSev || "MEDIUM"] || "var(--accent-cyan)";
            return (
              <div key={name}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-[9px] font-mono" style={{ color: "var(--text-secondary)" }}>{name}</span>
                  <span className="text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>{count} ({pct.toFixed(0)}%)</span>
                </div>
                <div className="h-1 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                  <motion.div className="h-full rounded-full" style={{ background: color }}
                    initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.6, ease: "easeOut" }} />
                </div>
              </div>
            );
          })}
          <div className="pt-2 border-t" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
            <p className="text-[9px] font-mono mb-1.5" style={{ color: "var(--text-muted)" }}>Legend</p>
            <div className="grid grid-cols-2 gap-1">
              {Object.entries(SEV_COLORS).map(([label, color]) => (
                <div key={label} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color, boxShadow: `0 0 4px ${color}60` }} />
                  <span className="text-[8px] font-mono" style={{ color: "var(--text-muted)" }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  CARD 9 — Live Events (WebSocket)                             */
/* ═══════════════════════════════════════════════════════════════ */
function LiveEventsCard() {
  const events = useEventStore((s) => s.events);
  const wsEvents = events.filter((e) => e.details && typeof e.details === "object" && "attack_type" in (e.details as Record<string, unknown>));
  const hasData = wsEvents.length > 0;
  const visibleEvents = wsEvents.slice(0, 4);

  const severityColors: Record<string, string> = {
    CRITICAL: "var(--accent-red)",
    HIGH: "var(--accent-amber)",
    MEDIUM: "var(--accent-cyan)",
    LOW: "var(--accent-green)",
  };

  return (
    <GlassCard hoverGlow={false}>
      <CardLabel icon={Zap}>Live Threat Events</CardLabel>
      <div className="h-[340px] overflow-hidden relative">
        {!hasData ? (
          <EmptyState message="Awaiting live events..." />
        ) : (
          <div className="space-y-2">
            <AnimatePresence initial={false} mode="popLayout">
              {visibleEvents.map((evt) => {
                const d = evt.details as Record<string, unknown>;
                const attackType = (d.attack_type as string) || "Unknown";
                const severity = (d.severity as string) || "LOW";
                const severityScore = (d.severity_score as number) || 0;
                const sourceIp = (d.source_ip as string) || "—";
                const destIp = (d.dest_ip as string) || "—";
                const country = (d.country as string) || "—";
                const status = (d.status as string) || "DETECTED";
                const color = severityColors[severity] || "var(--text-muted)";

                return (
                  <motion.div
                    key={evt.id}
                    layout
                    initial={{ opacity: 0, height: 0, marginTop: 0 }}
                    animate={{ opacity: 1, height: "auto", marginTop: 8 }}
                    exit={{ opacity: 0, height: 0, marginTop: 0 }}
                    transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                    className="rounded-xl p-3 overflow-hidden"
                    style={{ border: `1px solid ${color}20`, background: `${color}06` }}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span
                          className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold tracking-wider"
                          style={{ background: `${color}15`, color, border: `1px solid ${color}30` }}
                        >
                          {attackType}
                        </span>
                        <span
                          className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold"
                          style={{ background: `${color}12`, color }}
                        >
                          {severity}
                        </span>
                      </div>
                      <span className="text-[8px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(0,229,255,0.06)", color: "var(--text-muted)" }}>
                        {status}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[9px] font-mono" style={{ color: "var(--text-muted)" }}>
                      <Globe className="w-3 h-3" />
                      <span>{sourceIp}</span>
                      <span style={{ color: "var(--text-muted)" }}>→</span>
                      <span>{destIp}</span>
                      <span className="ml-auto">{country}</span>
                    </div>
                    <div className="mt-1.5 flex items-center gap-2">
                      <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                        <motion.div
                          className="h-full rounded-full"
                          style={{ background: color }}
                          initial={{ width: 0 }}
                          animate={{ width: `${(severityScore / 100) * 100}%` }}
                          transition={{ duration: 0.6, ease: "easeOut" }}
                        />
                      </div>
                      <span className="text-[8px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                        SEV {severityScore.toFixed(0)}
                      </span>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </div>
    </GlassCard>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/*  MAIN DASHBOARD                                               */
/* ═══════════════════════════════════════════════════════════════ */
export default function Dashboard() {
  const metrics = useAnalyticsStore((s) => s.getDashboardMetrics);
  const [backendStats, setBackendStats] = useState<SystemStats | null>(null);

  const m = useMemo(() => metrics(), [metrics]);

  useEffect(() => {
    statsAPI()
      .then(setBackendStats)
      .catch(() => {});
  }, []);

  return (
    <div className="h-full overflow-y-auto p-6 lg:p-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-6"
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Cyber Command Center
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          Threat Dashboard
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Real-time overview of system health, predictions, and threat activity.
        </p>
      </motion.div>

      <Explanation text="The Threat Score is computed from prediction confidence, alert counts, and model agreement rates. All metrics are derived from actual prediction and comparison data stored in the system." />

      <Provenance
        source="FastAPI Backend + Store Analytics"
        lastUpdated={backendStats ? new Date().toISOString() : null}
        className="mt-3 mb-4"
      />

      <motion.div
        variants={stagger}
        initial="hidden"
        animate="show"
        className="grid grid-cols-12 gap-6"
      >
        {/* Row 1: 4 × col-span-3 */}
        <div className="col-span-3">
          <ThreatScoreCard metrics={m} />
        </div>
        <div className="col-span-3">
          <BackendHealthCard />
        </div>
        <div className="col-span-3">
          <LatestPredictionCard metrics={m} />
        </div>
        <div className="col-span-3">
          <ModelAgreementCard metrics={m} />
        </div>

        {/* Row 2: 3 × col-span-4 */}
        <div className="col-span-4">
          <PredictionVolumeCard metrics={m} />
        </div>
        <div className="col-span-4">
          <DriftStatusCard metrics={m} />
        </div>
        <div className="col-span-4">
          <ApiLatencyCard />
        </div>

        {/* Row 3: 3 × col-span-4 */}
        <div className="col-span-4">
          <CriticalAlertsCard metrics={m} />
        </div>
        <div className="col-span-4">
          <AttackDistributionCard metrics={m} />
        </div>
        <div className="col-span-4">
          <LiveEventsCard />
        </div>

        {/* Row 4: World Attack Map — full width */}
        <div className="col-span-12">
          <WorldAttackMap />
        </div>

        {/* Row 5: Threat Radar — full width */}
        <div className="col-span-12">
          <ThreatRadar />
        </div>

        {/* Row 6: full width */}
        <div className="col-span-12">
          <RecentPredictionsCard metrics={m} />
        </div>
      </motion.div>
    </div>
  );
}
