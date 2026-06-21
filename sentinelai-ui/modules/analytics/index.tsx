"use client";

import { useMemo, useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip as RechartsTooltip,
  LineChart,
  Line,
  Area,
  AreaChart,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";
import GlassPanel from "@/components/ui/GlassPanel";
import { ChartErrorBoundary } from "@/components/ui/ChartErrorBoundary";
import ThreatHeatmap from "@/modules/analytics/ThreatHeatmap";
import { useAnalyticsStore } from "@/stores/analyticsStore";
import { usePredictionStore } from "@/stores/predictionStore";
import { statsAPI, type SystemStats } from "@/lib/api";
import {
  Target,
  TrendingUp,
  Shield,
  Brain,
  Activity,
  BarChart3,
  LineChart as LineChartIcon,
  Clock,
  Flame,
} from "lucide-react";

const ATTACK_COLORS: Record<string, string> = {
  DDoS: "#FF4D6D",
  DoS: "#FFB020",
  PortScan: "#00E5FF",
  Bot: "#a855f7",
  WebAttack: "#FF4D6D",
  BruteForce: "#FFB020",
  Infiltration: "#ef4444",
  BENIGN: "#22c55e",
};

const chartTooltipStyle = {
  backgroundColor: "rgba(8, 20, 32, 0.95)",
  border: "1px solid rgba(0, 229, 255, 0.3)",
  borderRadius: "12px",
  color: "#fff",
  fontSize: "12px",
  fontFamily: "monospace",
};

const CHART_GRID_STYLE = { strokeDasharray: "3 3", stroke: "rgba(255,255,255,0.05)" };

function EmptyChart({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-3">
      <Icon className="w-8 h-8" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {label}
      </p>
    </div>
  );
}

export default function Analytics() {
  const metrics = useAnalyticsStore((s) => s.getDashboardMetrics)();
  const getStats = usePredictionStore((s) => s.getStats);
  const stats = useMemo(() => getStats(), [getStats]);
  const [backendStats, setBackendStats] = useState<SystemStats | null>(null);

  useEffect(() => {
    statsAPI()
      .then(setBackendStats)
      .catch(() => {});
  }, []);

  const attackDistributionData = useMemo(() => {
    return Object.entries(metrics.attackDistribution).map(([name, value]) => ({
      name,
      value,
      color: ATTACK_COLORS[name] || "#8892A4",
    }));
  }, [metrics.attackDistribution]);

  const confidenceTrendData = useMemo(() => {
    return metrics.confidenceTrend.map((point) => ({
      time: point.time,
      confidence: point.confidence,
      attack: point.attack,
    }));
  }, [metrics.confidenceTrend]);

  const driftTrendData = useMemo(() => {
    return metrics.driftTrend.map((d) => ({
      time: d.time,
      score: d.score,
      status: d.status,
    }));
  }, [metrics.driftTrend]);

  const predictionTimelineData = useMemo(() => {
    return metrics.recentPredictions.map((pred) => ({
      time: new Date(pred.timestamp).toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      confidence: Math.round(pred.confidence * 100),
      attack: pred.predictedAttack,
    }));
  }, [metrics.recentPredictions]);

  const hasAttackData = attackDistributionData.length > 0;
  const hasConfidenceData = confidenceTrendData.length > 0;
  const hasPredictionData = predictionTimelineData.length > 0;

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Performance Analytics
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          System Metrics
        </h1>
        <p
          className="text-sm mt-2"
          style={{ color: "var(--text-secondary)" }}
        >
          Real-time model performance and threat analysis
        </p>
      </motion.div>

      {/* KPI Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="grid grid-cols-2 lg:grid-cols-6 gap-4"
      >
        <GlassPanel title="Total Predictions" icon={<Brain className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{ color: "var(--accent-cyan)" }}
            >
              {metrics.predictionVolume}
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Predictions processed
            </p>
          </div>
        </GlassPanel>

        <GlassPanel title="Average Confidence" icon={<Target className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{ color: "var(--accent-green)" }}
            >
              {stats.averageConfidence > 0
                ? `${(stats.averageConfidence * 100).toFixed(1)}%`
                : "—"}
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Model confidence
            </p>
          </div>
        </GlassPanel>

        <GlassPanel title="Model Agreement" icon={<Shield className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{ color: "var(--accent-purple)" }}
            >
              {metrics.modelAgreement > 0 ? `${metrics.modelAgreement}%` : "—"}
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              ML + Markov
            </p>
          </div>
        </GlassPanel>

        <GlassPanel title="Avg Latency" icon={<Clock className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{ color: backendStats && backendStats.average_latency > 500 ? "var(--accent-red)" : "var(--accent-cyan)" }}
            >
              {backendStats && backendStats.average_latency > 0
                ? `${backendStats.average_latency.toFixed(1)}ms`
                : stats.averageLatency > 0
                ? `${stats.averageLatency.toFixed(1)}ms`
                : "—"}
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Response time
            </p>
          </div>
        </GlassPanel>

        <GlassPanel title="Critical Alerts" icon={<Flame className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{ color: "var(--accent-red)" }}
            >
              {backendStats ? backendStats.critical_alerts : metrics.criticalAlerts}
            </p>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              High-risk events
            </p>
          </div>
        </GlassPanel>

        <GlassPanel title="Drift Score" icon={<Activity className="w-4 h-4" />}>
          <div className="text-center py-3">
            <p
              className="text-3xl font-display font-bold"
              style={{
                color:
                  metrics.driftStatus === "critical"
                    ? "var(--accent-red)"
                    : metrics.driftStatus === "warning"
                    ? "var(--accent-amber)"
                    : "var(--accent-green)",
              }}
            >
              {driftTrendData.length > 0 ? `${driftTrendData[0].score}%` : "—"}
            </p>
            <p
              className="text-xs font-mono uppercase"
              style={{
                color:
                  metrics.driftStatus === "critical"
                    ? "var(--accent-red)"
                    : metrics.driftStatus === "warning"
                    ? "var(--accent-amber)"
                    : "var(--accent-green)",
              }}
            >
              {metrics.driftStatus}
            </p>
          </div>
        </GlassPanel>
      </motion.div>

      {/* Charts Row 1 */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <GlassPanel
            title="Attack Distribution"
            icon={<Shield className="w-4 h-4" />}
            className="h-full flex flex-col"
          >
            <div className="flex-1 min-h-[280px]">
              {hasAttackData ? (
                <ChartErrorBoundary>
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={attackDistributionData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) =>
                          `${name} ${((percent || 0) * 100).toFixed(0)}%`
                        }
                        outerRadius={100}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {attackDistributionData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip contentStyle={chartTooltipStyle} />
                      <Legend
                        wrapperStyle={{ color: "var(--text-muted)", fontSize: "12px" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </ChartErrorBoundary>
              ) : (
                <EmptyChart icon={Shield} label="No attack data yet" />
              )}
            </div>
          </GlassPanel>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          <GlassPanel
            title="Confidence Trend"
            icon={<TrendingUp className="w-4 h-4" />}
            className="h-full flex flex-col"
          >
            <div className="flex-1 min-h-[280px]">
              {hasConfidenceData ? (
                <ChartErrorBoundary>
                  <ResponsiveContainer width="100%" height={280}>
                    <AreaChart data={confidenceTrendData}>
                      <defs>
                        <linearGradient id="colorConfidence" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--accent-green)" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="var(--accent-green)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid {...CHART_GRID_STYLE} />
                      <XAxis
                        dataKey="time"
                        stroke="var(--text-muted)"
                        fontSize={11}
                        tickLine={false}
                      />
                      <YAxis
                        stroke="var(--text-muted)"
                        fontSize={11}
                        tickLine={false}
                      />
                      <RechartsTooltip contentStyle={chartTooltipStyle} />
                      <Area
                        type="monotone"
                        dataKey="confidence"
                        stroke="var(--accent-green)"
                        fillOpacity={1}
                        fill="url(#colorConfidence)"
                        name="Confidence %"
                        strokeWidth={2}
                        dot={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </ChartErrorBoundary>
              ) : (
                <EmptyChart icon={TrendingUp} label="No confidence data yet" />
              )}
            </div>
          </GlassPanel>
        </motion.div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ height: "300px" }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          <GlassPanel
            title="Prediction Timeline"
            icon={<BarChart3 className="w-4 h-4" />}
            className="h-full flex flex-col"
          >
            <div className="flex-1 min-h-0">
              {hasPredictionData ? (
                <ChartErrorBoundary>
                  <ResponsiveContainer width="100%" height={280}>
                    <LineChart data={predictionTimelineData}>
                      <CartesianGrid {...CHART_GRID_STYLE} />
                      <XAxis
                        dataKey="time"
                        stroke="var(--text-muted)"
                        fontSize={11}
                        tickLine={false}
                      />
                      <YAxis
                        stroke="var(--text-muted)"
                        fontSize={11}
                        tickLine={false}
                        domain={[0, 100]}
                      />
                      <RechartsTooltip contentStyle={chartTooltipStyle} />
                      <Legend
                        wrapperStyle={{ color: "var(--text-muted)", fontSize: "12px" }}
                      />
                      <Line
                        type="monotone"
                        dataKey="confidence"
                        stroke="var(--accent-cyan)"
                        strokeWidth={2}
                        dot={{ r: 3, fill: "var(--accent-cyan)" }}
                        name="Confidence %"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </ChartErrorBoundary>
              ) : (
                <EmptyChart icon={LineChartIcon} label="No prediction data yet" />
              )}
            </div>
          </GlassPanel>
        </motion.div>
      </div>

      {/* Threat Heatmap */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mt-8"
      >
        <GlassPanel title="Threat Severity Heatmap">
          <ThreatHeatmap />
        </GlassPanel>
      </motion.div>
    </div>
  );
}
