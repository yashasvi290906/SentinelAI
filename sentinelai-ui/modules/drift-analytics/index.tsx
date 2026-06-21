"use client";

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Activity,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  BarChart3,
  Clock,
  RefreshCw,
} from "lucide-react";
import { driftAnalyticsAPI } from "@/lib/api";
import { ATTACK_COLORS } from "@/lib/config";
import type { DriftAnalyticsResponse } from "@/lib/api";

const chartTooltipStyle = {
  backgroundColor: "rgba(8, 20, 32, 0.95)",
  border: "1px solid rgba(0, 229, 255, 0.3)",
  borderRadius: "12px",
  color: "#fff",
  fontSize: "12px",
  fontFamily: "monospace",
};

const CHART_GRID_STYLE = {
  strokeDasharray: "3 3",
  stroke: "rgba(255,255,255,0.05)",
};

function getStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "stable":
      return "var(--accent-green)";
    case "warning":
      return "var(--accent-amber)";
    case "critical":
      return "var(--accent-red)";
    default:
      return "var(--accent-cyan)";
  }
}

function getStatusBg(status: string): string {
  switch (status.toLowerCase()) {
    case "stable":
      return "rgba(34,197,94,0.12)";
    case "warning":
      return "rgba(255,176,32,0.12)";
    case "critical":
      return "rgba(255,61,61,0.12)";
    default:
      return "rgba(0,229,255,0.08)";
  }
}

function getDriftScoreColor(score: number): string {
  if (score < 0.1) return "var(--accent-green)";
  if (score <= 0.25) return "var(--accent-amber)";
  return "var(--accent-red)";
}

export default function DriftAnalytics() {
  const [data, setData] = useState<DriftAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const result = await driftAnalyticsAPI();
      setData(result);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to fetch drift analytics data."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(fetchData, 0);
    const interval = setInterval(fetchData, 10000);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [fetchData]);

  const confidenceTrendData = data?.history.map((h) => ({
    time: new Date(h.timestamp).toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    confidence: h.confidence,
    prediction: h.prediction,
  })) ?? [];

  const attackDistributionData = data?.distribution
    ? Object.entries(data.distribution).map(([name, value]) => ({
        name,
        value,
        color: ATTACK_COLORS[name] || "#8892A4",
      }))
    : [];

  const recentPredictions = data?.history.slice(0, 10) ?? [];

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex items-start justify-between"
      >
        <div>
          <p
            className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
            style={{ color: "var(--accent-cyan)" }}
          >
            Model Monitoring
          </p>
          <h1
            className="text-3xl font-display font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            Drift Analytics
          </h1>
          <p
            className="text-sm mt-2"
            style={{ color: "var(--text-secondary)" }}
          >
            Monitor model drift, confidence degradation, and prediction stability over time.
          </p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 text-xs font-mono font-semibold rounded-xl transition-all duration-300 disabled:opacity-50"
          style={{
            background: "rgba(0,229,255,0.08)",
            border: "1px solid rgba(0,229,255,0.15)",
            color: "var(--accent-cyan)",
          }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </motion.div>

      {/* Loading State */}
      {loading && !data && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex items-center justify-center"
        >
          <div className="text-center space-y-3">
            <Activity
              className="w-8 h-8 mx-auto animate-pulse"
              style={{ color: "var(--accent-cyan)" }}
            />
            <p className="text-sm font-mono" style={{ color: "var(--text-muted)" }}>
              Loading drift analytics...
            </p>
          </div>
        </motion.div>
      )}

      {/* Error State */}
      {error && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="rounded-xl p-4 text-sm font-mono flex items-center gap-2"
          style={{
            background: "rgba(255,77,109,0.08)",
            border: "1px solid rgba(255,77,109,0.2)",
            color: "var(--accent-red)",
          }}
        >
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </motion.div>
      )}

      {/* Empty State */}
      {!loading && !error && !data && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex-1 flex items-center justify-center"
        >
          <div
            className="rounded-2xl p-12 text-center"
            style={{
              background: "rgba(8,20,32,0.4)",
              border: "2px dashed rgba(0,229,255,0.1)",
            }}
          >
            <Activity
              className="w-12 h-12 mx-auto mb-4"
              style={{ color: "var(--text-muted)" }}
            />
            <p className="font-mono text-sm" style={{ color: "var(--text-secondary)" }}>
              No drift data available. Run predictions first.
            </p>
          </div>
        </motion.div>
      )}

      {/* Content */}
      {data && (
        <>
          {/* Top Metrics Row */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="grid grid-cols-2 lg:grid-cols-4 gap-4"
          >
            {/* Drift Score */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div
                className="flex items-center gap-2 px-5 py-3"
                style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
              >
                <Activity className="w-4 h-4" style={{ color: getDriftScoreColor(data.drift_score) }} />
                <span
                  className="text-[11px] font-mono tracking-widest uppercase"
                  style={{ color: "var(--text-muted)" }}
                >
                  Drift Score
                </span>
              </div>
              <div className="p-5 text-center">
                <p
                  className="text-3xl font-display font-bold"
                  style={{ color: getDriftScoreColor(data.drift_score) }}
                >
                  {data.drift_score.toFixed(3)}
                </p>
                <p className="text-xs font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                  {data.drift_score < 0.1
                    ? "Stable"
                    : data.drift_score <= 0.25
                    ? "Moderate Drift"
                    : "High Drift"}
                </p>
              </div>
            </div>

            {/* Confidence */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div
                className="flex items-center gap-2 px-5 py-3"
                style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
              >
                <TrendingUp className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                <span
                  className="text-[11px] font-mono tracking-widest uppercase"
                  style={{ color: "var(--text-muted)" }}
                >
                  Confidence
                </span>
              </div>
              <div className="p-5 text-center">
                <p
                  className="text-3xl font-display font-bold"
                  style={{ color: "var(--accent-cyan)" }}
                >
                  {(data.confidence * 100).toFixed(1)}%
                </p>
                <p className="text-xs font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                  Average model confidence
                </p>
              </div>
            </div>

            {/* Accuracy */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div
                className="flex items-center gap-2 px-5 py-3"
                style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
              >
                <CheckCircle2 className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
                <span
                  className="text-[11px] font-mono tracking-widest uppercase"
                  style={{ color: "var(--text-muted)" }}
                >
                  Accuracy
                </span>
              </div>
              <div className="p-5 text-center">
                <p
                  className="text-3xl font-display font-bold"
                  style={{ color: "var(--accent-green)" }}
                >
                  {(data.accuracy * 100).toFixed(1)}%
                </p>
                <p className="text-xs font-mono mt-1" style={{ color: "var(--text-muted)" }}>
                  Prediction accuracy
                </p>
              </div>
            </div>

            {/* Status */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div
                className="flex items-center gap-2 px-5 py-3"
                style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
              >
                <BarChart3 className="w-4 h-4" style={{ color: getStatusColor(data.status) }} />
                <span
                  className="text-[11px] font-mono tracking-widest uppercase"
                  style={{ color: "var(--text-muted)" }}
                >
                  Status
                </span>
              </div>
              <div className="p-5 text-center">
                <span
                  className="inline-block px-4 py-1.5 rounded-lg text-sm font-mono font-bold uppercase"
                  style={{
                    background: getStatusBg(data.status),
                    border: `1px solid ${getStatusColor(data.status)}30`,
                    color: getStatusColor(data.status),
                  }}
                >
                  {data.status}
                </span>
                <p className="text-xs font-mono mt-3" style={{ color: "var(--text-muted)" }}>
                  {data.total_predictions} total predictions
                </p>
              </div>
            </div>
          </motion.div>

          {/* Charts Section */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confidence Trend */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <div
                className="rounded-2xl overflow-hidden h-full flex flex-col"
                style={{
                  background: "rgba(8,20,32,0.7)",
                  backdropFilter: "blur(24px)",
                  border: "1px solid rgba(0,229,255,0.08)",
                }}
              >
                <div
                  className="flex items-center gap-2 px-5 py-3"
                  style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
                >
                  <TrendingUp className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                  <span
                    className="text-[11px] font-mono tracking-widest uppercase"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Confidence Trend
                  </span>
                </div>
                <div className="p-5 flex-1 min-h-[300px]">
                  {confidenceTrendData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={confidenceTrendData}>
                        <defs>
                          <linearGradient id="colorConfidence" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
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
                          domain={[0, 1]}
                          tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                        />
                        <Tooltip
                          contentStyle={chartTooltipStyle}
                          formatter={(value) => [
                            `${(Number(value) * 100).toFixed(1)}%`,
                            "Confidence",
                          ]}
                        />
                        <Legend
                          wrapperStyle={{ color: "var(--text-muted)", fontSize: "12px" }}
                        />
                        <Line
                          type="monotone"
                          dataKey="confidence"
                          stroke="var(--accent-cyan)"
                          strokeWidth={2}
                          dot={false}
                          name="Confidence"
                          fill="url(#colorConfidence)"
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full gap-3">
                      <TrendingUp
                        className="w-8 h-8"
                        style={{ color: "var(--text-muted)", opacity: 0.3 }}
                      />
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                        No confidence trend data yet
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>

            {/* Attack Distribution */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <div
                className="rounded-2xl overflow-hidden h-full flex flex-col"
                style={{
                  background: "rgba(8,20,32,0.7)",
                  backdropFilter: "blur(24px)",
                  border: "1px solid rgba(0,229,255,0.08)",
                }}
              >
                <div
                  className="flex items-center gap-2 px-5 py-3"
                  style={{ borderBottom: "1px solid rgba(0,229,255,0.06)" }}
                >
                  <BarChart3 className="w-4 h-4" style={{ color: "var(--accent-purple)" }} />
                  <span
                    className="text-[11px] font-mono tracking-widest uppercase"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Attack Distribution
                  </span>
                </div>
                <div className="p-5 flex-1 min-h-[300px]">
                  {attackDistributionData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
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
                        <Tooltip contentStyle={chartTooltipStyle} />
                        <Legend
                          wrapperStyle={{ color: "var(--text-muted)", fontSize: "12px" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full gap-3">
                      <BarChart3
                        className="w-8 h-8"
                        style={{ color: "var(--text-muted)", opacity: 0.3 }}
                      />
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                        No attack distribution data yet
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>

          {/* Recent Predictions Table */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(8,20,32,0.7)",
                backdropFilter: "blur(24px)",
                border: "1px solid rgba(0,229,255,0.08)",
              }}
            >
              <div
                className="flex items-center gap-2.5 px-5 py-3.5 border-b"
                style={{ borderColor: "rgba(0,229,255,0.06)" }}
              >
                <Clock className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                <h3
                  className="text-[11px] font-bold tracking-[0.12em] uppercase"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Recent Predictions
                </h3>
                <span className="ml-auto text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                  Last {recentPredictions.length} entries
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr
                      className="border-b"
                      style={{ borderColor: "rgba(0,229,255,0.06)" }}
                    >
                      <th
                        className="px-5 py-3 text-left text-[10px] font-mono tracking-widest uppercase"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Timestamp
                      </th>
                      <th
                        className="px-5 py-3 text-left text-[10px] font-mono tracking-widest uppercase"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Attack
                      </th>
                      <th
                        className="px-5 py-3 text-left text-[10px] font-mono tracking-widest uppercase"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Confidence
                      </th>
                      <th
                        className="px-5 py-3 text-left text-[10px] font-mono tracking-widest uppercase"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Latency
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentPredictions.length > 0 ? (
                      recentPredictions.map((pred, i) => (
                        <motion.tr
                          key={pred.timestamp + i}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.03 }}
                          className="border-b transition-colors"
                          style={{
                            borderColor: "rgba(0,229,255,0.04)",
                            background: "rgba(255,255,255,0.01)",
                          }}
                        >
                          <td className="px-5 py-3">
                            <div className="flex items-center gap-2">
                              <Clock
                                className="w-3 h-3"
                                style={{ color: "var(--text-muted)" }}
                              />
                              <span
                                className="text-xs font-mono"
                                style={{ color: "var(--text-secondary)" }}
                              >
                                {new Date(pred.timestamp).toLocaleTimeString("en-US", {
                                  hour12: false,
                                  hour: "2-digit",
                                  minute: "2-digit",
                                  second: "2-digit",
                                })}
                              </span>
                            </div>
                          </td>
                          <td className="px-5 py-3">
                            <span
                              className="px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold"
                              style={{
                                background: `${ATTACK_COLORS[pred.prediction] || "var(--accent-cyan)"}15`,
                                border: `1px solid ${ATTACK_COLORS[pred.prediction] || "var(--accent-cyan)"}30`,
                                color: ATTACK_COLORS[pred.prediction] || "var(--accent-cyan)",
                              }}
                            >
                              {pred.prediction}
                            </span>
                          </td>
                          <td className="px-5 py-3">
                            <div className="flex items-center gap-2">
                              <div
                                className="h-1.5 w-16 rounded-full overflow-hidden"
                                style={{ background: "rgba(0,229,255,0.06)" }}
                              >
                                <div
                                  className="h-full rounded-full"
                                  style={{
                                    width: `${pred.confidence * 100}%`,
                                    background:
                                      pred.confidence > 0.8
                                        ? "var(--accent-green)"
                                        : pred.confidence > 0.5
                                        ? "var(--accent-cyan)"
                                        : "var(--accent-amber)",
                                  }}
                                />
                              </div>
                              <span
                                className="text-xs font-mono"
                                style={{
                                  color:
                                    pred.confidence > 0.8
                                      ? "var(--accent-green)"
                                      : pred.confidence > 0.5
                                      ? "var(--accent-cyan)"
                                      : "var(--accent-amber)",
                                }}
                              >
                                {(pred.confidence * 100).toFixed(1)}%
                              </span>
                            </div>
                          </td>
                          <td className="px-5 py-3">
                            <span
                              className="text-xs font-mono"
                              style={{
                                color:
                                  pred.latency_ms < 5
                                    ? "var(--accent-green)"
                                    : pred.latency_ms < 20
                                    ? "var(--accent-cyan)"
                                    : "var(--accent-amber)",
                              }}
                            >
                              {pred.latency_ms.toFixed(1)}ms
                            </span>
                          </td>
                        </motion.tr>
                      ))
                    ) : (
                      <tr>
                        <td
                          colSpan={4}
                          className="px-5 py-12 text-center"
                        >
                          <p className="text-sm font-mono" style={{ color: "var(--text-muted)" }}>
                            No predictions recorded yet
                          </p>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </div>
  );
}
