"use client";

import { useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassPanel from "@/components/ui/GlassPanel";
import { usePredictionStore } from "@/stores/predictionStore";
import { useSystemStore } from "@/stores/systemStore";
import { ATTACK_COLORS } from "@/lib/config";
import {
  FileText,
  BarChart3,
  Activity,
  AlertTriangle,
  Download,
  Clock,
  Shield,
  Cpu,
  Zap,
  Target,
  Bug,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

type ReportType = "threat" | "performance" | "incident" | "drift";

interface ReportConfig {
  id: ReportType;
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
}

const REPORT_TYPES: ReportConfig[] = [
  {
    id: "threat",
    title: "Threat Analysis",
    description: "Comprehensive threat overview with risk scores and attack distribution",
    icon: <Shield className="w-5 h-5" />,
    color: "var(--accent-red)",
  },
  {
    id: "performance",
    title: "Model Performance",
    description: "ML vs Markov agreement rates, latency, and confidence statistics",
    icon: <BarChart3 className="w-5 h-5" />,
    color: "var(--accent-green)",
  },
  {
    id: "incident",
    title: "Incident Report",
    description: "Event timeline, severity progression, and recommended response actions",
    icon: <Bug className="w-5 h-5" />,
    color: "var(--accent-amber)",
  },
  {
    id: "drift",
    title: "Drift Analysis",
    description: "Data drift measurements, status distribution, and trend analysis",
    icon: <Activity className="w-5 h-5" />,
    color: "var(--accent-purple)",
  },
];

function csvEscape(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n")) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}

function RiskBadge({ level }: { level: string }) {
  const color =
    level === "CRITICAL" ? "var(--accent-red)"
      : level === "HIGH" ? "var(--accent-amber)"
        : level === "MEDIUM" ? "var(--accent-cyan)"
          : "var(--accent-green)";
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold"
      style={{ background: `${color}20`, color }}
    >
      {level}
    </span>
  );
}

function MetricCard({
  label,
  value,
  icon,
  color,
  suffix,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  suffix?: string;
}) {
  return (
    <div
      className="p-4 rounded-xl border backdrop-blur-sm"
      style={{
        borderColor: `${color}20`,
        background: `linear-gradient(135deg, ${color}08, ${color}03)`,
        boxShadow: `0 4px 24px ${color}08`,
      }}
    >
      <div className="flex items-center gap-2 mb-2">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: `${color}15`, color }}
        >
          {icon}
        </div>
        <span className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--text-muted)" }}>
          {label}
        </span>
      </div>
      <p className="text-2xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
        {value}{suffix}
      </p>
    </div>
  );
}

function AttackDistributionBar({
  distribution,
  total,
}: {
  distribution: Record<string, number>;
  total: number;
}) {
  const sorted = Object.entries(distribution)
    .filter(([, count]) => count > 0)
    .sort(([, a], [, b]) => b - a);

  if (sorted.length === 0) {
    return (
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        No attack distribution data
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {sorted.map(([type, count]) => {
        const pct = total > 0 ? (count / total) * 100 : 0;
        const color = ATTACK_COLORS[type] || "var(--accent-cyan)";
        return (
          <div key={type} className="flex items-center gap-3">
            <span className="text-xs font-mono w-20 truncate" style={{ color: "var(--text-muted)" }}>
              {type}
            </span>
            <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
              <motion.div
                className="h-full rounded-full"
                style={{ background: color }}
                initial={{ width: 0 }}
                animate={{ width: `${pct}%` }}
                transition={{ duration: 0.6, ease: "easeOut" }}
              />
            </div>
            <span className="text-xs font-mono w-16 text-right" style={{ color: "var(--text-secondary)" }}>
              {count} ({pct.toFixed(0)}%)
            </span>
          </div>
        );
      })}
    </div>
  );
}

function DriftTrendChart({
  trend,
}: {
  trend: Array<{ time: string; score: number; status: string }>;
}) {
  if (trend.length === 0) {
    return (
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        No drift trend data
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {trend.slice(0, 10).map((d, i) => (
        <div key={i} className="flex items-center gap-3">
          <span className="text-[10px] w-16 font-mono" style={{ color: "var(--text-muted)" }}>
            {d.time}
          </span>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
            <motion.div
              className="h-full rounded-full"
              style={{
                background:
                  d.status === "critical" ? "var(--accent-red)"
                    : d.status === "warning" ? "var(--accent-amber)"
                      : "var(--accent-green)",
              }}
              initial={{ width: 0 }}
              animate={{ width: `${Math.min(d.score, 100)}%` }}
              transition={{ duration: 0.5, delay: i * 0.05 }}
            />
          </div>
          <span className="text-xs font-mono w-14 text-right" style={{ color: "var(--text-secondary)" }}>
            {d.score.toFixed(1)}
          </span>
          <span
            className="text-[10px] font-bold uppercase w-16 text-right"
            style={{
              color:
                d.status === "critical" ? "var(--accent-red)"
                  : d.status === "warning" ? "var(--accent-amber)"
                    : "var(--accent-green)",
            }}
          >
            {d.status}
          </span>
        </div>
      ))}
    </div>
  );
}

function TimelineItem({
  timestamp,
  message,
  type,
}: {
  timestamp: string;
  message: string;
  type: string;
}) {
  const color =
    type === "critical" ? "var(--accent-red)"
      : type === "high" ? "var(--accent-amber)"
        : "var(--accent-cyan)";
  return (
    <div className="flex gap-3 items-start">
      <div className="flex flex-col items-center">
        <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
        <div className="w-px flex-1 mt-1" style={{ background: "rgba(255,255,255,0.06)" }} />
      </div>
      <div className="pb-4">
        <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
          {new Date(timestamp).toLocaleString()}
        </p>
        <p className="text-xs mt-1" style={{ color: "var(--text-primary)" }}>
          {message}
        </p>
      </div>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between py-2 border-b" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>{label}</span>
      <span className="text-xs font-mono font-bold" style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}

export default function Reports() {
  const [selectedReport, setSelectedReport] = useState<ReportType | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const toggleSection = (key: string) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const compareHistory = usePredictionStore((s) => s.compareHistory);
  const driftHistory = usePredictionStore((s) => s.driftHistory);
  const lastPrediction = usePredictionStore((s) => s.lastPrediction);
  const systemStore = useSystemStore();

  const stats = useMemo(() => {
    const preds = predictionHistory.length;
    const comp = compareHistory.length;
    const criticalAlerts = predictionHistory.filter((p) => p.riskLevel === "CRITICAL").length;
    const highAlerts = predictionHistory.filter((p) => p.riskLevel === "HIGH").length;
    const averageConfidence = preds > 0
      ? predictionHistory.reduce((sum, p) => sum + p.confidence, 0) / preds
      : 0;
    const criticalRate = preds > 0 ? ((criticalAlerts / preds) * 100) : 0;
    const attackDistribution: Record<string, number> = {};
    predictionHistory.forEach((p) => { attackDistribution[p.predictedAttack] = (attackDistribution[p.predictedAttack] || 0) + 1; });
    const mostFrequentAttack = Object.entries(attackDistribution).sort(([, a], [, b]) => b - a)[0]?.[0] || "N/A";
    const agreements = compareHistory.filter((c) => c.modelsAgree).length;
    const agreementRate = comp > 0 ? agreements / comp : 0;
    const conflictRate = comp > 0 ? 1 - agreementRate : 0;
    const averageLatency = comp > 0 ? compareHistory.reduce((sum, c) => sum + c.latencyMs, 0) / comp : 0;
    const confidenceTrend = predictionHistory.map((p) => ({ time: p.timestamp, confidence: p.confidence }));
    return { totalPredictions: preds, totalComparisons: comp, totalCompares: comp, criticalAlerts, highAlerts, averageConfidence, criticalRate, attackDistribution, mostFrequentAttack, agreementRate, conflictRate, averageLatency, confidenceTrend };
  }, [predictionHistory, compareHistory]);

  const hasData = stats.totalPredictions > 0;

  const mlCount = useMemo(
    () => compareHistory.filter((c) => c.mlPrediction !== "N/A").length,
    [compareHistory]
  );

  const markovCount = useMemo(
    () => compareHistory.filter((c) => c.markovPrediction !== "N/A").length,
    [compareHistory]
  );

  const confidenceStats = useMemo(() => {
    if (predictionHistory.length === 0) return { min: 0, max: 0, avg: 0 };
    const confs = predictionHistory.map((p) => p.confidence);
    return {
      min: Math.min(...confs),
      max: Math.max(...confs),
      avg: stats.averageConfidence,
    };
  }, [predictionHistory, stats.averageConfidence]);

  const driftDistribution = useMemo(() => {
    const dist = { stable: 0, warning: 0, critical: 0 };
    driftHistory.forEach((d) => {
      if (d.status in dist) dist[d.status as keyof typeof dist]++;
    });
    return dist;
  }, [driftHistory]);

  const currentDriftScore = useMemo(() => {
    if (driftHistory.length === 0) return 0;
    return driftHistory[0].score;
  }, [driftHistory]);

  const threatScore = useMemo(() => {
    if (!stats || stats.totalPredictions === 0) return 0;
    const criticalWeight = stats.criticalAlerts * 25;
    const highWeight = stats.highAlerts * 10;
    const confidencePenalty = (1 - stats.averageConfidence) * 20;
    const raw = criticalWeight + highWeight + confidencePenalty;
    return Math.min(Math.round(raw), 100);
  }, [stats]);

  const threatRecommendations = useMemo(() => {
    const recs: string[] = [];
    if (stats.criticalAlerts > 0) {
      recs.push("Investigate critical threats immediately");
    }
    if (stats.highAlerts > 0) {
      recs.push("Review high-severity alerts for potential escalation");
    }
    if (driftDistribution.warning > 0 || driftDistribution.critical > 0) {
      recs.push("Review drift data for model degradation");
    }
    if (stats.averageConfidence < 0.5) {
      recs.push("Low average confidence — consider model retraining");
    }
    if (stats.conflictRate > 0.3) {
      recs.push("High model conflict rate — investigate disagreement causes");
    }
    if (recs.length === 0) {
      recs.push("System operating within normal parameters");
    }
    return recs;
  }, [stats, driftDistribution]);

  const incidentRecommendations = useMemo(() => {
    const recs: string[] = [];
    const recentAttacks = predictionHistory.slice(0, 10).map((p) => p.predictedAttack);

    if (stats.criticalAlerts > 0) {
      recs.push("Activate IR playbook for critical threats");
    }
    if (recentAttacks.some((a) => a === "DDoS")) {
      recs.push("Enable traffic scrubbing and DDoS mitigation");
    }
    if (recentAttacks.some((a) => a === "BruteForce" || a === "Infiltration")) {
      recs.push("Isolate affected systems and rotate credentials");
    }
    if (recentAttacks.some((a) => a === "PortScan")) {
      recs.push("Review firewall rules and close unnecessary ports");
    }
    if (recentAttacks.some((a) => a === "Bot")) {
      recs.push("Deploy bot detection filters at network edge");
    }
    if (recentAttacks.some((a) => a === "WebAttack")) {
      recs.push("Activate WAF rules and review web application logs");
    }
    if (recentAttacks.some((a) => a === "DoS")) {
      recs.push("Enable rate limiting and traffic shaping");
    }
    if (recs.length === 0) {
      recs.push("Monitor for new incident patterns");
    }
    return recs;
  }, [predictionHistory, stats.criticalAlerts]);

  const driftRecommendations = useMemo(() => {
    const recs: string[] = [];
    if (driftDistribution.critical > 0) {
      recs.push("Critical drift detected — initiate model retraining");
    }
    if (driftDistribution.warning > 2) {
      recs.push("Multiple warning-level drift events — investigate data pipeline");
    }
    if (currentDriftScore > 0.7) {
      recs.push("High drift score — validate input feature distributions");
    }
    if (driftHistory.length > 5) {
      const recentScores = driftHistory.slice(0, 5).map((d) => d.score);
      const trend = recentScores[0] - recentScores[recentScores.length - 1];
      if (trend > 0.1) {
        recs.push("Upward drift trend detected — schedule baseline recalibration");
      }
    }
    if (recs.length === 0) {
      recs.push("Drift levels within acceptable bounds");
    }
    return recs;
  }, [driftHistory, driftDistribution, currentDriftScore]);

  const handleExportCSV = useCallback(() => {
    if (!selectedReport) return;

    const rows: string[] = [];
    rows.push(["Metric", "Value"].map(csvEscape).join(","));

    if (selectedReport === "threat") {
      rows.push(["Report Type", "Threat Analysis"].map(csvEscape).join(","));
      rows.push(["Generated At", new Date().toISOString()].map(csvEscape).join(","));
      rows.push(["Total Predictions", String(stats.totalPredictions)].map(csvEscape).join(","));
      rows.push(["Most Frequent Attack", stats.mostFrequentAttack].map(csvEscape).join(","));
      rows.push(["Average Confidence", `${(stats.averageConfidence * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Critical Alerts", String(stats.criticalAlerts)].map(csvEscape).join(","));
      rows.push(["High Alerts", String(stats.highAlerts)].map(csvEscape).join(","));
      rows.push(["Risk Score", String(threatScore)].map(csvEscape).join(","));
      rows.push("");
      rows.push(["Attack Type", "Count", "Percentage"].map(csvEscape).join(","));
      Object.entries(stats.attackDistribution)
        .filter(([, c]) => c > 0)
        .sort(([, a], [, b]) => b - a)
        .forEach(([type, count]) => {
          const pct = stats.totalPredictions > 0 ? (count / stats.totalPredictions) * 100 : 0;
          rows.push([type, String(count), `${pct.toFixed(1)}%`].map(csvEscape).join(","));
        });
    } else if (selectedReport === "performance") {
      rows.push(["Report Type", "Model Performance"].map(csvEscape).join(","));
      rows.push(["Generated At", new Date().toISOString()].map(csvEscape).join(","));
      rows.push(["Total Comparisons", String(stats.totalCompares)].map(csvEscape).join(","));
      rows.push(["ML Predictions", String(mlCount)].map(csvEscape).join(","));
      rows.push(["Markov Predictions", String(markovCount)].map(csvEscape).join(","));
      rows.push(["Agreement Rate", `${(stats.agreementRate * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Conflict Rate", `${(stats.conflictRate * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Avg Confidence", `${(confidenceStats.avg * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Min Confidence", `${(confidenceStats.min * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Max Confidence", `${(confidenceStats.max * 100).toFixed(1)}%`].map(csvEscape).join(","));
      rows.push(["Avg Latency", `${stats.averageLatency.toFixed(2)}ms`].map(csvEscape).join(","));
      rows.push(["System Uptime", `${(systemStore.uptime / 1000).toFixed(0)}s`].map(csvEscape).join(","));
    } else if (selectedReport === "incident") {
      rows.push(["Report Type", "Incident Report"].map(csvEscape).join(","));
      rows.push(["Generated At", new Date().toISOString()].map(csvEscape).join(","));
      rows.push("");
      rows.push(["Timestamp", "Attack", "Confidence", "Severity", "Sequence", "Model", "Explanation"].map(csvEscape).join(","));
      predictionHistory.slice(0, 10).forEach((p) => {
        rows.push([
          new Date(p.timestamp).toLocaleString(),
          p.predictedAttack,
          `${(p.confidence * 100).toFixed(1)}%`,
          p.riskLevel,
          p.sequence.join(";"),
          p.model,
          p.explanation.reasoning.join("; "),
        ].map(csvEscape).join(","));
      });
      rows.push("");
      rows.push(["Recommended Actions"].map(csvEscape).join(","));
      incidentRecommendations.forEach((r) => {
        rows.push([r].map(csvEscape).join(","));
      });
    } else if (selectedReport === "drift") {
      rows.push(["Report Type", "Drift Analysis"].map(csvEscape).join(","));
      rows.push(["Generated At", new Date().toISOString()].map(csvEscape).join(","));
      rows.push(["Current Drift Score", String(currentDriftScore)].map(csvEscape).join(","));
      rows.push(["Total Measurements", String(driftHistory.length)].map(csvEscape).join(","));
      rows.push(["Stable", String(driftDistribution.stable)].map(csvEscape).join(","));
      rows.push(["Warning", String(driftDistribution.warning)].map(csvEscape).join(","));
      rows.push(["Critical", String(driftDistribution.critical)].map(csvEscape).join(","));
      rows.push("");
      rows.push(["Timestamp", "Score", "Status"].map(csvEscape).join(","));
      driftHistory.forEach((d) => {
        rows.push([new Date(d.timestamp).toLocaleString(), String(d.score), d.status].map(csvEscape).join(","));
      });
    }

    const csv = rows.join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-${selectedReport}-report.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [selectedReport, stats, mlCount, markovCount, confidenceStats, threatScore, predictionHistory, driftHistory, driftDistribution, currentDriftScore, incidentRecommendations, systemStore.uptime]);

  const handleExportJSON = useCallback(() => {
    if (!selectedReport) return;

    let data: Record<string, unknown>;

    if (selectedReport === "threat") {
      data = {
        reportType: "threat",
        generatedAt: new Date().toISOString(),
        totalPredictions: stats.totalPredictions,
        attackDistribution: stats.attackDistribution,
        mostFrequentAttack: stats.mostFrequentAttack,
        averageConfidence: stats.averageConfidence,
        criticalAlerts: stats.criticalAlerts,
        highAlerts: stats.highAlerts,
        riskScore: threatScore,
        latestPrediction: lastPrediction
          ? {
              attack: lastPrediction.predictedAttack,
              confidence: lastPrediction.confidence,
              severity: lastPrediction.riskLevel,
              model: lastPrediction.model,
              timestamp: lastPrediction.timestamp,
            }
          : null,
        recommendations: threatRecommendations,
      };
    } else if (selectedReport === "performance") {
      data = {
        reportType: "performance",
        generatedAt: new Date().toISOString(),
        totalComparisons: stats.totalCompares,
        mlPredictions: mlCount,
        markovPredictions: markovCount,
        agreementRate: stats.agreementRate,
        conflictRate: stats.conflictRate,
        confidenceStats,
        averageLatency: stats.averageLatency,
        driftStatus: driftDistribution,
        systemUptime: systemStore.uptime,
      };
    } else if (selectedReport === "incident") {
      data = {
        reportType: "incident",
        generatedAt: new Date().toISOString(),
        eventTimeline: predictionHistory.slice(0, 10).map((p) => ({
          timestamp: p.timestamp,
          predictedAttack: p.predictedAttack,
          confidence: p.confidence,
          riskLevel: p.riskLevel,
          severityScore: p.severityScore,
          sequence: p.sequence,
          model: p.model,
          explanation: p.explanation,
        })),
        recommendedActions: incidentRecommendations,
      };
    } else if (selectedReport === "drift") {
      data = {
        reportType: "drift",
        generatedAt: new Date().toISOString(),
        currentDriftScore,
        totalMeasurements: driftHistory.length,
        driftDistribution,
        confidenceTrend: stats.confidenceTrend,
        measurements: driftHistory.map((d) => ({
          timestamp: d.timestamp,
          score: d.score,
          status: d.status,
        })),
        recommendations: driftRecommendations,
      };
    } else {
      return;
    }

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-${selectedReport}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [selectedReport, stats, mlCount, markovCount, confidenceStats, threatScore, lastPrediction, threatRecommendations, predictionHistory, incidentRecommendations, currentDriftScore, driftHistory, driftDistribution, driftRecommendations, systemStore.uptime]);

  const handleExportPDF = useCallback(() => {
    window.print();
  }, []);

  const renderThreatReport = () => {
    if (!hasData) {
      return (
        <div className="p-8 text-center">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No prediction data available. Submit attack sequences to generate reports.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard
            label="Total Predictions"
            value={stats.totalPredictions}
            icon={<Shield className="w-4 h-4" />}
            color="var(--accent-cyan)"
          />
          <MetricCard
            label="Avg Confidence"
            value={(stats.averageConfidence * 100).toFixed(1)}
            icon={<BarChart3 className="w-4 h-4" />}
            color="var(--accent-green)"
            suffix="%"
          />
          <MetricCard
            label="Critical Alerts"
            value={stats.criticalAlerts}
            icon={<AlertTriangle className="w-4 h-4" />}
            color="var(--accent-red)"
          />
          <MetricCard
            label="Risk Score"
            value={threatScore}
            icon={<Target className="w-4 h-4" />}
            color="var(--accent-amber)"
            suffix="/100"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Attack Distribution
            </p>
            <AttackDistributionBar
              distribution={stats.attackDistribution}
              total={stats.totalPredictions}
            />
          </div>

          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Key Metrics
            </p>
            <StatRow label="Most Frequent Attack" value={stats.mostFrequentAttack} />
            <StatRow label="High Alerts" value={stats.highAlerts} />
            <StatRow label="Agreement Rate" value={`${(stats.agreementRate * 100).toFixed(1)}%`} />
            <StatRow label="Total Comparisons" value={stats.totalCompares} />
          </div>
        </div>

        {lastPrediction && (
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: `${lastPrediction.riskLevel === "CRITICAL" ? "var(--accent-red)" : "var(--accent-cyan)"}20`,
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Latest Prediction
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Attack</p>
                <p className="text-sm font-mono font-bold" style={{ color: "var(--text-primary)" }}>
                  {lastPrediction.predictedAttack}
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Confidence</p>
                <p className="text-sm font-mono font-bold" style={{ color: "var(--text-primary)" }}>
                  {(lastPrediction.confidence * 100).toFixed(1)}%
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Severity</p>
                <RiskBadge level={lastPrediction.riskLevel} />
              </div>
              <div>
                <p className="text-[10px] uppercase" style={{ color: "var(--text-muted)" }}>Model</p>
                <p className="text-sm font-mono" style={{ color: "var(--text-primary)" }}>
                  {lastPrediction.model}
                </p>
              </div>
            </div>
          </div>
        )}

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(239,68,68,0.1)",
            background: "linear-gradient(135deg, rgba(239,68,68,0.04), rgba(239,68,68,0.01))",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--accent-red)" }}>
            <Zap className="w-3 h-3 inline mr-1" />
            Recommendations
          </p>
          <ul className="space-y-1.5">
            {threatRecommendations.map((rec, i) => (
              <li key={i} className="text-xs flex items-start gap-2" style={{ color: "var(--text-secondary)" }}>
                <span style={{ color: "var(--accent-red)" }}>•</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      </div>
    );
  };

  const renderPerformanceReport = () => {
    if (stats.totalCompares === 0) {
      return (
        <div className="p-8 text-center">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No model comparison data available. Run comparisons to generate this report.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard
            label="Total Comparisons"
            value={stats.totalCompares}
            icon={<BarChart3 className="w-4 h-4" />}
            color="var(--accent-cyan)"
          />
          <MetricCard
            label="Agreement Rate"
            value={(stats.agreementRate * 100).toFixed(1)}
            icon={<Activity className="w-4 h-4" />}
            color="var(--accent-green)"
            suffix="%"
          />
          <MetricCard
            label="Avg Latency"
            value={stats.averageLatency.toFixed(1)}
            icon={<Cpu className="w-4 h-4" />}
            color="var(--accent-purple)"
            suffix="ms"
          />
          <MetricCard
            label="System Uptime"
            value={(systemStore.uptime / 1000).toFixed(0)}
            icon={<Clock className="w-4 h-4" />}
            color="var(--accent-amber)"
            suffix="s"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Model Breakdown
            </p>
            <StatRow label="ML Predictions" value={mlCount} />
            <StatRow label="Markov Predictions" value={markovCount} />
            <StatRow label="Agreements" value={Math.round(stats.agreementRate * stats.totalCompares)} />
            <StatRow label="Conflicts" value={stats.totalCompares - Math.round(stats.agreementRate * stats.totalCompares)} />
            <StatRow label="Conflict Rate" value={`${(stats.conflictRate * 100).toFixed(1)}%`} />
          </div>

          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Confidence Statistics
            </p>
            <StatRow label="Minimum" value={`${(confidenceStats.min * 100).toFixed(1)}%`} />
            <StatRow label="Maximum" value={`${(confidenceStats.max * 100).toFixed(1)}%`} />
            <StatRow label="Average" value={`${(confidenceStats.avg * 100).toFixed(1)}%`} />
            <StatRow label="Drift Status" value={
              driftDistribution.critical > 0 ? "CRITICAL"
                : driftDistribution.warning > 0 ? "WARNING"
                  : "STABLE"
            } />
          </div>
        </div>

        {compareHistory.length > 0 && (
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs uppercase tracking-widest" style={{ color: "var(--text-muted)" }}>
                Recent Comparisons
              </p>
              <button
                onClick={() => toggleSection("compares")}
                className="text-xs flex items-center gap-1"
                style={{ color: "var(--accent-cyan)" }}
              >
                {expandedSections["compares"] ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                {expandedSections["compares"] ? "Collapse" : "Expand"}
              </button>
            </div>
            <div style={{ maxHeight: expandedSections["compares"] ? "none" : "200px", overflow: "auto" }}>
              <table className="w-full text-xs">
                <thead className="sticky top-0" style={{ background: "var(--bg-card)" }}>
                  <tr className="border-b" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
                    <th className="text-left py-2 font-medium" style={{ color: "var(--text-muted)" }}>Time</th>
                    <th className="text-left py-2 font-medium" style={{ color: "var(--text-muted)" }}>ML</th>
                    <th className="text-left py-2 font-medium" style={{ color: "var(--text-muted)" }}>Markov</th>
                    <th className="text-left py-2 font-medium" style={{ color: "var(--text-muted)" }}>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {compareHistory.slice(0, expandedSections["compares"] ? 50 : 10).map((c, i) => (
                    <tr key={i} className="border-b" style={{ borderColor: "rgba(255,255,255,0.03)" }}>
                      <td className="py-2" style={{ color: "var(--text-secondary)" }}>
                        {new Date(c.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2 font-mono" style={{ color: "var(--text-primary)" }}>{c.mlPrediction}</td>
                      <td className="py-2 font-mono" style={{ color: "var(--text-primary)" }}>{c.markovPrediction}</td>
                      <td className="py-2">
                        <RiskBadge level={c.modelsAgree ? "LOW" : "HIGH"} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderIncidentReport = () => {
    const recent = predictionHistory.slice(0, 10);

    if (recent.length === 0) {
      return (
        <div className="p-8 text-center">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No prediction data available. Submit attack sequences to generate reports.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard
            label="Events (Last 10)"
            value={recent.length}
            icon={<Clock className="w-4 h-4" />}
            color="var(--accent-cyan)"
          />
          <MetricCard
            label="Critical Events"
            value={recent.filter((p) => p.riskLevel === "CRITICAL").length}
            icon={<AlertTriangle className="w-4 h-4" />}
            color="var(--accent-red)"
          />
          <MetricCard
            label="Avg Severity"
            value={
              recent.length > 0
                ? (recent.reduce((s, p) => s + p.severityScore, 0) / recent.length).toFixed(2)
                : "0"
            }
            icon={<Target className="w-4 h-4" />}
            color="var(--accent-amber)"
          />
          <MetricCard
            label="Unique Attacks"
            value={new Set(recent.map((p) => p.predictedAttack)).size}
            icon={<Zap className="w-4 h-4" />}
            color="var(--accent-purple)"
          />
        </div>

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(255,255,255,0.06)",
            background: "rgba(255,255,255,0.02)",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
            Event Timeline
          </p>
          <div className="space-y-0">
            {recent.map((p, i) => (
              <TimelineItem
                key={i}
                timestamp={p.timestamp}
                message={`${p.predictedAttack} — ${(p.confidence * 100).toFixed(1)}% confidence (${p.riskLevel})`}
                type={p.riskLevel === "CRITICAL" ? "critical" : p.riskLevel === "HIGH" ? "high" : "normal"}
              />
            ))}
          </div>
        </div>

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(255,255,255,0.06)",
            background: "rgba(255,255,255,0.02)",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
            Severity Progression
          </p>
          <div className="flex items-end gap-1 h-16">
            {recent.reverse().map((p, i) => {
              const maxSeverity = 10;
              const height = Math.max((p.severityScore / maxSeverity) * 100, 8);
              const color =
                p.riskLevel === "CRITICAL" ? "var(--accent-red)"
                  : p.riskLevel === "HIGH" ? "var(--accent-amber)"
                    : p.riskLevel === "MEDIUM" ? "var(--accent-cyan)"
                      : "var(--accent-green)";
              return (
                <motion.div
                  key={i}
                  className="flex-1 rounded-t"
                  style={{ background: color, opacity: 0.8 }}
                  initial={{ height: 0 }}
                  animate={{ height: `${height}%` }}
                  transition={{ duration: 0.4, delay: i * 0.05 }}
                />
              );
            })}
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Oldest</span>
            <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Newest</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Model Decisions
            </p>
            <div className="space-y-2">
              {recent.map((p, i) => (
                <div key={i} className="flex items-center justify-between text-xs py-1 border-b" style={{ borderColor: "rgba(255,255,255,0.03)" }}>
                  <span className="font-mono" style={{ color: "var(--text-primary)" }}>
                    {p.model}
                  </span>
                  <span style={{ color: "var(--text-secondary)" }}>
                    → {p.predictedAttack} ({(p.confidence * 100).toFixed(0)}%)
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Prediction Sequences
            </p>
            <div className="space-y-2">
              {recent.map((p, i) => (
                <div key={i} className="text-xs py-1 border-b" style={{ borderColor: "rgba(255,255,255,0.03)" }}>
                  <div className="flex items-center justify-between">
                    <RiskBadge level={p.riskLevel} />
                    <span className="font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>
                      [{p.sequence.join(", ")}]
                    </span>
                  </div>
                  {p.explanation && (
                    <p className="mt-1 text-[10px]" style={{ color: "var(--text-muted)" }}>
                      {p.explanation.reasoning[0] || p.explanation.pattern_match}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(255,165,0,0.1)",
            background: "linear-gradient(135deg, rgba(255,165,0,0.04), rgba(255,165,0,0.01))",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--accent-amber)" }}>
            <Zap className="w-3 h-3 inline mr-1" />
            Recommended Response Actions
          </p>
          <ul className="space-y-1.5">
            {incidentRecommendations.map((rec, i) => (
              <li key={i} className="text-xs flex items-start gap-2" style={{ color: "var(--text-secondary)" }}>
                <span style={{ color: "var(--accent-amber)" }}>•</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      </div>
    );
  };

  const renderDriftReport = () => {
    if (driftHistory.length === 0) {
      return (
        <div className="p-8 text-center">
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No drift data available. Run drift detection to establish baseline measurements.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard
            label="Current Drift Score"
            value={currentDriftScore.toFixed(3)}
            icon={<Activity className="w-4 h-4" />}
            color="var(--accent-purple)"
          />
          <MetricCard
            label="Total Measurements"
            value={driftHistory.length}
            icon={<BarChart3 className="w-4 h-4" />}
            color="var(--accent-cyan)"
          />
          <MetricCard
            label="Stable Events"
            value={driftDistribution.stable}
            icon={<Shield className="w-4 h-4" />}
            color="var(--accent-green)"
          />
          <MetricCard
            label="Critical Events"
            value={driftDistribution.critical}
            icon={<AlertTriangle className="w-4 h-4" />}
            color="var(--accent-red)"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Status Distribution
            </p>
            <StatRow label="Stable" value={driftDistribution.stable} />
            <StatRow label="Warning" value={driftDistribution.warning} />
            <StatRow label="Critical" value={driftDistribution.critical} />
            <StatRow label="Warning Rate" value={`${driftHistory.length > 0 ? ((driftDistribution.warning / driftHistory.length) * 100).toFixed(1) : 0}%`} />
            <StatRow label="Critical Rate" value={`${driftHistory.length > 0 ? ((driftDistribution.critical / driftHistory.length) * 100).toFixed(1) : 0}%`} />
          </div>

          <div
            className="p-4 rounded-xl border backdrop-blur-sm"
            style={{
              borderColor: "rgba(255,255,255,0.06)",
              background: "rgba(255,255,255,0.02)",
            }}
          >
            <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
              Confidence Trend
            </p>
            {stats.confidenceTrend.length > 0 ? (
              <div className="space-y-1">
                {stats.confidenceTrend.slice(-10).map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="w-14 font-mono" style={{ color: "var(--text-muted)" }}>{c.time}</span>
                    <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                      <motion.div
                        className="h-full rounded-full"
                        style={{ background: "var(--accent-cyan)" }}
                        initial={{ width: 0 }}
                        animate={{ width: `${c.confidence}%` }}
                        transition={{ duration: 0.4 }}
                      />
                    </div>
                    <span className="w-10 text-right font-mono" style={{ color: "var(--text-secondary)" }}>{c.confidence}%</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>No confidence trend data</p>
            )}
          </div>
        </div>

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(255,255,255,0.06)",
            background: "rgba(255,255,255,0.02)",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>
            Drift Measurements Over Time
          </p>
          <DriftTrendChart
            trend={driftHistory.map((d) => ({
              time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false }),
              score: d.score,
              status: d.status,
            }))}
          />
        </div>

        <div
          className="p-4 rounded-xl border backdrop-blur-sm"
          style={{
            borderColor: "rgba(128,0,255,0.1)",
            background: "linear-gradient(135deg, rgba(128,0,255,0.04), rgba(128,0,255,0.01))",
          }}
        >
          <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "var(--accent-purple)" }}>
            <Zap className="w-3 h-3 inline mr-1" />
            Recommendations
          </p>
          <ul className="space-y-1.5">
            {driftRecommendations.map((rec, i) => (
              <li key={i} className="text-xs flex items-start gap-2" style={{ color: "var(--text-secondary)" }}>
                <span style={{ color: "var(--accent-purple)" }}>•</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      </div>
    );
  };

  const renderReportContent = () => {
    switch (selectedReport) {
      case "threat":
        return renderThreatReport();
      case "performance":
        return renderPerformanceReport();
      case "incident":
        return renderIncidentReport();
      case "drift":
        return renderDriftReport();
      default:
        return null;
    }
  };

  const selectedConfig = selectedReport ? REPORT_TYPES.find((r) => r.id === selectedReport) : null;

  return (
    <div className="h-full p-6 flex flex-col gap-6 overflow-hidden">
      <div className="flex items-start justify-between">
        <div>
          <p
            className="text-xs font-mono tracking-[0.2em] uppercase mb-2"
            style={{ color: "var(--accent-cyan)" }}
          >
            Intelligence Center
          </p>
          <h1
            className="text-2xl font-display font-semibold"
            style={{ color: "var(--text-primary)" }}
          >
            Threat Intelligence Reports
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Generate dynamic reports from real-time threat data and predictions.
          </p>
        </div>
      </div>

      <GlassPanel title="Select Report Type" icon={<FileText className="w-4 h-4" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {REPORT_TYPES.map((report) => (
            <motion.button
              key={report.id}
              onClick={() => setSelectedReport(report.id)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="relative p-4 rounded-xl border text-left transition-all duration-300 backdrop-blur-sm"
              style={{
                background: selectedReport === report.id
                  ? `linear-gradient(135deg, ${report.color}12, ${report.color}05)`
                  : "rgba(255,255,255,0.03)",
                borderColor: selectedReport === report.id
                  ? `${report.color}30`
                  : "rgba(255,255,255,0.06)",
                boxShadow: selectedReport === report.id
                  ? `0 0 24px ${report.color}15, inset 0 1px 0 ${report.color}10`
                  : "none",
              }}
            >
              <div className="flex items-start gap-3">
                <div
                  className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: `${report.color}15`, color: report.color }}
                >
                  {report.icon}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                    {report.title}
                  </p>
                  <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                    {report.description}
                  </p>
                </div>
              </div>
              {selectedReport === report.id && (
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  className="absolute top-2 right-2 w-2.5 h-2.5 rounded-full"
                  style={{ background: report.color, boxShadow: `0 0 10px ${report.color}` }}
                />
              )}
            </motion.button>
          ))}
        </div>
      </GlassPanel>

      <AnimatePresence>
        {selectedReport && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="flex-1 min-h-0 flex flex-col"
          >
            <GlassPanel
              title={selectedConfig?.title || "Report"}
              icon={selectedConfig?.icon}
              className="flex-1 min-h-0 flex flex-col"
            >
              <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="text-xs flex items-center gap-1" style={{ color: "var(--text-secondary)" }}>
                      <Clock className="w-3 h-3" />
                      Generated {new Date().toLocaleString()}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={handleExportPDF}
                      className="px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all hover:scale-105"
                      style={{
                        borderColor: "rgba(255,255,255,0.1)",
                        background: "rgba(255,255,255,0.03)",
                        color: "var(--text-secondary)",
                      }}
                    >
                      PDF
                    </button>
                    <button
                      onClick={handleExportCSV}
                      className="px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all hover:scale-105"
                      style={{
                        borderColor: "rgba(0,229,255,0.2)",
                        background: "rgba(0,229,255,0.1)",
                        color: "var(--accent-cyan)",
                      }}
                    >
                      <Download className="w-3 h-3 inline mr-1" />
                      CSV
                    </button>
                    <button
                      onClick={handleExportJSON}
                      className="px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all hover:scale-105"
                      style={{
                        borderColor: "rgba(0,229,255,0.2)",
                        background: "rgba(0,229,255,0.1)",
                        color: "var(--accent-cyan)",
                      }}
                    >
                      <Download className="w-3 h-3 inline mr-1" />
                      JSON
                    </button>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto space-y-4 pr-2">
                  {renderReportContent()}
                </div>
              </div>
            </GlassPanel>
          </motion.div>
        )}
      </AnimatePresence>

      {!selectedReport && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <FileText className="w-12 h-12 mx-auto mb-3" style={{ color: "var(--text-muted)" }} />
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Select a report type above to generate a preview
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
