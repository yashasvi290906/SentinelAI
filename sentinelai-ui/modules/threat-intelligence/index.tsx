"use client";

import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import {
  FileText,
  Brain,
  BookOpen,
  Search,
  TrendingUp,
  Activity,
  AlertTriangle,
  Shield,
  GitCompareArrows,
  BarChart3,
  Zap,
} from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import GlassPanel from "@/components/ui/GlassPanel";
import Provenance from "@/components/ui/Provenance";
import Explanation from "@/components/ui/Explanation";
import { generateReport, type ReportType } from "@/services/report.service";
import { ATTACK_COLORS } from "@/lib/config";

type TabId = "feed" | "reports" | "insights" | "docs";

const TABS: Array<{ id: TabId; label: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }> }> = [
  { id: "feed", label: "Threat Feed", icon: Activity },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "insights", label: "Model Insights", icon: Brain },
  { id: "docs", label: "Documentation", icon: BookOpen },
];

export default function ThreatIntelligence() {
  const [activeTab, setActiveTab] = useState<TabId>("feed");
  const [searchQuery, setSearchQuery] = useState("");

  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const compareHistory = usePredictionStore((s) => s.compareHistory);
  const driftHistory = usePredictionStore((s) => s.driftHistory);
  const confidenceHistory = usePredictionStore((s) => s.confidenceHistory);
  const getStats = usePredictionStore((s) => s.getStats);

  const stats = useMemo(() => getStats(), [getStats]);

  const filteredPredictions = useMemo(() => {
    if (!searchQuery) return predictionHistory;
    const q = searchQuery.toLowerCase();
    return predictionHistory.filter(
      (p) =>
        p.predictedAttack.toLowerCase().includes(q) ||
        p.riskLevel.toLowerCase().includes(q) ||
        p.model.toLowerCase().includes(q)
    );
  }, [predictionHistory, searchQuery]);

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2" style={{ color: "var(--accent-cyan)" }}>
          Intelligence Center
        </p>
        <h1 className="text-3xl font-display font-bold" style={{ color: "var(--text-primary)" }}>
          Threat Intelligence
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Analyze prediction history, generate reports, and understand model behavior.
        </p>
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl" style={{ background: "rgba(8,20,32,0.5)", border: "1px solid rgba(0,229,255,0.06)" }}>
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition-all duration-200 flex-1 justify-center"
              style={{
                background: isActive ? "rgba(0,229,255,0.1)" : "transparent",
                color: isActive ? "var(--accent-cyan)" : "var(--text-muted)",
                border: isActive ? "1px solid rgba(0,229,255,0.15)" : "1px solid transparent",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      {activeTab === "feed" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col gap-4"
        >
          <Explanation text="The Threat Feed displays all predictions, model comparisons, and timeline events in a searchable table. Filter by attack type, risk level, or model to find specific patterns." />

          {/* Search */}
          <div
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl"
            style={{ background: "rgba(8,20,32,0.7)", border: "1px solid rgba(0,229,255,0.08)" }}
          >
            <Search className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
            <input
              type="text"
              placeholder="Search by attack type, risk level, or model..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-transparent outline-none text-xs font-mono"
              style={{ color: "var(--text-primary)" }}
            />
          </div>

          {/* Feed Table */}
          <GlassPanel title="Prediction History" icon={<Activity className="w-4 h-4" />}>
            {filteredPredictions.length === 0 ? (
              <div className="p-8 text-center">
                <Activity className="w-8 h-8 mx-auto mb-2" style={{ color: "var(--text-muted)", opacity: 0.3 }} />
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  {searchQuery ? "No results match your search" : "No predictions recorded yet"}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Time</th>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Attack</th>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Sequence</th>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Confidence</th>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Risk</th>
                      <th className="text-left py-2 px-3 font-mono font-medium" style={{ color: "var(--text-muted)" }}>Model</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredPredictions.slice(0, 50).map((pred) => (
                      <tr key={pred.id} className="border-b" style={{ borderColor: "rgba(0,229,255,0.03)" }}>
                        <td className="py-2.5 px-3 font-mono" style={{ color: "var(--text-secondary)" }}>
                          {new Date(pred.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold" style={{ color: ATTACK_COLORS[pred.predictedAttack] || "var(--text-primary)" }}>
                          {pred.predictedAttack}
                        </td>
                        <td className="py-2.5 px-3 font-mono" style={{ color: "var(--text-muted)" }}>
                          {pred.sequence.join(" → ")}
                        </td>
                        <td className="py-2.5 px-3 font-mono" style={{ color: "var(--accent-cyan)" }}>
                          {(pred.confidence * 100).toFixed(1)}%
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold"
                            style={{
                              background: pred.riskLevel === "CRITICAL" ? "rgba(255,61,61,0.12)" : pred.riskLevel === "HIGH" ? "rgba(255,45,85,0.12)" : pred.riskLevel === "MEDIUM" ? "rgba(255,176,32,0.12)" : "rgba(0,229,255,0.08)",
                              color: pred.riskLevel === "CRITICAL" ? "#FF3B3B" : pred.riskLevel === "HIGH" ? "#FF2D55" : pred.riskLevel === "MEDIUM" ? "#FFB020" : "var(--accent-cyan)",
                            }}
                          >
                            {pred.riskLevel}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono" style={{ color: "var(--text-muted)" }}>
                          {pred.model}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </GlassPanel>

          {/* Compare History */}
          {compareHistory.length > 0 && (
            <GlassPanel title="Model Comparison History" icon={<GitCompareArrows className="w-4 h-4" />}>
              <div className="space-y-2">
                {compareHistory.slice(0, 20).map((c) => (
                  <div key={c.id} className="flex items-center gap-4 px-3 py-2 rounded-lg" style={{ background: "rgba(255,255,255,0.01)" }}>
                    <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>
                      {new Date(c.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                    </span>
                    <span className="text-xs font-mono shrink-0" style={{ color: "var(--accent-cyan)" }}>
                      ML: {c.mlPrediction}
                    </span>
                    <span className="text-xs font-mono shrink-0" style={{ color: "var(--accent-purple)" }}>
                      Markov: {c.markovPrediction}
                    </span>
                    <span
                      className="text-[10px] font-mono px-2 py-0.5 rounded shrink-0"
                      style={{
                        background: c.modelsAgree ? "rgba(0,255,136,0.1)" : "rgba(255,77,109,0.1)",
                        color: c.modelsAgree ? "var(--accent-green)" : "var(--accent-red)",
                      }}
                    >
                      {c.modelsAgree ? "AGREE" : "CONFLICT"}
                    </span>
                  </div>
                ))}
              </div>
            </GlassPanel>
          )}

          <Provenance source="Prediction Store" />
        </motion.div>
      )}

      {activeTab === "reports" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col gap-4"
        >
          <Explanation text="Reports are generated dynamically from your prediction history, comparison data, and drift measurements. Every report reflects the current state of your data — no values are hardcoded." />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(["daily", "performance", "predictions", "drift"] as ReportType[]).map((type) => {
              const report = generateReport(type);
              const icons: Record<string, React.ComponentType<{ className?: string; style?: React.CSSProperties }>> = {
                daily: FileText,
                performance: BarChart3,
                predictions: TrendingUp,
                drift: Activity,
              };
              const colors: Record<string, string> = {
                daily: "var(--accent-cyan)",
                performance: "var(--accent-green)",
                predictions: "var(--accent-purple)",
                drift: "var(--accent-amber)",
              };
              const Icon = icons[type] || FileText;
              return (
                <motion.div
                  key={type}
                  whileHover={{ scale: 1.02 }}
                  className="rounded-xl p-4"
                  style={{
                    background: "rgba(8,20,32,0.7)",
                    border: "1px solid rgba(0,229,255,0.08)",
                  }}
                >
                  <div className="flex items-start gap-3">
                    <Icon className="w-5 h-5 shrink-0" style={{ color: colors[type] }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{report.title}</p>
                      <p className="text-[11px] mt-1 leading-relaxed" style={{ color: "var(--text-muted)" }}>{report.summary}</p>
                      <p className="text-[9px] font-mono mt-2" style={{ color: "var(--text-muted)", opacity: 0.6 }}>
                        Generated: {new Date(report.generatedAt).toLocaleTimeString("en-US", { hour12: false })}
                      </p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      )}

      {activeTab === "insights" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col gap-4"
        >
          <Explanation text="Model Insights shows how the ML and Markov models are performing over time. Track prediction distribution, agreement rates, drift trends, and confidence patterns to understand model behavior." />

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Total Predictions", value: String(stats.totalPredictions), color: "var(--accent-cyan)" },
              { label: "Avg Confidence", value: stats.totalPredictions > 0 ? `${(stats.averageConfidence * 100).toFixed(1)}%` : "—", color: "var(--accent-green)" },
              { label: "Agreement Rate", value: stats.totalCompares > 0 ? `${(stats.agreementRate * 100).toFixed(1)}%` : "—", color: "var(--accent-purple)" },
              { label: "Most Common", value: stats.mostFrequentAttack, color: "var(--accent-amber)" },
            ].map((item) => (
              <div key={item.label} className="rounded-xl p-4" style={{ background: "rgba(8,20,32,0.7)", border: "1px solid rgba(0,229,255,0.08)" }}>
                <p className="text-[10px] font-mono tracking-wider uppercase" style={{ color: "var(--text-muted)" }}>{item.label}</p>
                <p className="text-2xl font-display font-bold mt-1" style={{ color: item.color }}>{item.value}</p>
              </div>
            ))}
          </div>

          {/* Attack Distribution */}
          <GlassPanel title="Prediction Distribution" icon={<BarChart3 className="w-4 h-4" />}>
            {Object.keys(stats.attackDistribution).length === 0 ? (
              <p className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>No prediction data available</p>
            ) : (
              <div className="space-y-2">
                {Object.entries(stats.attackDistribution)
                  .sort(([, a], [, b]) => b - a)
                  .map(([type, count]) => (
                    <div key={type} className="flex items-center gap-3">
                      <span className="text-xs font-mono w-24 shrink-0" style={{ color: ATTACK_COLORS[type] || "var(--text-muted)" }}>{type}</span>
                      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                        <motion.div
                          className="h-full rounded-full"
                          style={{ background: ATTACK_COLORS[type] || "var(--accent-cyan)" }}
                          initial={{ width: 0 }}
                          animate={{ width: `${stats.totalPredictions > 0 ? (count / stats.totalPredictions) * 100 : 0}%` }}
                          transition={{ duration: 0.5 }}
                        />
                      </div>
                      <span className="text-xs font-mono w-12 text-right shrink-0" style={{ color: "var(--text-secondary)" }}>{count}</span>
                    </div>
                  ))}
              </div>
            )}
          </GlassPanel>

          {/* Confidence Trend */}
          <GlassPanel title="Confidence Trend" icon={<TrendingUp className="w-4 h-4" />}>
            {confidenceHistory.length === 0 ? (
              <p className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>No confidence data available</p>
            ) : (
              <div className="space-y-1">
                {confidenceHistory.slice(-20).map((c, i) => (
                  <div key={i} className="flex items-center gap-3 px-2 py-1.5">
                    <span className="text-[10px] font-mono w-16 shrink-0" style={{ color: "var(--text-muted)" }}>{c.time}</span>
                    <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                      <div className="h-full rounded-full" style={{ width: `${c.confidence}%`, background: "var(--accent-cyan)" }} />
                    </div>
                    <span className="text-[10px] font-mono w-12 text-right shrink-0" style={{ color: "var(--accent-cyan)" }}>{c.confidence}%</span>
                    <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--text-muted)" }}>{c.attack}</span>
                  </div>
                ))}
              </div>
            )}
          </GlassPanel>

          {/* Drift Trend */}
          <GlassPanel title="Drift Trend" icon={<Activity className="w-4 h-4" />}>
            {driftHistory.length === 0 ? (
              <p className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>No drift data available</p>
            ) : (
              <div className="space-y-1">
                {driftHistory.slice(-10).map((d, i) => (
                  <div key={i} className="flex items-center gap-3 px-2 py-1.5">
                    <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: "var(--text-muted)" }}>
                      {new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                    </span>
                    <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${Math.min(d.score * 100, 100)}%`,
                          background: d.status === "critical" ? "var(--accent-red)" : d.status === "warning" ? "var(--accent-amber)" : "var(--accent-green)",
                        }}
                      />
                    </div>
                    <span className="text-[10px] font-mono w-16 text-right shrink-0" style={{ color: "var(--text-secondary)" }}>{d.score.toFixed(3)}</span>
                    <span
                      className="text-[10px] font-mono font-bold uppercase w-16 text-right shrink-0"
                      style={{ color: d.status === "critical" ? "var(--accent-red)" : d.status === "warning" ? "var(--accent-amber)" : "var(--accent-green)" }}
                    >
                      {d.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </GlassPanel>
        </motion.div>
      )}

      {activeTab === "docs" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col gap-4"
        >
          <Explanation text="This section explains how each component of the SentinelAI prediction pipeline works. Understanding these concepts helps you interpret predictions and alerts correctly." />

          {[
            {
              title: "ML Prediction Model",
              icon: Brain,
              color: "var(--accent-cyan)",
              content: "The ML model (MockModel) accepts a numeric sequence of attack types and predicts the next likely attack. Each attack is encoded as a numeric value (DDoS=0, DoS=1, PortScan=2, Bot=3, WebAttack=4, BruteForce=5, Infiltration=6). The model processes the full sequence and outputs the predicted next attack vector.",
            },
            {
              title: "Markov Chain Model",
              icon: Activity,
              color: "var(--accent-purple)",
              content: "The Markov model builds transition probabilities from historical attack sequences. Given the current attack type, it predicts the most likely next attack based on observed transition frequencies. This model captures sequential patterns in attack behavior.",
            },
            {
              title: "Prediction Pipeline",
              icon: Zap,
              color: "var(--accent-green)",
              content: "When a user submits an attack sequence, the frontend converts attack names to numeric values and sends them to the FastAPI backend. The backend runs both ML and Markov models, returning predictions. The frontend calculates risk levels based on confidence scores and stores results in the prediction store.",
            },
            {
              title: "Drift Detection",
              icon: AlertTriangle,
              color: "var(--accent-amber)",
              content: "Drift detection measures whether current traffic patterns differ significantly from the training data distribution. A drift score above 0.66 indicates warning level, and above 1.0 indicates critical drift. When drift is detected, the model may need retraining with fresh data.",
            },
            {
              title: "Model Comparison",
              icon: GitCompareArrows,
              color: "var(--accent-cyan)",
              content: "The Compare module runs both ML and Markov models on the same sequence and shows whether they agree or conflict. High agreement rates indicate consistent predictions. Conflicts may indicate that one model captures patterns the other misses.",
            },
            {
              title: "Risk Assessment",
              icon: Shield,
              color: "var(--accent-red)",
              content: "Risk levels are calculated from prediction confidence: CRITICAL (≥85%), HIGH (≥75%), MEDIUM (≥60%), LOW (<60%). Higher confidence predictions indicate stronger model certainty about the predicted attack vector.",
            },
          ].map((doc) => {
            const Icon = doc.icon;
            return (
              <div
                key={doc.title}
                className="rounded-xl p-5"
                style={{ background: "rgba(8,20,32,0.7)", border: "1px solid rgba(0,229,255,0.08)" }}
              >
                <div className="flex items-center gap-2.5 mb-3">
                  <Icon className="w-4 h-4" style={{ color: doc.color }} />
                  <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{doc.title}</h3>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{doc.content}</p>
              </div>
            );
          })}
        </motion.div>
      )}
    </div>
  );
}
