import { usePredictionStore } from "@/stores/predictionStore";
import { useSystemStore } from "@/stores/systemStore";
import { useEventStore } from "@/stores/eventStore";
import type { ReportData } from "@/lib/types";

export type ReportType = "daily" | "performance" | "predictions" | "drift";

export function generateReport(type: ReportType): ReportData {
  const stats = usePredictionStore.getState().getStats();
  const system = useSystemStore.getState();
  const events = useEventStore.getState().events;

  const now = new Date();
  const reportId = `rpt-${now.getTime()}`;

  const baseMetrics = {
    totalPredictions: stats.totalPredictions,
    averageConfidence: stats.averageConfidence,
    averageLatency: stats.averageLatency,
    criticalAlerts: stats.criticalAlerts,
    highAlerts: stats.highAlerts,
    totalCompares: stats.totalCompares,
    agreementRate: stats.agreementRate,
    driftTrend: stats.driftTrend,
    attackDistribution: stats.attackDistribution,
    topAttack: stats.mostFrequentAttack,
    executionTimeMs: system.apiLatency,
  };

  const predictions = stats.recentPredictions.map((p) => ({
    timestamp: p.timestamp,
    predictedAttack: p.predictedAttack,
    confidence: p.confidence,
    severityScore: p.severityScore,
    riskLevel: p.riskLevel,
    latencyMs: p.latencyMs,
    model: p.model,
  }));

  switch (type) {
    case "daily": {
      const total = stats.totalPredictions;
      const eventCount = events.filter(
        (e) => e.timestamp.startsWith(now.toISOString().split("T")[0])
      ).length;
      return {
        id: reportId,
        title: "Daily Intelligence Report",
        generatedAt: now.toISOString(),
        type,
        summary:
          total > 0
            ? `Processed ${total} predictions and ${stats.totalCompares} comparisons across ${eventCount} system events. Most common attack vector: ${stats.mostFrequentAttack}. Average model confidence: ${(stats.averageConfidence * 100).toFixed(1)}%. ${stats.criticalAlerts} critical and ${stats.highAlerts} high-risk threats identified. Backend latency: ${system.apiLatency}ms.`
            : "No predictions have been recorded yet. Deploy the prediction engine and submit attack sequences to begin generating intelligence.",
        metrics: baseMetrics,
        predictions,
      };
    }
    case "performance": {
      const total = stats.totalCompares;
      const agreeCount = Math.round(stats.agreementRate * total);
      return {
        id: reportId,
        title: "Model Performance Report",
        generatedAt: now.toISOString(),
        type,
        summary:
          total > 0
            ? `Evaluated ${total} model comparisons. ML and Markov models agreed on ${agreeCount} occasions (${(stats.agreementRate * 100).toFixed(1)}% agreement rate). Conflict rate: ${(stats.conflictRate * 100).toFixed(1)}%. Average prediction confidence across both models: ${(stats.averageConfidence * 100).toFixed(1)}%.`
            : "No model comparisons recorded. Use the Compare module to evaluate ML vs Markov model predictions.",
        metrics: baseMetrics,
        predictions,
      };
    }
    case "predictions": {
      const total = stats.totalPredictions;
      const attackEntries = Object.entries(stats.attackDistribution).sort(
        ([, a], [, b]) => b - a
      );
      const topThree = attackEntries.slice(0, 3);
      return {
        id: reportId,
        title: "Prediction History Report",
        generatedAt: now.toISOString(),
        type,
        summary:
          total > 0
            ? `${total} total predictions generated. Top attack types: ${topThree.map(([t, c]) => `${t} (${c})`).join(", ")}. Risk breakdown: ${stats.criticalAlerts} CRITICAL, ${stats.highAlerts} HIGH. Confidence range: ${(Math.min(...stats.recentPredictions.map((p) => p.confidence)) * 100).toFixed(1)}% - ${(Math.max(...stats.recentPredictions.map((p) => p.confidence)) * 100).toFixed(1)}%.`
            : "No prediction history available. Use the Predictions module to generate attack forecasts.",
        metrics: baseMetrics,
        predictions,
      };
    }
    case "drift": {
      const latest = stats.driftTrend[0];
      const stableCount = stats.driftTrend.filter((d) => d.status === "stable").length;
      const warningCount = stats.driftTrend.filter((d) => d.status === "warning").length;
      const criticalCount = stats.driftTrend.filter((d) => d.status === "critical").length;
      return {
        id: reportId,
        title: "Drift Analysis Report",
        generatedAt: now.toISOString(),
        type,
        summary: latest
          ? `Latest drift score: ${latest.score} (${latest.status}). Analysis of ${stats.driftTrend.length} measurements: ${stableCount} stable, ${warningCount} warning, ${criticalCount} critical. ${
              latest.status === "critical"
                ? "Data drift detected — model retraining recommended."
                : latest.status === "warning"
                ? "Moderate drift observed — monitor closely."
                : "Traffic patterns remain within baseline parameters."
            }`
          : "No drift data available. Run drift detection to establish baseline measurements.",
        metrics: baseMetrics,
        predictions,
      };
    }
  }
}
