import { create } from "zustand";
import { usePredictionStore } from "./predictionStore";
import { useSystemStore } from "./systemStore";

interface AnalyticsState {
  getDashboardMetrics: () => DashboardMetrics;
}

export type DashboardMetrics = {
  threatScore: number;
  threatBreakdown: {
    confidence_contribution: number;
    critical_alerts: number;
    model_conflict: number;
    drift_impact: number;
  };
  backendHealth: string;
  latestPrediction: string;
  latestConfidence: number;
  latestSeverityScore: number;
  latestLatency: number;
  modelAgreement: number;
  driftStatus: string;
  predictionVolume: number;
  apiLatency: number;
  uptime: number;
  criticalAlerts: number;
  highAlerts: number;
  totalEvents: number;
  attackDistribution: Record<string, number>;
  confidenceTrend: Array<{ time: string; confidence: number; attack: string }>;
  latencyTrend: Array<{ time: string; latency: number }>;
  driftTrend: Array<{ time: string; score: number; status: string }>;
  recentPredictions: Array<{
    id: string;
    timestamp: string;
    predictedAttack: string;
    confidence: number;
    severityScore: number;
    riskLevel: string;
    latencyMs: number;
    sequence: string[];
    topPredictions: Array<{ attack: string; probability: number }>;
  }>;
};

let _lastPredictionCount = -1;
let _cachedMetrics: DashboardMetrics | null = null;

export const useAnalyticsStore = create<AnalyticsState>(() => ({
  getDashboardMetrics: (): DashboardMetrics => {
    const predStats = usePredictionStore.getState().getStats();
    const system = useSystemStore.getState();
    const predHistory = usePredictionStore.getState().predictionHistory;

    if (_cachedMetrics && predHistory.length === _lastPredictionCount) {
      return _cachedMetrics;
    }
    _lastPredictionCount = predHistory.length;

    // Use the same formula as backend for consistency
    const avgConf = predStats.averageConfidence;
    const criticalCount = predStats.criticalAlerts;
    const disagreementRate = predStats.conflictRate;

    const confidenceContrib = avgConf * 40;
    const criticalContrib = Math.min(criticalCount * 2.5, 25);
    const conflictContrib = disagreementRate * 20;
    const driftContrib = 0; // Will be overridden by backend if available

    const threatScore = predStats.totalPredictions > 0
      ? Math.min(100, Math.round(confidenceContrib + criticalContrib + conflictContrib + driftContrib))
      : 0;

    const result: DashboardMetrics = {
      threatScore,
      threatBreakdown: {
        confidence_contribution: Math.round(confidenceContrib * 10) / 10,
        critical_alerts: Math.round(criticalContrib * 10) / 10,
        model_conflict: Math.round(conflictContrib * 10) / 10,
        drift_impact: driftContrib,
      },
      backendHealth: system.backendStatus,
      latestPrediction: predStats.recentPredictions[0]?.predictedAttack || "None",
      latestConfidence: predStats.recentPredictions[0]?.confidence || 0,
      latestSeverityScore: predStats.recentPredictions[0]?.severityScore || 0,
      latestLatency: predStats.recentPredictions[0]?.latencyMs || 0,
      modelAgreement: Math.round(predStats.agreementRate * 100),
      driftStatus: predStats.driftTrend[0]?.status || "stable",
      predictionVolume: predStats.totalPredictions,
      apiLatency: system.apiLatency,
      uptime: system.uptime,
      criticalAlerts: predStats.criticalAlerts,
      highAlerts: predStats.highAlerts,
      totalEvents: predStats.totalPredictions + predStats.totalCompares,
      attackDistribution: predStats.attackDistribution,
      confidenceTrend: predStats.confidenceTrend,
      latencyTrend: predStats.latencyTrend,
      driftTrend: predStats.driftTrend,
      recentPredictions: predStats.recentPredictions.map((p) => ({
        id: p.id,
        timestamp: p.timestamp,
        predictedAttack: p.predictedAttack,
        confidence: p.confidence,
        severityScore: p.severityScore,
        riskLevel: p.riskLevel,
        latencyMs: p.latencyMs,
        sequence: p.sequence,
        topPredictions: p.topPredictions || [],
      })),
    };

    _cachedMetrics = result;
    return result;
  },
}));
