import { create } from "zustand";
import type { PredictionRecord, CompareRecord, DriftRecord } from "@/lib/types";
import { useEventStore } from "./eventStore";
import { useNotificationStore } from "./notificationStore";
import { audioManager } from "@/services/audioManager";
import { logger } from "@/services/logger";

interface PredictionState {
  predictionHistory: PredictionRecord[];
  compareHistory: CompareRecord[];
  driftHistory: DriftRecord[];
  lastPrediction: PredictionRecord | null;
  lastSequence: number[];
  confidenceHistory: Array<{ time: string; confidence: number; attack: string }>;
  latencyHistory: Array<{ time: string; latency: number }>;

  addPrediction: (record: PredictionRecord) => void;
  addCompare: (record: CompareRecord) => void;
  setLastSequence: (seq: number[]) => void;

  getStats: () => {
    totalPredictions: number;
    totalCompares: number;
    totalDrift: number;
    attackDistribution: Record<string, number>;
    mostFrequentAttack: string;
    averageConfidence: number;
    averageLatency: number;
    averageSeverityScore: number;
    agreementRate: number;
    conflictRate: number;
    criticalAlerts: number;
    highAlerts: number;
    recentPredictions: PredictionRecord[];
    confidenceTrend: Array<{ time: string; confidence: number; attack: string }>;
    latencyTrend: Array<{ time: string; latency: number }>;
    driftTrend: Array<{ time: string; score: number; status: string }>;
  };
}

export const usePredictionStore = create<PredictionState>((set, get) => ({
  predictionHistory: [],
  compareHistory: [],
  driftHistory: [],
  lastPrediction: null,
  lastSequence: [],
  confidenceHistory: [],
  latencyHistory: [],

  addPrediction: (record) => {
    set((state) => ({
      predictionHistory: [record, ...state.predictionHistory].slice(0, 200),
      lastPrediction: record,
      confidenceHistory: [
        ...state.confidenceHistory.slice(-49),
        {
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          confidence: Math.round(record.confidence * 100),
          attack: record.predictedAttack,
        },
      ],
      latencyHistory: [
        ...state.latencyHistory.slice(-49),
        {
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          latency: record.latencyMs,
        },
      ],
    }));
    useEventStore.getState().addEvent("prediction", `Predicted: ${record.predictedAttack} (${(record.confidence * 100).toFixed(1)}%) — ${record.latencyMs}ms`);

    if (record.riskLevel === "CRITICAL") {
      if (typeof window !== "undefined") audioManager.play("criticalThreat");
      logger.warn("prediction", `Critical threat: ${record.predictedAttack}`, { confidence: record.confidence, severityScore: record.severityScore });
      useNotificationStore.getState().addNotification({
        type: "error",
        title: "Critical Threat Detected",
        message: `${record.predictedAttack} predicted with ${(record.confidence * 100).toFixed(1)}% confidence (severity: ${record.severityScore})`,
      });
    } else if (record.riskLevel === "HIGH") {
      if (typeof window !== "undefined") audioManager.play("threatDetected");
      logger.info("prediction", `High threat: ${record.predictedAttack}`, { confidence: record.confidence });
    }
  },

  addCompare: (record) => {
    set((state) => ({
      compareHistory: [record, ...state.compareHistory].slice(0, 100),
    }));
    useEventStore.getState().addEvent("compare", `Compare: ML=${record.mlPrediction} vs Markov=${record.markovPrediction} (${record.modelsAgree ? "AGREE" : "CONFLICT"})`);

    if (!record.modelsAgree) {
      logger.warn("prediction", `Model disagreement: ML=${record.mlPrediction} vs Markov=${record.markovPrediction}`);
      useNotificationStore.getState().addNotification({
        type: "warning",
        title: "Model Disagreement",
        message: `ML predicted ${record.mlPrediction} but Markov predicted ${record.markovPrediction}`,
      });
    }
  },

  setLastSequence: (seq) => set({ lastSequence: seq }),

  getStats: () => {
    const { predictionHistory, compareHistory, driftHistory, confidenceHistory, latencyHistory } = get();

    const attackDistribution: Record<string, number> = {};
    predictionHistory.forEach((p) => {
      attackDistribution[p.predictedAttack] = (attackDistribution[p.predictedAttack] || 0) + 1;
    });

    const mostFrequentAttack =
      Object.entries(attackDistribution).sort(([, a], [, b]) => b - a)[0]?.[0] || "None";

    const averageConfidence =
      predictionHistory.length > 0
        ? predictionHistory.reduce((sum, p) => sum + p.confidence, 0) / predictionHistory.length
        : 0;

    const averageLatency =
      predictionHistory.length > 0
        ? predictionHistory.reduce((sum, p) => sum + p.latencyMs, 0) / predictionHistory.length
        : 0;

    const averageSeverityScore =
      predictionHistory.length > 0
        ? predictionHistory.reduce((sum, p) => sum + (p.severityScore || 0), 0) / predictionHistory.length
        : 0;

    const agreementRate =
      compareHistory.length > 0
        ? compareHistory.filter((c) => c.modelsAgree).length / compareHistory.length
        : 0;

    const conflictRate = compareHistory.length > 0 ? 1 - agreementRate : 0;

    const criticalAlerts = predictionHistory.filter((p) => p.riskLevel === "CRITICAL").length;
    const highAlerts = predictionHistory.filter((p) => p.riskLevel === "HIGH").length;

    return {
      totalPredictions: predictionHistory.length,
      totalCompares: compareHistory.length,
      totalDrift: driftHistory.length,
      attackDistribution,
      mostFrequentAttack,
      averageConfidence,
      averageLatency,
      averageSeverityScore,
      agreementRate,
      conflictRate,
      criticalAlerts,
      highAlerts,
      recentPredictions: predictionHistory.slice(0, 10),
      confidenceTrend: confidenceHistory,
      latencyTrend: latencyHistory,
      driftTrend: driftHistory.map((d) => ({
        time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false }),
        score: Math.round(d.score * 100),
        status: d.status,
      })),
    };
  },
}));
