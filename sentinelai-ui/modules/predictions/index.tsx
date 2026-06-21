"use client";

import { useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Brain,
  Zap,
  Activity,
  AlertTriangle,
  ArrowRight,
  Trash2,
  History,
  Clock,
  Target,
  GripVertical,
  ChevronDown,
} from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import { predictAPI } from "@/lib/api";
import { ChartErrorBoundary } from "@/components/ui/ChartErrorBoundary";
import type { AttackType, PredictionRecord } from "@/lib/types";
import {
  ATTACK_TYPES,
  ATTACK_COLORS,
  ATTACK_SEVERITY,
  ATTACK_TO_NUMERIC,
} from "@/lib/config";

function calcRisk(severityScore: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (severityScore >= 75) return "CRITICAL";
  if (severityScore >= 55) return "HIGH";
  if (severityScore >= 35) return "MEDIUM";
  return "LOW";
}

export default function Predictions() {
  const [sequence, setSequence] = useState<AttackType[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PredictionRecord | null>(null);

  const predictionHistory = usePredictionStore((s) => s.predictionHistory);
  const confidenceHistory = usePredictionStore((s) => s.confidenceHistory);
  const latencyHistory = usePredictionStore((s) => s.latencyHistory);
  const addPrediction = usePredictionStore((s) => s.addPrediction);
  const setLastSequence = usePredictionStore((s) => s.setLastSequence);

  const addAttack = useCallback(
    (attack: AttackType) => {
      if (sequence.length >= 10) return;
      setSequence((prev) => [...prev, attack]);
      setResult(null);
      setError(null);
    },
    [sequence.length]
  );

  const removeAt = useCallback((index: number) => {
    setSequence((prev) => prev.filter((_, i) => i !== index));
    setResult(null);
  }, []);

  const reorderSequence = useCallback((fromIndex: number, toIndex: number) => {
    setSequence((prev) => {
      const next = [...prev];
      const [moved] = next.splice(fromIndex, 1);
      next.splice(toIndex, 0, moved);
      return next;
    });
    setResult(null);
  }, []);

  const clearSequence = useCallback(() => {
    setSequence([]);
    setResult(null);
    setError(null);
  }, []);

  const runPredict = async () => {
    if (sequence.length < 1) return;
    setLoading(true);
    setError(null);

    const numeric = sequence.map((a) => ATTACK_TO_NUMERIC[a] ?? 0);

    try {
      const data = await predictAPI(numeric);
      const predictedAttack = data.prediction;
      const confidence = data.confidence ?? 0.5;
      const severityScore = data.severity_score ?? 0;
      const riskLevel = calcRisk(severityScore);

      const record: PredictionRecord = {
        id: `pred-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
        timestamp: new Date().toISOString(),
        sequence: [...sequence],
        predictedAttack,
        confidence,
        severityScore,
        riskLevel,
        model: data.model || "unknown",
        latencyMs: data.latency_ms ?? 0,
        topPredictions: data.top_predictions ?? [],
        explanation: data.explanation ?? { reasoning: [], pattern_match: "N/A", similar_sequences: 0, input_pattern: "" },
        rawResponse: data,
      };

      addPrediction(record);
      setLastSequence(numeric);
      setResult(record);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Prediction failed. Check backend connection."
      );
    } finally {
      setLoading(false);
    }
  };

  const chartData = useMemo(() =>
    confidenceHistory.map((c) => ({ time: c.time, confidence: c.confidence })),
    [confidenceHistory]
  );

  const latencyChartData = useMemo(() =>
    latencyHistory.map((l) => ({ time: l.time, latency: l.latency })),
    [latencyHistory]
  );

  return (
    <div className="h-full p-6 lg:p-8 flex flex-col gap-6 overflow-y-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <p
          className="text-[10px] font-mono tracking-[0.3em] uppercase mb-2"
          style={{ color: "var(--accent-cyan)" }}
        >
          Attack Sequence Forecasting
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          AI Prediction Engine
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Build an attack sequence and let the AI predict the next likely vector with top-3 alternatives.
        </p>
      </motion.div>

      {/* Sequence Builder */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
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
            <Brain className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
            <h3
              className="text-[11px] font-bold tracking-[0.12em] uppercase"
              style={{ color: "var(--text-secondary)" }}
            >
              Attack Sequence Builder
            </h3>
            <span
              className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded-md"
              style={{
                background: sequence.length >= 10 ? "rgba(255,77,109,0.12)" : "rgba(0,229,255,0.06)",
                color: sequence.length >= 10 ? "var(--accent-red)" : "var(--text-muted)",
                border: `1px solid ${sequence.length >= 10 ? "rgba(255,77,109,0.2)" : "rgba(0,229,255,0.08)"}`,
              }}
            >
              {sequence.length}/10
            </span>
          </div>
          <div className="p-5 space-y-4">
            <div className="flex flex-wrap gap-2">
              {ATTACK_TYPES.map((type) => (
                <button
                  key={type}
                  onClick={() => addAttack(type as AttackType)}
                  disabled={sequence.length >= 10}
                  className="px-4 py-2 text-xs font-mono font-semibold rounded-xl transition-all duration-300 disabled:opacity-30 disabled:cursor-not-allowed hover:scale-105"
                  style={{
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(0,229,255,0.08)",
                    color: "var(--text-secondary)",
                  }}
                >
                  + {type}
                </button>
              ))}
            </div>

            {sequence.length === 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="rounded-xl p-6 text-center"
                style={{
                  background: "rgba(0,229,255,0.02)",
                  border: "1px dashed rgba(0,229,255,0.12)",
                }}
              >
                <ChevronDown
                  className="w-6 h-6 mx-auto mb-2 animate-bounce"
                  style={{ color: "var(--text-muted)" }}
                />
                <p className="text-xs font-mono" style={{ color: "var(--text-muted)" }}>
                  Minimum 1 attack needed
                </p>
                <p className="text-[10px] font-mono mt-1" style={{ color: "var(--text-muted)", opacity: 0.6 }}>
                  Click an attack type above to begin
                </p>
              </motion.div>
            )}

            {sequence.length > 0 && (
              <div
                className="rounded-xl p-4 space-y-0"
                style={{
                  background: "rgba(0,229,255,0.02)",
                  border: "1px solid rgba(0,229,255,0.06)",
                }}
              >
                <AnimatePresence mode="popLayout">
                  {sequence.map((attack, i) => {
                    const isLast = i === sequence.length - 1;
                    return (
                      <motion.div
                        key={`${i}-${attack}`}
                        layout
                        initial={{ opacity: 0, y: -12, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, x: -40, scale: 0.9 }}
                        transition={{ type: "spring", stiffness: 400, damping: 28 }}
                        className="group flex items-center gap-3"
                      >
                        <div className="flex flex-col items-center shrink-0 w-6">
                          <GripVertical
                            className="w-3.5 h-3.5 opacity-0 group-hover:opacity-60 transition-opacity"
                            style={{ color: "var(--text-muted)" }}
                          />
                        </div>
                        <div
                          draggable
                          onDragStart={(e: React.DragEvent) => {
                            e.dataTransfer.setData("text/plain", String(i));
                            e.dataTransfer.effectAllowed = "move";
                          }}
                          onDragOver={(e: React.DragEvent) => {
                            e.preventDefault();
                            e.dataTransfer.dropEffect = "move";
                          }}
                          onDrop={(e: React.DragEvent) => {
                            e.preventDefault();
                            const fromIndex = Number(e.dataTransfer.getData("text/plain"));
                            if (fromIndex !== i) reorderSequence(fromIndex, i);
                          }}
                          className="flex-1 flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group-hover:translate-x-0.5 cursor-grab active:cursor-grabbing"
                          style={{
                            background: `${ATTACK_COLORS[attack] || "var(--accent-cyan)"}08`,
                            border: `1px solid ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}25`,
                          }}
                        >
                          <span
                            className="text-[10px] font-mono w-5 text-center shrink-0"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <span
                            className="text-sm font-mono font-bold"
                            style={{ color: ATTACK_COLORS[attack] || "var(--accent-cyan)" }}
                          >
                            {attack}
                          </span>
                          <button
                            onClick={() => removeAt(i)}
                            className="ml-auto shrink-0 w-6 h-6 rounded-lg flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all duration-200 hover:scale-110"
                            style={{
                              background: "rgba(255,77,109,0.1)",
                              color: "var(--accent-red)",
                            }}
                          >
                            <span className="text-xs font-bold">&times;</span>
                          </button>
                        </div>
                        {!isLast && (
                          <div className="flex justify-center w-6 -my-1">
                            <div
                              className="w-px h-4"
                              style={{ background: "rgba(0,229,255,0.15)" }}
                            />
                          </div>
                        )}
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            )}

            <div
              className="flex items-center gap-3 pt-3 border-t"
              style={{ borderColor: "rgba(0,229,255,0.06)" }}
            >
              {sequence.length > 0 && (
                <button
                  onClick={clearSequence}
                  className="px-4 py-2 text-xs font-mono rounded-xl transition-colors flex items-center gap-1.5"
                  style={{
                    border: "1px solid rgba(0,229,255,0.08)",
                    color: "var(--text-muted)",
                  }}
                >
                  <Trash2 className="w-3 h-3" />
                  Clear
                </button>
              )}
              <button
                onClick={runPredict}
                disabled={loading || sequence.length < 1}
                className="ml-auto px-6 py-2 text-xs font-mono font-bold rounded-xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 hover:scale-[1.02]"
                style={{
                  background:
                    "linear-gradient(135deg, var(--accent-cyan), #00B8D4)",
                  color: "var(--bg-deep)",
                  boxShadow: "0 0 20px rgba(0,229,255,0.2)",
                }}
              >
                {loading ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Predict Next &rarr;
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
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
      </AnimatePresence>

      {/* Prediction Result */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-4"
          >
            {/* Main prediction card */}
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
                <Zap className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                <h3
                  className="text-[11px] font-bold tracking-[0.12em] uppercase"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Prediction Result
                </h3>
                <span className="ml-auto text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                  {result.latencyMs}ms
                </span>
              </div>
              <div className="p-6 space-y-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-2">
                    <motion.p
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="text-4xl font-display font-bold"
                      style={{
                        color:
                          ATTACK_COLORS[result.predictedAttack] ||
                          "var(--text-primary)",
                      }}
                    >
                      {result.predictedAttack}
                    </motion.p>
                    <p
                      className="text-sm"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {ATTACK_SEVERITY[result.predictedAttack]
                        ? `${ATTACK_SEVERITY[result.predictedAttack]} severity attack`
                        : "Threat detected"}{" "}
                      &mdash; model: {result.model}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Severity</p>
                      <p className="text-lg font-mono font-bold" style={{ color: result.severityScore >= 75 ? "var(--accent-red)" : result.severityScore >= 55 ? "var(--accent-amber)" : "var(--accent-cyan)" }}>
                        {result.severityScore}
                      </p>
                    </div>
                    <div
                      className="shrink-0 px-3 py-1.5 rounded-lg text-xs font-mono font-bold"
                      style={{
                        background:
                          result.riskLevel === "CRITICAL"
                            ? "rgba(255,61,61,0.15)"
                            : result.riskLevel === "HIGH"
                            ? "rgba(255,45,85,0.15)"
                            : result.riskLevel === "MEDIUM"
                            ? "rgba(255,176,32,0.15)"
                            : "rgba(0,229,255,0.1)",
                        border: `1px solid ${
                          result.riskLevel === "CRITICAL"
                            ? "rgba(255,61,61,0.3)"
                            : result.riskLevel === "HIGH"
                            ? "rgba(255,45,85,0.3)"
                            : result.riskLevel === "MEDIUM"
                            ? "rgba(255,176,32,0.3)"
                            : "rgba(0,229,255,0.2)"
                        }`,
                        color:
                          result.riskLevel === "CRITICAL"
                            ? "#FF3D3B"
                            : result.riskLevel === "HIGH"
                            ? "#FF2D55"
                            : result.riskLevel === "MEDIUM"
                            ? "#FFB020"
                            : "var(--accent-cyan)",
                      }}
                    >
                      {result.riskLevel}
                    </div>
                  </div>
                </div>

                {/* Confidence + Latency row */}
                <div className="grid grid-cols-2 gap-4">
                  {/* Confidence Bar */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span
                        className="text-[10px] font-mono tracking-widest uppercase flex items-center gap-1"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <Target className="w-3 h-3" /> Confidence
                      </span>
                      <span
                        className="text-sm font-mono font-bold"
                        style={{ color: "var(--accent-cyan)" }}
                      >
                        {(result.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div
                      className="h-3 rounded-full overflow-hidden"
                      style={{ background: "rgba(0,229,255,0.06)" }}
                    >
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${result.confidence * 100}%` }}
                        transition={{ duration: 1, ease: "easeOut", delay: 0.2 }}
                        className="h-full rounded-full"
                        style={{
                          background:
                            "linear-gradient(90deg, var(--accent-cyan), var(--accent-green))",
                          boxShadow: "0 0 12px rgba(0,229,255,0.3)",
                        }}
                      />
                    </div>
                  </div>
                  {/* Latency */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span
                        className="text-[10px] font-mono tracking-widest uppercase flex items-center gap-1"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <Clock className="w-3 h-3" /> Inference
                      </span>
                      <span
                        className="text-sm font-mono font-bold"
                        style={{ color: result.latencyMs < 5 ? "var(--accent-green)" : result.latencyMs < 20 ? "var(--accent-cyan)" : "var(--accent-amber)" }}
                      >
                        {result.latencyMs}ms
                      </span>
                    </div>
                    <div
                      className="h-3 rounded-full overflow-hidden"
                      style={{ background: "rgba(0,229,255,0.06)" }}
                    >
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(100, (result.latencyMs / 50) * 100)}%` }}
                        transition={{ duration: 0.8, ease: "easeOut", delay: 0.3 }}
                        className="h-full rounded-full"
                        style={{
                          background: result.latencyMs < 5 ? "var(--accent-green)" : result.latencyMs < 20 ? "var(--accent-cyan)" : "var(--accent-amber)",
                        }}
                      />
                    </div>
                  </div>
                </div>

                {/* Top-3 Predictions */}
                {result.topPredictions.length > 0 && (
                  <div>
                    <p
                      className="text-[10px] font-mono tracking-widest uppercase mb-3"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Top Predictions
                    </p>
                    <div className="space-y-2">
                      {result.topPredictions.map((tp, i) => (
                        <div key={tp.attack} className="flex items-center gap-3">
                          <span
                            className="text-[10px] font-mono w-4 text-right"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {i + 1}
                          </span>
                          <span
                            className="text-xs font-mono font-semibold w-24"
                            style={{ color: ATTACK_COLORS[tp.attack] || "var(--text-primary)" }}
                          >
                            {tp.attack}
                          </span>
                          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.06)" }}>
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${tp.probability * 100}%` }}
                              transition={{ duration: 0.8, delay: 0.4 + i * 0.1 }}
                              className="h-full rounded-full"
                              style={{
                                background: i === 0 ? "var(--accent-cyan)" : i === 1 ? "var(--accent-amber)" : "var(--accent-green)",
                              }}
                            />
                          </div>
                          <span
                            className="text-[10px] font-mono w-12 text-right"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {(tp.probability * 100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Explanation */}
                {result.explanation?.reasoning?.length > 0 && (
                  <div
                    className="rounded-xl p-4"
                    style={{ background: "rgba(0,229,255,0.03)", border: "1px solid rgba(0,229,255,0.06)" }}
                  >
                    <p
                      className="text-[10px] font-mono tracking-widest uppercase mb-2"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Reasoning
                    </p>
                    <ul className="space-y-1">
                      {result.explanation.reasoning.map((r, i) => (
                        <li key={i} className="text-xs font-mono flex items-start gap-2" style={{ color: "var(--text-secondary)" }}>
                          <span style={{ color: "var(--accent-cyan)" }}>•</span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Sequence Chain */}
                <div>
                  <p
                    className="text-[10px] font-mono tracking-widest uppercase mb-2"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Input Sequence
                  </p>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {result.sequence.map((attack, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <span
                          className="px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold"
                          style={{
                            background: `${ATTACK_COLORS[attack] || "var(--accent-cyan)"}12`,
                            border: `1px solid ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}25`,
                            color: ATTACK_COLORS[attack] || "var(--accent-cyan)",
                          }}
                        >
                          {attack}
                        </span>
                        {i < result.sequence.length - 1 && (
                          <ArrowRight
                            className="w-2.5 h-2.5"
                            style={{ color: "var(--text-muted)" }}
                          />
                        )}
                      </div>
                    ))}
                    <ArrowRight
                      className="w-2.5 h-2.5"
                      style={{ color: "var(--text-muted)" }}
                    />
                    <span
                      className="px-2.5 py-1 rounded-md text-[11px] font-mono font-bold"
                      style={{
                        background: "rgba(0,229,255,0.1)",
                        border: "1px solid rgba(0,229,255,0.2)",
                        color: "var(--accent-cyan)",
                      }}
                    >
                      {result.predictedAttack}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Empty State */}
      {!result && predictionHistory.length === 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl p-12 text-center"
          style={{
            background: "rgba(8,20,32,0.4)",
            border: "2px dashed rgba(0,229,255,0.1)",
          }}
        >
          <Brain
            className="w-12 h-12 mx-auto mb-4"
            style={{ color: "var(--text-muted)" }}
          />
          <p className="font-mono text-sm" style={{ color: "var(--text-secondary)" }}>
            Add attacks above to build a sequence
          </p>
          <p className="font-mono text-xs mt-2" style={{ color: "var(--text-muted)" }}>
            Example: PortScan &rarr; PortScan &rarr; DDoS &rarr; ?
          </p>
        </motion.div>
      )}

      {/* Prediction History */}
      {predictionHistory.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
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
              <History
                className="w-4 h-4"
                style={{ color: "var(--accent-cyan)" }}
              />
              <h3
                className="text-[11px] font-bold tracking-[0.12em] uppercase"
                style={{ color: "var(--text-secondary)" }}
              >
                Prediction History
              </h3>
            </div>
            <div className="p-2 space-y-1">
              {predictionHistory.slice(0, 20).map((pred, i) => (
                <motion.div
                  key={pred.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200"
                  style={{ background: "rgba(255,255,255,0.01)" }}
                >
                  <span
                    className="text-[10px] font-mono shrink-0 w-16"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {new Date(pred.timestamp).toLocaleTimeString("en-US", {
                      hour12: false,
                    })}
                  </span>
                  <span
                    className="text-[10px] font-mono px-2 py-0.5 rounded shrink-0"
                    style={{
                      background: "rgba(0,229,255,0.06)",
                      color: "var(--text-secondary)",
                    }}
                  >
                    {pred.sequence.join(" → ")}
                  </span>
                  <ArrowRight
                    className="w-2.5 h-2.5 shrink-0"
                    style={{ color: "var(--text-muted)" }}
                  />
                  <span
                    className="text-xs font-mono font-bold shrink-0"
                    style={{
                      color:
                        ATTACK_COLORS[pred.predictedAttack] ||
                        "var(--accent-cyan)",
                    }}
                  >
                    {pred.predictedAttack}
                  </span>
                  <span
                    className="text-[10px] font-mono shrink-0"
                    style={{ color: "var(--accent-cyan)" }}
                  >
                    {(pred.confidence * 100).toFixed(1)}%
                  </span>
                  <span
                    className="text-[10px] font-mono shrink-0"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {pred.latencyMs}ms
                  </span>
                  <span
                    className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded ml-auto shrink-0"
                    style={{
                      background:
                        pred.riskLevel === "CRITICAL"
                          ? "rgba(255,61,61,0.12)"
                          : pred.riskLevel === "HIGH"
                          ? "rgba(255,45,85,0.12)"
                          : pred.riskLevel === "MEDIUM"
                          ? "rgba(255,176,32,0.12)"
                          : "rgba(0,229,255,0.08)",
                      color:
                        pred.riskLevel === "CRITICAL"
                          ? "#FF3D3B"
                          : pred.riskLevel === "HIGH"
                          ? "#FF2D55"
                          : pred.riskLevel === "MEDIUM"
                          ? "#FFB020"
                          : "var(--accent-cyan)",
                    }}
                  >
                    {pred.riskLevel}
                  </span>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* Confidence Timeline + Latency Timeline */}
      {confidenceHistory.length > 0 && (
        <div className="grid grid-cols-2 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
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
                <Activity className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
                  Confidence Timeline
                </h3>
              </div>
              <div className="p-5 h-48">
                <ChartErrorBoundary>
                  <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,229,255,0.06)" />
                      <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} />
                      <YAxis stroke="var(--text-muted)" fontSize={10} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                      <Tooltip
                        contentStyle={{
                          background: "rgba(8,20,32,0.9)",
                          border: "1px solid rgba(0,229,255,0.15)",
                          borderRadius: "8px",
                          color: "var(--text-primary)",
                          fontSize: 11,
                        }}
                        formatter={(value) => [`${Number(value).toFixed(1)}%`, "Confidence"]}
                      />
                      <Area type="monotone" dataKey="confidence" stroke="var(--accent-cyan)" strokeWidth={2} fill="url(#confGrad)" />
                      <defs>
                        <linearGradient id="confGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                          <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                    </AreaChart>
                  </ResponsiveContainer>
                </ChartErrorBoundary>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
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
                <Clock className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
                <h3 className="text-[11px] font-bold tracking-[0.12em] uppercase" style={{ color: "var(--text-secondary)" }}>
                  Inference Latency
                </h3>
              </div>
              <div className="p-5 h-48">
                <ChartErrorBoundary>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={latencyChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,229,255,0.06)" />
                      <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} />
                      <YAxis stroke="var(--text-muted)" fontSize={10} tickFormatter={(v) => `${v}ms`} />
                      <Tooltip
                        contentStyle={{
                          background: "rgba(8,20,32,0.9)",
                          border: "1px solid rgba(0,229,255,0.15)",
                          borderRadius: "8px",
                          color: "var(--text-primary)",
                          fontSize: 11,
                        }}
                        formatter={(value) => [`${Number(value).toFixed(2)}ms`, "Latency"]}
                      />
                      <Bar dataKey="latency" fill="var(--accent-green)" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </ChartErrorBoundary>
              </div>
            </div>
          </motion.div>
        </div>
      )}

      {confidenceHistory.length === 0 && predictionHistory.length === 0 && (
        <div className="hidden" />
      )}
    </div>
  );
}
