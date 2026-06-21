"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Brain,
  Zap,
  Activity,
  ArrowRight,
  Trash2,
  BarChart3,
  Target,
  Layers,
} from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import { explainAPI, predictAPI } from "@/lib/api";
import type { AttackType } from "@/lib/types";
import {
  ATTACK_TYPES,
  ATTACK_COLORS,
  ATTACK_TO_NUMERIC,
} from "@/lib/config";
import ExplainabilityPanel from "@/components/explainability/ExplainabilityPanel";

interface ExplainResult {
  prediction: string;
  confidence: number;
  importance: Array<{ token: string; position: number; weight: number; label: string }>;
  topPredictions: Array<{ attack: string; probability: number }>;
  explanation: {
    reasoning: string[];
    pattern_match: string;
    similar_sequences: number;
    input_pattern: string;
  };
  latencyMs: number;
}

export default function Explainability() {
  const [sequence, setSequence] = useState<AttackType[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExplainResult | null>(null);

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

  const removeLast = useCallback(() => {
    setSequence((prev) => prev.slice(0, -1));
    setResult(null);
  }, []);

  const clearSequence = useCallback(() => {
    setSequence([]);
    setResult(null);
    setError(null);
  }, []);

  const runExplain = async () => {
    if (sequence.length < 1) return;
    setLoading(true);
    setError(null);

    const numeric = sequence.map((a) => ATTACK_TO_NUMERIC[a] ?? 0);

    try {
      const [explainData, predictData] = await Promise.all([
        explainAPI(numeric),
        predictAPI(numeric),
      ]);

      const record = {
        id: `pred-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
        timestamp: new Date().toISOString(),
        sequence: [...sequence],
        predictedAttack: explainData.prediction,
        confidence: explainData.confidence,
        severityScore: predictData.severity_score ?? 0,
        riskLevel: (predictData.severity_score ?? 0) >= 75 ? "CRITICAL" as const : (predictData.severity_score ?? 0) >= 55 ? "HIGH" as const : (predictData.severity_score ?? 0) >= 35 ? "MEDIUM" as const : "LOW" as const,
        model: predictData.model || "unknown",
        latencyMs: predictData.latency_ms ?? 0,
        topPredictions: explainData.top_predictions ?? [],
        explanation: explainData.explanation ?? { reasoning: [], pattern_match: "N/A", similar_sequences: 0, input_pattern: "" },
        rawResponse: explainData,
      };

      addPrediction(record);
      setLastSequence(numeric);

      setResult({
        prediction: explainData.prediction,
        confidence: explainData.confidence,
        importance: explainData.importance ?? [],
        topPredictions: explainData.top_predictions ?? [],
        explanation: explainData.explanation ?? { reasoning: [], pattern_match: "N/A", similar_sequences: 0, input_pattern: "" },
        latencyMs: predictData.latency_ms ?? 0,
      });
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Explain request failed. Check backend connection."
      );
    } finally {
      setLoading(false);
    }
  };

  const chartData = result?.importance.map((imp) => ({
    token: imp.token,
    weight: Math.round(imp.weight * 100),
  })) ?? [];

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
          Model Explainability
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          XAI Explanation Engine
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Build an attack sequence to visualize per-token feature importance, attention flow, and reasoning.
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

            <AnimatePresence mode="popLayout">
              {sequence.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  className="flex items-center gap-2 flex-wrap p-4 rounded-xl"
                  style={{
                    background: "rgba(0,229,255,0.03)",
                    border: "1px solid rgba(0,229,255,0.08)",
                  }}
                >
                  {sequence.map((attack, i) => (
                    <motion.div
                      key={`${i}-${attack}`}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.8 }}
                      transition={{ delay: i * 0.05 }}
                      className="flex items-center gap-1"
                    >
                      <span
                        className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold"
                        style={{
                          background: `${ATTACK_COLORS[attack] || "var(--accent-cyan)"}15`,
                          border: `1px solid ${ATTACK_COLORS[attack] || "var(--accent-cyan)"}30`,
                          color: ATTACK_COLORS[attack] || "var(--accent-cyan)",
                        }}
                      >
                        {attack}
                      </span>
                      {i < sequence.length - 1 && (
                        <ArrowRight
                          className="w-3 h-3"
                          style={{ color: "var(--text-muted)" }}
                        />
                      )}
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>

            {sequence.length > 0 && (
              <div
                className="flex items-center gap-3 pt-3 border-t"
                style={{ borderColor: "rgba(0,229,255,0.06)" }}
              >
                <button
                  onClick={removeLast}
                  className="px-4 py-2 text-xs font-mono rounded-xl transition-colors"
                  style={{
                    border: "1px solid rgba(0,229,255,0.08)",
                    color: "var(--text-muted)",
                  }}
                >
                  &larr; Remove
                </button>
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
                <span
                  className="text-[10px] font-mono ml-2"
                  style={{ color: "var(--text-muted)" }}
                >
                  {sequence.length}/10
                </span>
                <button
                  onClick={runExplain}
                  disabled={loading || sequence.length < 1}
                  className="ml-auto px-6 py-2 text-xs font-mono font-bold rounded-xl transition-all duration-300 disabled:opacity-50 flex items-center gap-2"
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
                      Explaining...
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      Explain &rarr;
                    </>
                  )}
                </button>
              </div>
            )}
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
            <Activity className="w-4 h-4 shrink-0" /> {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Explanation Result */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-4"
          >
            {/* Prediction Summary Card */}
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
                  Explanation Result
                </h3>
                <span className="ml-auto text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                  {result.latencyMs}ms
                </span>
              </div>
              <div className="p-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-2">
                    <motion.p
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="text-4xl font-display font-bold"
                      style={{
                        color:
                          ATTACK_COLORS[result.prediction] ||
                          "var(--text-primary)",
                      }}
                    >
                      {result.prediction}
                    </motion.p>
                    <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                      Pattern: {result.explanation.pattern_match}
                    </p>
                  </div>
                  <div className="text-right space-y-1">
                    <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Confidence</p>
                    <p className="text-lg font-mono font-bold" style={{ color: "var(--accent-cyan)" }}>
                      {(result.confidence * 100).toFixed(1)}%
                    </p>
                    <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                      {result.explanation.similar_sequences} similar sequences
                    </p>
                  </div>
                </div>

                {/* Confidence Bar */}
                <div className="mt-4">
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

                {/* Sequence Chain */}
                <div className="mt-4">
                  <p
                    className="text-[10px] font-mono tracking-widest uppercase mb-2"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Input Sequence
                  </p>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {sequence.map((attack, i) => (
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
                        {i < sequence.length - 1 && (
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
                      {result.prediction}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Feature Importance Chart */}
            {chartData.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 }}
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
                    <BarChart3 className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                    <h3
                      className="text-[11px] font-bold tracking-[0.12em] uppercase"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      Feature Importance
                    </h3>
                  </div>
                  <div className="p-5 h-56">
                     <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={chartData} layout="vertical" margin={{ left: 10 }}>
                        <XAxis
                          type="number"
                          domain={[0, 100]}
                          stroke="var(--text-muted)"
                          fontSize={10}
                          tickFormatter={(v) => `${v}%`}
                        />
                        <YAxis
                          type="category"
                          dataKey="token"
                          stroke="var(--text-muted)"
                          fontSize={10}
                          width={80}
                        />
                        <Tooltip
                          contentStyle={{
                            background: "rgba(8,20,32,0.9)",
                            border: "1px solid rgba(0,229,255,0.15)",
                            borderRadius: "8px",
                            color: "var(--text-primary)",
                            fontSize: 11,
                          }}
                          formatter={(value) => [`${Number(value).toFixed(1)}%`, "Weight"]}
                        />
                        <Bar
                          dataKey="weight"
                          radius={[0, 4, 4, 0]}
                          fill="var(--accent-cyan)"
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Explainability Panel (bars, timeline, reasoning) */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <ExplainabilityPanel
                importance={result.importance}
                prediction={result.prediction}
                confidence={result.confidence}
                explanation={result.explanation}
              />
            </motion.div>

            {/* Top-3 Predictions */}
            {result.topPredictions.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.25 }}
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
                    <Target className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                    <h3
                      className="text-[11px] font-bold tracking-[0.12em] uppercase"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      Top Predictions
                    </h3>
                  </div>
                  <div className="p-5 space-y-2">
                    {result.topPredictions.slice(0, 3).map((tp, i) => (
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
                            transition={{ duration: 0.8, delay: 0.3 + i * 0.1 }}
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
              </motion.div>
            )}

            {/* Explanation Reasoning */}
            {result.explanation.reasoning.length > 0 && (
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
                    <Layers className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
                    <h3
                      className="text-[11px] font-bold tracking-[0.12em] uppercase"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      Explanation Reasoning
                    </h3>
                  </div>
                  <div className="p-5">
                    <div
                      className="rounded-xl p-4"
                      style={{ background: "rgba(0,229,255,0.03)", border: "1px solid rgba(0,229,255,0.06)" }}
                    >
                      <ul className="space-y-1.5">
                        {result.explanation.reasoning.map((r, i) => (
                          <li key={i} className="text-xs font-mono flex items-start gap-2" style={{ color: "var(--text-secondary)" }}>
                            <span style={{ color: "var(--accent-cyan)" }}>•</span>
                            {r}
                          </li>
                        ))}
                      </ul>
                      <div className="mt-3 pt-3 border-t flex items-center gap-4" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
                        <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                          Pattern: <span style={{ color: "var(--text-secondary)" }}>{result.explanation.pattern_match}</span>
                        </span>
                        <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                          Input: <span style={{ color: "var(--text-secondary)" }}>{result.explanation.input_pattern}</span>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Empty State */}
      {!result && (
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
    </div>
  );
}
