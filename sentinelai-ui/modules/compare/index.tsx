"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain,
  GitCompareArrows,
  Zap,
  Activity,
  AlertTriangle,
  ArrowRight,
  Trash2,
  History,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { usePredictionStore } from "@/stores/predictionStore";
import { compareAPI } from "@/lib/api";
import type { AttackType, CompareRecord } from "@/lib/types";
import {
  ATTACK_TYPES,
  ATTACK_COLORS,
  ATTACK_TO_NUMERIC,
} from "@/lib/config";

export default function Compare() {
  const [sequence, setSequence] = useState<AttackType[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CompareRecord | null>(null);

  const compareHistory = usePredictionStore((s) => s.compareHistory);
  const addCompare = usePredictionStore((s) => s.addCompare);
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

  const runCompare = async () => {
    if (sequence.length < 1) return;
    setLoading(true);
    setError(null);

    const numeric = sequence.map((a) => ATTACK_TO_NUMERIC[a] ?? 0);

    try {
      const data = await compareAPI(numeric);
      const agree = data.ml_prediction === data.markov_prediction;

      const record: CompareRecord = {
        id: `cmp-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
        timestamp: new Date().toISOString(),
        sequence: [...sequence],
        mlPrediction: data.ml_prediction,
        markovPrediction: data.markov_prediction,
        mlConfidence: data.ml_confidence ?? 0.5,
        markovConfidence: data.markov_confidence ?? 0.5,
        modelsAgree: agree,
        agreementScore: data.agreement_score ?? 0,
        mlTopPredictions: data.ml_top_predictions ?? [],
        latencyMs: data.latency_ms ?? 0,
        rawResponse: data,
      };

      addCompare(record);
      setLastSequence(numeric);
      setResult(record);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Compare failed. Check backend connection."
      );
    } finally {
      setLoading(false);
    }
  };

  const agreementRate =
    compareHistory.length > 0
      ? compareHistory.filter((c) => c.modelsAgree).length / compareHistory.length
      : null;

  const recentCompares = compareHistory.slice(0, 15);

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
          ML vs Markov Analysis
        </p>
        <h1
          className="text-3xl font-display font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          Model Comparison Engine
        </h1>
        <p className="text-sm mt-2" style={{ color: "var(--text-secondary)" }}>
          Build an attack sequence and compare predictions from both models side-by-side.
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
            <Brain
              className="w-4 h-4"
              style={{ color: "var(--accent-cyan)" }}
            />
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
                  onClick={runCompare}
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
                      Comparing...
                    </>
                  ) : (
                    <>
                      <GitCompareArrows className="w-4 h-4" />
                      Compare &rarr;
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
            <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Compare Result */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-6"
          >
            {/* Model Cards Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* ML Model Card */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 }}
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
                  <Brain
                    className="w-4 h-4"
                    style={{ color: "var(--accent-cyan)" }}
                  />
                  <h3
                    className="text-[11px] font-bold tracking-[0.12em] uppercase"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    ML Model
                  </h3>
                </div>
                <div className="p-5 space-y-4">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center"
                      style={{
                        background: "rgba(0,229,255,0.1)",
                        border: "1px solid rgba(0,229,255,0.2)",
                      }}
                    >
                      <Brain
                        className="w-4 h-4"
                        style={{ color: "var(--accent-cyan)" }}
                      />
                    </div>
                    <span
                      className="text-xs font-mono"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Neural Network
                    </span>
                  </div>
                  <motion.p
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="text-3xl font-display font-bold"
                    style={{
                      color:
                        ATTACK_COLORS[result.mlPrediction] ||
                        "var(--text-primary)",
                    }}
                  >
                    {result.mlPrediction}
                  </motion.p>
                  <div
                    className="pt-3 border-t"
                    style={{ borderColor: "rgba(0,229,255,0.06)" }}
                  >
                    <p
                      className="text-[10px] font-mono tracking-widest uppercase"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Prediction Type
                    </p>
                    <p
                      className="text-sm font-mono mt-1"
                      style={{ color: "var(--accent-cyan)" }}
                    >
                      Deterministic
                    </p>
                  </div>
                </div>
              </motion.div>

              {/* Verdict Card */}
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
                className="rounded-2xl overflow-hidden flex flex-col"
                style={{
                  background: result.modelsAgree
                    ? "rgba(34,197,94,0.04)"
                    : "rgba(255,176,32,0.04)",
                  border: result.modelsAgree
                    ? "1px solid rgba(34,197,94,0.15)"
                    : "1px solid rgba(255,176,32,0.15)",
                }}
              >
                <div
                  className="flex items-center gap-2.5 px-5 py-3.5 border-b"
                  style={{
                    borderColor: result.modelsAgree
                      ? "rgba(34,197,94,0.1)"
                      : "rgba(255,176,32,0.1)",
                  }}
                >
                  <Zap
                    className="w-4 h-4"
                    style={{
                      color: result.modelsAgree
                        ? "var(--accent-green)"
                        : "var(--accent-amber)",
                    }}
                  />
                  <h3
                    className="text-[11px] font-bold tracking-[0.12em] uppercase"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    Verdict
                  </h3>
                </div>
                <div className="p-6 flex flex-col items-center justify-center text-center space-y-3">
                  {result.modelsAgree ? (
                    <CheckCircle2
                      className="w-10 h-10"
                      style={{ color: "var(--accent-green)" }}
                    />
                  ) : (
                    <XCircle
                      className="w-10 h-10"
                      style={{ color: "var(--accent-amber)" }}
                    />
                  )}
                  <p
                    className="text-lg font-display font-bold"
                    style={{
                      color: result.modelsAgree
                        ? "var(--accent-green)"
                        : "var(--accent-amber)",
                    }}
                  >
                    {result.modelsAgree ? "MODELS AGREE" : "MODELS CONFLICT"}
                  </p>
                  <p
                    className="text-xs leading-relaxed"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {result.modelsAgree
                      ? `Both ML and Markov models independently predict ${result.mlPrediction}. High-confidence consensus.`
                      : `ML predicts ${result.mlPrediction} while Markov predicts ${result.markovPrediction}. Different patterns detected.`}
                  </p>
                  <div className="flex items-center gap-4 pt-2">
                    <span
                      className="text-xs font-mono px-2 py-1 rounded"
                      style={{
                        background: "rgba(0,229,255,0.08)",
                        color: "var(--accent-cyan)",
                      }}
                    >
                      ML: {result.mlPrediction}
                    </span>
                    <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>vs</span>
                    <span
                      className="text-xs font-mono px-2 py-1 rounded"
                      style={{
                        background: "rgba(124,77,255,0.08)",
                        color: "var(--accent-purple)",
                      }}
                    >
                      Markov: {result.markovPrediction}
                    </span>
                  </div>
                  <div className="flex items-center gap-6 pt-3 border-t" style={{ borderColor: "rgba(0,229,255,0.06)" }}>
                    <div className="text-center">
                      <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Agreement</p>
                      <p className="text-sm font-mono font-bold" style={{ color: result.agreementScore >= 0.8 ? "var(--accent-green)" : "var(--accent-amber)" }}>
                        {(result.agreementScore * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>Latency</p>
                      <p className="text-sm font-mono font-bold" style={{ color: "var(--accent-cyan)" }}>
                        {result.latencyMs}ms
                      </p>
                    </div>
                  </div>
                </div>
              </motion.div>

              {/* Markov Model Card */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 }}
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
                  <GitCompareArrows
                    className="w-4 h-4"
                    style={{ color: "var(--accent-purple)" }}
                  />
                  <h3
                    className="text-[11px] font-bold tracking-[0.12em] uppercase"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    Markov Model
                  </h3>
                </div>
                <div className="p-5 space-y-4">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center"
                      style={{
                        background: "rgba(124,77,255,0.1)",
                        border: "1px solid rgba(124,77,255,0.2)",
                      }}
                    >
                      <GitCompareArrows
                        className="w-4 h-4"
                        style={{ color: "var(--accent-purple)" }}
                      />
                    </div>
                    <span
                      className="text-xs font-mono"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Transition Matrix
                    </span>
                  </div>
                  <motion.p
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.15 }}
                    className="text-3xl font-display font-bold"
                    style={{
                      color:
                        ATTACK_COLORS[result.markovPrediction] ||
                        "var(--text-primary)",
                    }}
                  >
                    {result.markovPrediction}
                  </motion.p>
                  <div
                    className="pt-3 border-t"
                    style={{ borderColor: "rgba(0,229,255,0.06)" }}
                  >
                    <p
                      className="text-[10px] font-mono tracking-widest uppercase"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Probability
                    </p>
                    <p
                      className="text-sm font-mono mt-1"
                      style={{ color: "var(--accent-purple)" }}
                    >
                      State-based
                    </p>
                  </div>
                </div>
              </motion.div>
            </div>

            {/* Agreement Rate */}
            {agreementRate !== null && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35 }}
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
                  <Activity
                    className="w-4 h-4"
                    style={{ color: "var(--accent-cyan)" }}
                  />
                  <h3
                    className="text-[11px] font-bold tracking-[0.12em] uppercase"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    Agreement Rate
                  </h3>
                </div>
                <div className="p-5">
                  <div className="flex items-center gap-6">
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <span
                          className="text-[10px] font-mono tracking-widest uppercase"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Overall Agreement
                        </span>
                        <span
                          className="text-sm font-mono font-bold"
                          style={{
                            color:
                              agreementRate >= 0.7
                                ? "var(--accent-green)"
                                : "var(--accent-amber)",
                          }}
                        >
                          {(agreementRate * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div
                        className="h-3 rounded-full overflow-hidden"
                        style={{ background: "rgba(0,229,255,0.06)" }}
                      >
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${agreementRate * 100}%` }}
                          transition={{ duration: 1, ease: "easeOut", delay: 0.2 }}
                          className="h-full rounded-full"
                          style={{
                            background:
                              agreementRate >= 0.7
                                ? "linear-gradient(90deg, var(--accent-green), #22C55E)"
                                : "linear-gradient(90deg, var(--accent-amber), #FFB020)",
                            boxShadow:
                              agreementRate >= 0.7
                                ? "0 0 12px rgba(34,197,94,0.3)"
                                : "0 0 12px rgba(255,176,32,0.3)",
                          }}
                        />
                      </div>
                    </div>
                    <div className="text-right">
                      <p
                        className="text-2xl font-display font-bold"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {compareHistory.filter((c) => c.modelsAgree).length}/
                        {compareHistory.length}
                      </p>
                      <p
                        className="text-[10px] font-mono"
                        style={{ color: "var(--text-muted)" }}
                      >
                        agreements
                      </p>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Empty State */}
      {!result && compareHistory.length === 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl p-12 text-center"
          style={{
            background: "rgba(8,20,32,0.4)",
            border: "2px dashed rgba(0,229,255,0.1)",
          }}
        >
          <GitCompareArrows
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

      {/* Compare History */}
      {recentCompares.length > 0 && (
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
              <History
                className="w-4 h-4"
                style={{ color: "var(--accent-cyan)" }}
              />
              <h3
                className="text-[11px] font-bold tracking-[0.12em] uppercase"
                style={{ color: "var(--text-secondary)" }}
              >
                Compare History
              </h3>
            </div>
            <div className="p-2 space-y-1">
              {recentCompares.map((event, i) => (
                <motion.div
                  key={event.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200"
                  style={{ background: "rgba(255,255,255,0.01)" }}
                >
                  <div className="shrink-0">
                    {event.modelsAgree ? (
                      <CheckCircle2
                        className="w-4 h-4"
                        style={{ color: "var(--accent-green)" }}
                      />
                    ) : (
                      <XCircle
                        className="w-4 h-4"
                        style={{ color: "var(--accent-amber)" }}
                      />
                    )}
                  </div>
                  <span
                    className="text-[10px] font-mono shrink-0 w-16"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {new Date(event.timestamp).toLocaleTimeString("en-US", {
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
                    {event.sequence.join(" → ")}
                  </span>
                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className="text-xs font-mono"
                      style={{ color: "var(--accent-cyan)" }}
                    >
                      ML: {event.mlPrediction}
                    </span>
                    <span
                      className="text-[10px]"
                      style={{ color: "var(--text-muted)" }}
                    >
                      vs
                    </span>
                    <span
                      className="text-xs font-mono"
                      style={{ color: "var(--accent-purple)" }}
                    >
                      Markov: {event.markovPrediction}
                    </span>
                  </div>
                  <span
                    className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded ml-auto shrink-0"
                    style={{
                      background: event.modelsAgree
                        ? "rgba(34,197,94,0.12)"
                        : "rgba(255,176,32,0.12)",
                      color: event.modelsAgree
                        ? "var(--accent-green)"
                        : "var(--accent-amber)",
                    }}
                  >
                    {event.modelsAgree ? "AGREE" : "CONFLICT"}
                  </span>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
